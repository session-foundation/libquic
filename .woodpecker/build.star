# Linux builds run in our Debian/Ubuntu images on the docker agents, macOS builds directly on the
# Mac agents.

registry = "registry.session.codes/"

events = ["push", "pull_request", "tag", "manual"]

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

ngtcp2_deps = ["libngtcp2-dev", "libngtcp2-crypto-gnutls-dev"]

# Focal doesn't get the CLI11, fmt and spdlog packages, so builds there use the bundled copies.
old_lib_deps = ["gnutls-bin", "libevent-dev", "libgnutls28-dev", "libsodium-dev"] + ngtcp2_deps
lib_deps = old_lib_deps + ["libcli11-dev", "libfmt-dev", "libspdlog-dev"]

# WITH_LTO is given either way because it defaults to on.
default_cmake = {
    "CMAKE_BUILD_TYPE": "Release",
    "CMAKE_COLOR_DIAGNOSTICS": True,
    "WARNINGS_AS_ERRORS": True,
    "WITH_LTO": False,
    "LOCAL_MIRROR": "https://builds.session.codes/deps",
}

def cmake_args(opts):
    return " ".join([
        "-D%s=%s" % (k, ("ON" if v else "OFF") if type(v) == "bool" else v)
        for k, v in opts.items()
    ])

# The commands, run from the top of the checkout, that configure and build in build/ and then run
# the test suite if wanted.
def build_commands(cmake, jobs, run_tests, test_0rtt, gdb):
    opts = dict(default_cmake)
    opts.update(cmake)
    cmds = [
        "mkdir build",
        "cd build",
        "cmake .. " + cmake_args(opts),
        "make -j%d VERBOSE=1" % jobs,
    ]
    if run_tests:
        cmds.append(
            ("../utils/ci/ci-gdb.sh " if gdb else "") +
            "./tests/alltests --success -T --no-ipv6 --colour-mode ansi" +
            ("" if test_0rtt else " --disable-0rtt"),
        )
    return cmds

def workflow(name, labels, steps):
    return {
        "name": name,
        "labels": labels,
        "when": [{"event": events}],
        "steps": steps,
    }

def backports(distro, pkgs):
    return [
        "echo deb http://deb.debian.org/debian %s-backports main >>/etc/apt/sources.list.d/backports.list" % distro,
        "eatmydata " + apt_get + " update",
        "eatmydata " + apt_get + " install -y " + " ".join(["%s/%s-backports" % (p, distro) for p in pkgs]),
    ]

def kitware_repo(distro):
    return [
        "eatmydata " + apt_get + " install -y curl ca-certificates",
        "curl -sSL https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - >/usr/share/keyrings/kitware-archive-keyring.gpg",
        'echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ %s main" >/etc/apt/sources.list.d/kitware.list' % distro,
        "eatmydata " + apt_get + " update",
    ]

session_repo = [
    "eatmydata " + apt_get + " install --no-install-recommends -y lsb-release",
    "cp utils/deb.session.foundation.gpg /etc/apt/trusted.gpg.d",
    "echo deb http://deb.session.foundation $$(lsb_release -sc) main >/etc/apt/sources.list.d/session.list",
    "eatmydata " + apt_get + " update",
]

def linux(
        name,
        image,
        arch = "amd64",
        deps = ["g++"] + lib_deps,
        setup = [],
        cmake = {},
        jobs = 6,
        run_tests = True,
        test_0rtt = True):
    commands = [
        'echo "Building on $${CI_MACHINE}"',
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        apt_get + " update",
        apt_get + " install -y eatmydata",
    ] + setup + [
        "eatmydata " + apt_get + " dist-upgrade -y",
        "eatmydata " + apt_get + " install --no-install-recommends -y " +
        " ".join(["cmake", "git", "pkg-config", "ccache"] + deps),
    ]
    return workflow(name, {"platform": "linux/" + arch, "backend": "docker"}, [{
        "name": "build",
        "image": registry + image,
        "pull": True,
        "commands": commands + build_commands(cmake, jobs, run_tests, test_0rtt, gdb = True),
    }])

def clang(version):
    return linux(
        "Debian sid clang-%d" % version,
        "debian-sid-clang",
        deps = ["clang-%d" % version] + lib_deps,
        cmake = {
            "CMAKE_C_COMPILER": "clang-%d" % version,
            "CMAKE_CXX_COMPILER": "clang++-%d" % version,
            # Enabling LTO in oxen-logging makes clang unhappy
            "USE_LTO": False,
            # clang's LTO objects need a linker that reads LLVM bitcode, which the default bfd linker
            # here doesn't, so the static dependencies have to be built without it.
            "SESSIONDEPS_LTO": False,
        },
    )

def full_llvm(version):
    cmake = {
        "CMAKE_C_COMPILER": "clang-%d" % version,
        "CMAKE_CXX_COMPILER": "clang++-%d" % version,
        "CMAKE_CXX_FLAGS": "-stdlib=libc++",
        "OXEN_LOGGING_FORCE_SUBMODULES": True,
    }
    for kind in ["EXE", "MODULE", "SHARED"]:
        cmake["CMAKE_%s_LINKER_FLAGS" % kind] = "-fuse-ld=lld-%d" % version
    return linux(
        "Debian sid llvm-%d" % version,
        "debian-sid-clang",
        deps = [
            "clang-%d" % version,
            "lld-%d" % version,
            "libc++-%d-dev" % version,
            "libc++abi-%d-dev" % version,
        ] + lib_deps,
        cmake = cmake,
    )

def macos(name, arch, cmake = {}, run_tests = True, test_0rtt = True, jobs = 6):
    return workflow(name, {"platform": "darwin/" + arch, "backend": "local"}, [{
        "name": "build",
        "image": "sh",
        "commands": [
            'echo "Building on $${CI_MACHINE}"',
            # If you don't do this then the C compiler doesn't have an include path containing
            # basic system headers.  WTF apple:
            'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
        ] + build_commands(cmake, jobs, run_tests, test_0rtt, gdb = False),
    }])

bookworm_ngtcp2 = backports("bookworm", ngtcp2_deps)

def main(ctx):
    return [
        workflow("lint check", {"platform": "linux/amd64", "backend": "docker"}, [{
            "name": "build",
            "image": registry + "lint",
            "pull": True,
            "commands": [
                'echo "Building on $${CI_MACHINE}"',
                apt_get + " update",
                apt_get + " install -y eatmydata",
                "eatmydata " + apt_get + " install --no-install-recommends -y git clang-format-19",
                "./utils/ci/lint-check.sh",
            ],
        }]),

        linux("Debian sid", "debian-sid"),
        linux("Debian sid Debug", "debian-sid", cmake = {"CMAKE_BUILD_TYPE": "Debug"}),
        clang(19),
        full_llvm(19),
        linux("Debian sid -GSO", "debian-sid", cmake = {"LIBQUIC_SEND": "sendmmsg"}),
        linux("Debian sid -mmsg", "debian-sid", cmake = {"LIBQUIC_SEND": "sendmsg", "LIBQUIC_RECVMMSG": False}),
        linux("Debian sid -GSO Debug", "debian-sid", cmake = {"CMAKE_BUILD_TYPE": "Debug", "LIBQUIC_SEND": "sendmmsg"}),
        linux(
            "Debian sid -mmsg Debug",
            "debian-sid",
            cmake = {"CMAKE_BUILD_TYPE": "Debug", "LIBQUIC_SEND": "sendmsg", "LIBQUIC_RECVMMSG": False},
        ),
        linux("Debian testing (i386)", "debian-testing/i386"),
        linux("Debian 13 static", "debian-trixie", deps = ["g++"], cmake = {"BUILD_STATIC_DEPS": True}),
        linux("Debian 13 (i386)", "debian-trixie/i386"),
        linux("Debian 12", "debian-bookworm", setup = bookworm_ngtcp2),
        linux(
            "Debian 12 static Debug",
            "debian-bookworm",
            deps = ["g++"],
            cmake = {"CMAKE_BUILD_TYPE": "Debug", "BUILD_STATIC_DEPS": True},
        ),
        linux("Ubuntu latest", "ubuntu-rolling"),
        linux("Ubuntu 24.04 noble", "ubuntu-noble", setup = session_repo),
        linux("Ubuntu 22.04 jammy", "ubuntu-jammy", setup = session_repo),
        linux(
            "Ubuntu 20.04 focal",
            "ubuntu-focal",
            deps = ["g++-10", "g++"] + old_lib_deps,
            setup = session_repo + kitware_repo("focal"),
            cmake = {"CMAKE_C_COMPILER": "gcc-10", "CMAKE_CXX_COMPILER": "g++-10"},
        ),

        # ARM builds; armhf builds in a 32-bit image on the arm64 agents.
        linux("Debian sid (ARM64)", "debian-sid", arch = "arm64", jobs = 4),
        linux(
            "Debian 12 Debug (ARM64)",
            "debian-bookworm",
            arch = "arm64",
            jobs = 4,
            setup = bookworm_ngtcp2,
            cmake = {"CMAKE_BUILD_TYPE": "Debug"},
            test_0rtt = False,
        ),
        linux("Debian 12 (armhf)", "debian-bookworm/arm32v7", arch = "arm64", jobs = 4, setup = bookworm_ngtcp2),

        # The tests are built, but not run.
        linux(
            "Windows (x64)",
            "debian-win32-cross",
            deps = ["build-essential", "ca-certificates", "g++-mingw-w64-x86-64-posix"],
            cmake = {
                "CMAKE_TOOLCHAIN_FILE": "../cmake/cross/mingw-x64.cmake",
                "BUILD_STATIC_DEPS": True,
                "WARNINGS_AS_ERRORS": False,
            },
            run_tests = False,
        ),

        macos("macOS (Release, ARM)", "arm64"),
        macos("macOS (Debug, ARM)", "arm64", cmake = {"CMAKE_BUILD_TYPE": "Debug"}, test_0rtt = False),
        macos("macOS (Static, ARM)", "arm64", cmake = {"BUILD_STATIC_DEPS": True, "WITH_LTO": True}),
        macos("macOS (Release, Intel)", "amd64", cmake = {"LIBQUIC_BUILD_TESTS": False}, run_tests = False),
        macos(
            "macOS (Debug, Intel)",
            "amd64",
            cmake = {"CMAKE_BUILD_TYPE": "Debug", "LIBQUIC_BUILD_TESTS": False},
            run_tests = False,
        ),
    ]
