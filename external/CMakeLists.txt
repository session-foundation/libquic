include(ExternalProject)

function(enable_lto)
  if(IPO_ENABLED)
    set_target_properties(${ARGN} PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
  endif()
endfunction()

set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)

# Force shared libs off for any libraries we build inside here so that if we build a shared lib we
# don't end up with a libspdlog.so or whatever that would need to be distributed alongside the
# libquic.so
set(BUILD_SHARED_LIBS OFF)

include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)

check_submodule(oxen-logging fmt spdlog)
check_submodule(oxen-encoding)

# oxen::logging (and implicitly fmt/spdlog):
include(oxen-logging/cmake/load.cmake)

# oxenc
if (NOT TARGET oxenc::oxenc)
    sessiondep_or_submodule(liboxenc 1.4.0 oxen-encoding oxenc::oxenc)
endif()
