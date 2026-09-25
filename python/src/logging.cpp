#include "common.hpp"

#include <oxen/log.hpp>
#include <oxen/log/level.hpp>
#include <oxen/log/type.hpp>

#include <pybind11/pybind11.h>

#include <algorithm>
#include <array>
#include <string>

namespace seshquic
{
    namespace log = oxen::log;

    void init_logging(py::module_& m)
    {
        m.def(
                "enable_logging",
                [](const std::string& out, const std::string& level) {
                    // The same target spellings oxen-logging's print sink understands; anything
                    // else is a filename.
                    constexpr std::array print_to = {
                            "stdout", "-", "", "stderr", "nocolor", "stdout-nocolor", "stderr-nocolor"};

                    auto type = std::count(print_to.begin(), print_to.end(), out) ? log::Type::Print
                              : out == "syslog"                                   ? log::Type::System
                                                                                  : log::Type::File;

                    auto lvl = log::level_from_string(level);

                    without_gil([&] {
                        log::add_sink(type, out);
                        log::reset_level(lvl);
                    });
                },
                py::arg("out") = "stderr",
                py::arg("level") = "info",
                R"(Turns on libquic's internal logging.

`out` is where it goes: "stdout", "stderr", "-", or either with a "-nocolor" suffix to print;
"syslog" for the system log; anything else is taken as a filename to append to.

`level` is one of "critical", "error", "warning", "info", "debug" or "trace".  Note that "debug"
and especially "trace" are very verbose -- a trace log records every packet.

Calling this more than once adds another sink each time rather than replacing the first.
)");

        m.def(
                "flush_logs",
                [] { without_gil([] { log::flush(); }); },
                R"(Flushes buffered log output.

Log sinks buffer, so a file sink may lag well behind; call this to make what has been logged so
far actually land, such as before killing a process that is being debugged.
)");
    }

}  // namespace seshquic
