#include "common.hpp"
#include "wrappers.hpp"

#include <oxen/quic/version.hpp>

#include <pybind11/pybind11.h>

#include <string>

PYBIND11_MODULE(_core, m)
{
    m.doc() = "Compiled core of the seshquic package; import seshquic instead of this.";

    const auto& v = oxen::quic::VERSION;
    m.attr("__version__") = std::to_string(v[0]) + '.' + std::to_string(v[1]) + '.' + std::to_string(v[2]);

    seshquic::init_logging(m);
    seshquic::init_address(m);
    seshquic::init_creds(m);
    seshquic::init_stream(m);
    seshquic::init_btstream(m);
    seshquic::init_endpoint(m);
}
