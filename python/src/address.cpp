#include "common.hpp"

#include <oxen/quic/address.hpp>

#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace seshquic
{
    using oxen::quic::Address;

    Address to_address(const py::object& obj)
    {
        if (py::isinstance<Address>(obj))
            return obj.cast<Address>();

        if (py::isinstance<py::str>(obj))
            return make_address(obj.cast<std::string>(), std::nullopt);

        if (py::isinstance<py::tuple>(obj) || py::isinstance<py::list>(obj))
        {
            auto seq = obj.cast<py::sequence>();
            if (py::len(seq) != 2)
                throw py::value_error{"an address tuple must be (host, port)"};
            return make_address(seq[0].cast<std::string>(), seq[1].cast<uint16_t>());
        }

        throw py::type_error{"expected an Address, a 'host:port' string, or a (host, port) tuple"};
    }

    Address make_address(const std::string& addr, std::optional<uint16_t> port)
    {
        if (port)
            return Address{addr, *port};
        if (addr.empty())
            return Address{};
        // A lone string is the combined form, so that "1.2.3.4:5678" and "[::1]:443" work; a bare
        // host is still accepted and gets the any-port.
        return Address::parse(addr, 0);
    }

    void init_address(py::module_& m)
    {
        py::class_<Address>{m, "Address", R"(A local or remote socket address.

Takes either a combined "host:port" (or "[v6addr]:port") string, or a host and port separately.
An empty host means "any address" -- dual stack, where the platform supports it -- and an omitted
port means "any port", which is what you want for a client or for a server on an ephemeral port.
)"}
                .def(py::init(&make_address), py::arg("addr") = "", py::arg("port") = py::none())
                .def_static(
                        "parse",
                        [](std::string_view addr, std::optional<uint16_t> default_port) {
                            return Address::parse(addr, default_port);
                        },
                        py::arg("addr"),
                        py::arg("default_port") = py::none(),
                        R"(Parses "host:port", "[v6addr]:port" or a bare host.

A bare host is only accepted when `default_port` is given; otherwise the port is required.
Raises ValueError if the address cannot be parsed.
)")
                .def_property_readonly("host", &Address::host)
                .def_property_readonly("port", &Address::port)
                .def_property_readonly("is_ipv4", &Address::is_ipv4)
                .def_property_readonly("is_ipv6", &Address::is_ipv6)
                .def_property_readonly("is_set", &Address::is_set)
                .def_property_readonly("is_loopback", &Address::is_loopback)
                .def_property_readonly("is_public", &Address::is_public)
                .def_property_readonly("is_any_addr", &Address::is_any_addr)
                .def_property_readonly("is_any_port", &Address::is_any_port)
                .def_property_readonly(
                        "is_addressable",
                        &Address::is_addressable,
                        "True if this names a specific host and port, i.e. is usable as a connect target.")
                .def(py::self == py::self)
                .def(py::self < py::self)
                .def("__hash__", [](const Address& a) { return std::hash<std::string>{}(a.to_string()); })
                .def("__str__", &Address::to_string)
                .def("__repr__", [](const Address& a) { return "Address('" + a.to_string() + "')"; });
    }

}  // namespace seshquic
