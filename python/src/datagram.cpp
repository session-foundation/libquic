#include "wrappers.hpp"

#include <oxen/quic/datagram.hpp>
#include <oxen/quic/opt.hpp>

#include <pybind11/pybind11.h>

#include <stdexcept>

namespace seshquic
{
    using oxen::quic::datagram;
    namespace opt = oxen::quic::opt;

    oxen::quic::dgram_data_callback make_dgram_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](datagram&& d) {
            py::gil_scoped_acquire gil;
            // The datagram's data pointer is not guaranteed to outlive this call, which is why the
            // bytes are copied out rather than viewed.
            fn(wrap_connection(d.conn), from_bytes(d.data));
        };
    }

    std::optional<opt::enable_datagrams> datagram_option(
            bool enabled, bool splitting, std::optional<int> bufsize, std::optional<size_t> queue_limit)
    {
        if (!enabled)
        {
            if (splitting || bufsize || queue_limit)
                throw py::value_error{"datagram options were given without datagrams=True"};
            return std::nullopt;
        }

        if (bufsize && !splitting)
            throw py::value_error{"datagram_bufsize only applies with datagram_splitting=True"};

        // The option enforces the bufsize constraints itself, but reports the size bounds as
        // std::out_of_range, which pybind11 turns into IndexError.  A bad argument is a ValueError
        // in Python, so it is translated here.
        std::optional<opt::enable_datagrams> dgrams;
        try
        {
            if (!splitting)
                dgrams.emplace();
            else if (bufsize)
                dgrams.emplace(oxen::quic::Splitting::ACTIVE, *bufsize);
            else
                dgrams.emplace(oxen::quic::Splitting::ACTIVE);
        }
        catch (const std::out_of_range& e)
        {
            throw py::value_error{e.what()};
        }

        if (queue_limit)
            dgrams->queue_limit(*queue_limit);

        return dgrams;
    }

    void PyConnection::send_datagram(const py::object& data)
    {
        auto buf = to_bytes(data);
        auto conn = get();

        without_gil([&] {
            auto dgrams = conn->datagrams();
            if (!dgrams)
                throw std::runtime_error{"datagrams are not enabled on this connection's endpoint"};
            dgrams->send(std::move(buf));
        });
    }

}  // namespace seshquic
