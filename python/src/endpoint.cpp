#include "wrappers.hpp"

#include <oxen/quic/address.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/crypto.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/opt.hpp>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <stdexcept>
#include <string_view>

namespace seshquic
{
    using oxen::quic::Address;
    using oxen::quic::RemoteAddress;
    using oxen::quic::TLSCreds;
    namespace opt = oxen::quic::opt;

    std::shared_ptr<Connection> PyConnection::get() const
    {
        auto c = _c.lock();
        if (!c)
            throw std::runtime_error{"connection is no longer available; its endpoint has been closed"};
        return c;
    }

    py::object wrap(const std::shared_ptr<Connection>& c)
    {
        return py::cast(new PyConnection{c}, py::return_value_policy::take_ownership);
    }

    py::object wrap_connection(Connection& c)
    {
        // weak_from_this rather than shared_from_this: a close callback can run while the
        // connection is being torn down, where shared_from_this throws.
        return wrap(c.weak_from_this().lock());
    }

    oxen::quic::connection_established_callback make_conn_established_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](Connection& c) {
            py::gil_scoped_acquire gil;
            fn(wrap_connection(c));
        };
    }

    oxen::quic::connection_closed_callback make_conn_closed_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](Connection& c, uint64_t error_code) {
            py::gil_scoped_acquire gil;
            fn(wrap_connection(c), error_code);
        };
    }

    py::object PyConnection::open_stream(py::object on_data, py::object on_close, py::object on_fin)
    {
        auto data_cb = make_stream_data_cb(std::move(on_data));
        auto close_cb = make_stream_close_cb(std::move(on_close));
        auto fin_cb = make_stream_fin_cb(std::move(on_fin));

        auto conn = get();
        auto stream = without_gil([&] {
            // Stream's option handling has no std::optional overload, but an empty std::function is
            // equivalent: set_default_callbacks() only fills in a callback that is unset.
            return conn->open_stream<Stream>(std::move(data_cb), std::move(close_cb), std::move(fin_cb));
        });

        return wrap(stream);
    }

    py::object PyConnection::open_bt_stream(py::object on_request, py::object on_close)
    {
        auto generic = make_message_cb(std::move(on_request));
        auto close_cb = make_stream_close_cb(std::move(on_close));

        auto conn = get();
        auto stream = without_gil(
                [&] { return conn->open_stream<oxen::quic::BTRequestStream>(std::move(generic), std::move(close_cb)); });

        return wrap_bt(stream);
    }

    py::object PyConnection::queue_incoming_bt_stream(py::object on_request, py::object on_close)
    {
        auto generic = make_message_cb(std::move(on_request));
        auto close_cb = make_stream_close_cb(std::move(on_close));

        auto conn = get();
        auto stream = without_gil([&] {
            return conn->queue_incoming_stream<oxen::quic::BTRequestStream>(std::move(generic), std::move(close_cb));
        });

        return wrap_bt(stream);
    }

    void PyConnection::close(uint64_t error_code)
    {
        auto conn = get();
        without_gil([&] { conn->close_connection(error_code); });
    }

    Endpoint& PyEndpoint::get() const
    {
        if (!_ep)
            throw std::runtime_error{"endpoint is closed"};
        return *_ep;
    }

    PyEndpoint::PyEndpoint(
            const py::object& local,
            PyLoop* loop,
            std::optional<std::vector<std::string>> alpns,
            std::optional<double> handshake_timeout,
            std::optional<size_t> max_udp_payload,
            bool allow_gso,
            bool datagrams,
            bool datagram_splitting,
            std::optional<int> datagram_bufsize,
            std::optional<size_t> datagram_queue_limit,
            py::object on_connection,
            py::object on_connection_closed,
            py::object on_datagram) :
            _loop{loop ? loop->loop() : std::make_shared<Loop>()}
    {
        auto local_addr = to_address(local);

        auto established = make_conn_established_cb(std::move(on_connection));
        auto closed = make_conn_closed_cb(std::move(on_connection_closed));
        auto dgram_cb = make_dgram_cb(std::move(on_datagram));
        auto dgrams = datagram_option(datagrams, datagram_splitting, datagram_bufsize, datagram_queue_limit);

        // Every option is passed as an optional, which libquic's option handling treats as "not
        // given" when empty; that is what lets a variadic C++ API be driven by keyword arguments.
        auto ep = without_gil([&] {
            return Endpoint::endpoint(
                    *_loop,
                    local_addr,
                    value_option<opt::alpns>(alpns),
                    duration_option<opt::handshake_timeout, std::chrono::nanoseconds>(handshake_timeout),
                    value_option<opt::max_udp_payload>(max_udp_payload),
                    flag_option<opt::allow_gso>(allow_gso),
                    std::move(dgrams),
                    callback_option(std::move(established)),
                    callback_option(std::move(closed)),
                    callback_option(std::move(dgram_cb)));
        });

        _ep = loop_owned<Endpoint>{std::move(ep)};
    }

    void PyEndpoint::listen(
            std::shared_ptr<TLSCreds> creds,
            py::object on_connection,
            py::object on_connection_closed,
            py::object on_stream_data,
            py::object on_stream_close,
            py::object on_stream_fin,
            py::object on_stream_construct,
            py::object on_stream_open,
            py::object on_datagram)
    {
        if (!creds)
            throw py::value_error{"listen() requires credentials"};

        auto dgram_cb = make_dgram_cb(std::move(on_datagram));

        auto established = make_conn_established_cb(std::move(on_connection));
        auto closed = make_conn_closed_cb(std::move(on_connection_closed));
        auto data_cb = make_stream_data_cb(std::move(on_stream_data));
        auto stream_closed = make_stream_close_cb(std::move(on_stream_close));
        auto fin_cb = make_stream_fin_cb(std::move(on_stream_fin));
        auto ctor_cb = make_stream_ctor_cb(std::move(on_stream_construct));
        auto open_cb = make_stream_open_cb(std::move(on_stream_open));

        without_gil([&] {
            get().listen(
                    std::move(creds),
                    callback_option(std::move(data_cb)),
                    callback_option(std::move(stream_closed)),
                    fin_cb.cb ? std::optional{std::move(fin_cb)} : std::nullopt,
                    callback_option(std::move(ctor_cb)),
                    callback_option(std::move(open_cb)),
                    callback_option(std::move(established)),
                    callback_option(std::move(closed)),
                    callback_option(std::move(dgram_cb)));
        });
    }

    py::object PyEndpoint::connect(
            const py::object& remote,
            const py::object& remote_pubkey,
            std::shared_ptr<TLSCreds> creds,
            std::optional<std::vector<std::string>> alpns,
            std::optional<double> idle_timeout,
            std::optional<double> keep_alive,
            std::optional<double> handshake_timeout,
            py::object on_connection,
            py::object on_connection_closed,
            py::object on_stream_data,
            py::object on_stream_close,
            py::object on_stream_fin,
            py::object on_stream_construct,
            py::object on_stream_open,
            py::object on_datagram)
    {
        auto remote_addr = to_address(remote);
        auto pubkey = remote_pubkey.is_none() ? std::vector<std::byte>{} : to_bytes(remote_pubkey);
        std::string_view pk{reinterpret_cast<const char*>(pubkey.data()), pubkey.size()};

        auto established = make_conn_established_cb(std::move(on_connection));
        auto closed = make_conn_closed_cb(std::move(on_connection_closed));
        auto data_cb = make_stream_data_cb(std::move(on_stream_data));
        auto stream_closed = make_stream_close_cb(std::move(on_stream_close));
        auto fin_cb = make_stream_fin_cb(std::move(on_stream_fin));
        auto ctor_cb = make_stream_ctor_cb(std::move(on_stream_construct));
        auto open_cb = make_stream_open_cb(std::move(on_stream_open));
        auto dgram_cb = make_dgram_cb(std::move(on_datagram));

        auto conn = without_gil([&] {
            RemoteAddress raddr{pk, remote_addr};

            auto opt_alpns = value_option<opt::outbound_alpns>(alpns);
            auto opt_idle = duration_option<opt::idle_timeout, std::chrono::milliseconds>(idle_timeout);
            auto opt_keep = duration_option<opt::keep_alive, std::chrono::milliseconds>(keep_alive);
            auto opt_hs = duration_option<opt::handshake_timeout, std::chrono::nanoseconds>(handshake_timeout);

            // connect() static_asserts on being given at most one credentials argument, so the
            // absent case has to be a separate call rather than an empty optional.
            if (creds)
                return get().connect(
                        std::move(raddr),
                        std::move(creds),
                        std::move(opt_alpns),
                        std::move(opt_idle),
                        std::move(opt_keep),
                        std::move(opt_hs),
                        callback_option(std::move(data_cb)),
                        callback_option(std::move(stream_closed)),
                        fin_cb.cb ? std::optional{std::move(fin_cb)} : std::nullopt,
                        callback_option(std::move(ctor_cb)),
                        callback_option(std::move(open_cb)),
                        callback_option(std::move(established)),
                        callback_option(std::move(closed)),
                        callback_option(std::move(dgram_cb)));

            return get().connect(
                    std::move(raddr),
                    std::move(opt_alpns),
                    std::move(opt_idle),
                    std::move(opt_keep),
                    std::move(opt_hs),
                    callback_option(std::move(data_cb)),
                    callback_option(std::move(stream_closed)),
                    fin_cb.cb ? std::optional{std::move(fin_cb)} : std::nullopt,
                    callback_option(std::move(ctor_cb)),
                    callback_option(std::move(open_cb)),
                    callback_option(std::move(established)),
                    callback_option(std::move(closed)),
                    callback_option(std::move(dgram_cb)));
        });

        return wrap(std::move(conn));
    }

    void PyEndpoint::close(double wait)
    {
        if (!_ep)
            return;

        gil_release unlock;
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::duration<double>{wait});
        if (us > std::chrono::microseconds::zero())
            _ep->close_conns(us);
        _ep.reset();
        _loop.reset();
    }

    void init_endpoint(py::module_& m)
    {
        py::class_<PyLoop>{m, "Loop", R"(An event loop running on its own thread.

Only needed in order to share one loop between several endpoints; an Endpoint given no loop
creates and owns its own.  The loop stays alive as long as any endpoint using it does.
)"}
                .def(py::init<>());

        py::class_<PyConnection>{m, "Connection", R"(A QUIC connection.

Returned by `Endpoint.connect()`, and handed to the connection callbacks for incoming
connections.  Connection objects compare equal when they refer to the same connection.
)"}
                .def("open_stream",
                     &PyConnection::open_stream,
                     // Keeps this connection object alive for as long as the returned stream is,
                     // which in turn keeps the endpoint alive when the connection came from
                     // connect().
                     py::keep_alive<0, 1>(),
                     py::arg("on_data") = py::none(),
                     py::arg("on_close") = py::none(),
                     py::arg("on_fin") = py::none(),
                     R"(Opens a new outgoing stream.

The stream may not be usable immediately: if the connection has no stream slots free it is queued
and becomes ready when one opens up.  Check `Stream.is_ready`.
)")
                .def("open_bt_stream",
                     &PyConnection::open_bt_stream,
                     py::keep_alive<0, 1>(),
                     py::arg("on_request") = py::none(),
                     py::arg("on_close") = py::none(),
                     R"(Opens a bt-request stream to the other end.

`on_request` becomes the stream's generic handler, used for any command with no `register_handler`
endpoint of its own.
)")
                .def("queue_incoming_bt_stream",
                     &PyConnection::queue_incoming_bt_stream,
                     py::keep_alive<0, 1>(),
                     py::arg("on_request") = py::none(),
                     py::arg("on_close") = py::none(),
                     R"(Prepares a bt-request stream for the other end to open.

The returned stream takes the next incoming stream id and becomes usable once the other end opens
it.  This is the mirror image of `open_bt_stream`, and either side of a connection can do either.

For a protocol where only *some* incoming streams are bt-request streams -- stream 0 but not the
rest, say -- use `on_stream_construct` on listen()/connect() instead, which sees the stream id.
)")
                .def("send_datagram",
                     &PyConnection::send_datagram,
                     py::arg("data"),
                     R"(Sends an unreliable datagram.

Requires datagrams to have been enabled on both endpoints.  Data longer than `max_datagram_size`
is dropped rather than split across datagrams, and a datagram may be lost, duplicated or delivered
out of order -- if you need it to arrive, use a stream.
)")
                .def_property_readonly(
                        "datagrams_enabled",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->datagrams_enabled(); });
                        })
                .def_property_readonly(
                        "max_datagram_size",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->get_max_datagram_size(); });
                        },
                        R"(The largest datagram this connection can currently carry.

Negotiated, and it changes over time as the path MTU is discovered, so read it when you are about
to send rather than caching it.  Splitting roughly doubles it.
)")
                .def("close",
                     &PyConnection::close,
                     py::arg("error_code") = 0,
                     "Closes the connection, sending the given application error code to the other end.")
                .def_property_readonly(
                        "is_alive",
                        [](const PyConnection& c) { return static_cast<bool>(c.handle().lock()); },
                        "False once the connection's endpoint has gone away, after which the other members raise.")
                .def_property_readonly(
                        "is_established",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->is_handshaked(); });
                        },
                        "True once the handshake has completed.")
                .def_property_readonly(
                        "is_closing",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->is_closing(); });
                        })
                .def_property_readonly(
                        "is_inbound",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->is_inbound(); });
                        },
                        "True if the other end initiated this connection.")
                .def_property_readonly(
                        "local",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->local(); });
                        })
                .def_property_readonly(
                        "remote",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->remote(); });
                        })
                .def_property_readonly(
                        "alpn",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return py::bytes{without_gil([&] { return std::string{conn->selected_alpn()}; })};
                        },
                        "The negotiated ALPN, or empty until the connection is established.")
                .def_property_readonly(
                        "remote_pubkey",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            auto key = without_gil([&] {
                                auto k = conn->remote_key();
                                return std::vector<unsigned char>{k.begin(), k.end()};
                            });
                            return from_bytes(std::span{key});
                        },
                        R"(The other end's public key, or empty if it is not known.

For an outgoing connection this is known from the start; for an incoming one it is known only
after the handshake, and only if client keys are required.
)")
                .def_property_readonly(
                        "num_streams_active",
                        [](const PyConnection& c) {
                            auto conn = c.get();
                            return without_gil([&] { return conn->num_streams_active(); });
                        })
                .def(
                        "__eq__",
                        [](const PyConnection& a, const py::object& b) {
                            const auto* other = py::isinstance<PyConnection>(b) ? b.cast<const PyConnection*>() : nullptr;
                            return other != nullptr && a.handle() == other->handle();
                        },
                        py::arg("other"))
                .def("__hash__", [](const PyConnection& c) { return std::hash<const void*>{}(c.handle().identity()); });

        py::class_<PyEndpoint>{m, "Endpoint", R"(A bound UDP socket that QUIC connections run over.

Owns its own event loop thread unless given one to share.  Call `listen()` to accept incoming
connections, `connect()` to make outgoing ones, or both.
)"}
                .def(py::init<
                             const py::object&,
                             PyLoop*,
                             std::optional<std::vector<std::string>>,
                             std::optional<double>,
                             std::optional<size_t>,
                             bool,
                             bool,
                             bool,
                             std::optional<int>,
                             std::optional<size_t>,
                             py::object,
                             py::object,
                             py::object>(),
                     py::arg("local") = py::str{""},
                     py::arg("loop") = nullptr,
                     py::arg("alpns") = py::none(),
                     py::arg("handshake_timeout") = py::none(),
                     py::arg("max_udp_payload") = py::none(),
                     py::arg("allow_gso") = false,
                     py::arg("datagrams") = false,
                     py::arg("datagram_splitting") = false,
                     py::arg("datagram_bufsize") = py::none(),
                     py::arg("datagram_queue_limit") = py::none(),
                     py::arg("on_connection") = py::none(),
                     py::arg("on_connection_closed") = py::none(),
                     py::arg("on_datagram") = py::none(),
                     R"(A bound UDP socket, with its own event loop thread unless given one to share.

`datagrams=True` enables QUIC datagrams on connections from this endpoint; both ends must enable
them.  `datagram_splitting=True` lets a datagram be sent across two QUIC packets, roughly doubling
the size one can carry, with `datagram_bufsize` sizing the reassembly buffer.  Datagrams are
unreliable and unordered: they may be dropped, and are dropped outright once more than
`datagram_queue_limit` bytes are queued on a connection.
)")
                .def("listen",
                     &PyEndpoint::listen,
                     py::arg("creds"),
                     py::arg("on_connection") = py::none(),
                     py::arg("on_connection_closed") = py::none(),
                     py::arg("on_stream_data") = py::none(),
                     py::arg("on_stream_close") = py::none(),
                     py::arg("on_stream_fin") = py::none(),
                     py::arg("on_stream_construct") = py::none(),
                     py::arg("on_stream_open") = py::none(),
                     py::arg("on_datagram") = py::none(),
                     R"(Starts accepting incoming connections.  May only be called once per endpoint.

`on_stream_construct(connection, stream_id)` decides what kind of stream an incoming stream should
be, for protocols where that depends on the id -- returning `BTRequestStream` builds one, and
returning None (or `Stream`) takes the default.  `on_stream_open(stream)` is then called with the
constructed stream, which is where handlers go; returning an error code from it closes the stream.
)")
                .def("connect",
                     &PyEndpoint::connect,
                     // Keeps this endpoint alive for as long as the returned connection is.  The
                     // connection is only a weak handle on a libquic object the endpoint owns, so
                     // without this `Endpoint(...).connect(...)` would have the endpoint collected
                     // -- and the connection closed -- the moment the expression finished.
                     py::keep_alive<0, 1>(),
                     py::arg("remote"),
                     py::arg("remote_pubkey") = py::none(),
                     py::arg("creds") = nullptr,
                     py::arg("alpns") = py::none(),
                     py::arg("idle_timeout") = py::none(),
                     py::arg("keep_alive") = py::none(),
                     py::arg("handshake_timeout") = py::none(),
                     py::arg("on_connection") = py::none(),
                     py::arg("on_connection_closed") = py::none(),
                     py::arg("on_stream_data") = py::none(),
                     py::arg("on_stream_close") = py::none(),
                     py::arg("on_stream_fin") = py::none(),
                     py::arg("on_stream_construct") = py::none(),
                     py::arg("on_stream_open") = py::none(),
                     py::arg("on_datagram") = py::none(),
                     R"(Starts an outgoing connection and returns it immediately, before the handshake.

Watch `on_connection`/`on_connection_closed` to find out how it went.
)")
                .def("close",
                     &PyEndpoint::close,
                     py::arg("wait") = 0.5,
                     R"(Closes every connection and shuts the endpoint down.

Blocks for up to `wait` seconds to give the close packets a chance to go out.  Idempotent; the
endpoint is unusable afterwards.
)")
                .def_property_readonly(
                        "local",
                        [](const PyEndpoint& e) { return without_gil([&] { return e.get().local(); }); },
                        "The bound local address, with the port filled in if the endpoint was bound to port 0.")
                .def_property_readonly("is_accepting", [](const PyEndpoint& e) {
                    return without_gil([&] { return e.get().is_accepting(); });
                });
    }

}  // namespace seshquic
