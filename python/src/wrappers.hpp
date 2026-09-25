#pragma once

#include "common.hpp"

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/loop.hpp>
#include <oxen/quic/stream.hpp>

#include <pybind11/pybind11.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace seshquic
{
    using oxen::quic::Connection;
    using oxen::quic::Endpoint;
    using oxen::quic::Loop;
    using oxen::quic::Stream;

    /// Holds a Python callable that libquic will invoke from its event loop thread.
    ///
    /// Calling a Python object needs the GIL, and so does *destroying* one; this is destroyed on
    /// the loop thread when the stream or connection holding it goes away, so it owns that detail
    /// rather than leaving it to each call site.  Copyability is required because libquic stores
    /// these in std::function, which is copy-constructible.
    class py_callback
    {
        // Held indirectly so that copying a py_callback is a refcount bump on the shared_ptr rather
        // than a Py_INCREF: libquic copies the std::function this ends up inside, and a copy can
        // happen on the loop thread without the GIL, which touching a py::object directly would
        // not survive.  The GIL is needed only once, in the deleter.
        std::shared_ptr<py::object> _fn;

        static void release(py::object* fn)
        {
            if (python_is_finalizing())
            {
                // Dropping the reference needs the GIL, which this thread will never be given
                // again: CPython parks non-main threads that ask for it during finalization.
                // release() hands off ownership without decrementing, deliberately leaking -- the
                // interpreter is taking the whole heap with it, whereas blocking here would wedge
                // the process at exit.
                fn->release();
                delete fn;
                return;
            }

            py::gil_scoped_acquire gil;
            delete fn;
        }

      public:
        py_callback() = default;

        explicit py_callback(py::object fn)
        {
            if (fn && !fn.is_none())
                _fn = std::shared_ptr<py::object>{new py::object{std::move(fn)}, &release};
        }

        explicit operator bool() const { return static_cast<bool>(_fn); }

        /// Invokes the callback with the GIL held.
        ///
        /// Exceptions do not propagate: this sits on libquic's callback stack, which runs through
        /// ngtcp2's C callbacks, so letting one escape would terminate the process.  A Python
        /// exception is reported through sys.unraisablehook instead, which is where an exception
        /// from a thread that nobody can catch belongs.
        ///
        /// Callers that build Python arguments must hold the GIL themselves while doing so;
        /// acquiring it again here is cheap and reentrant.
        template <typename... Args>
        void operator()(Args&&... args) const
        {
            call(std::forward<Args>(args)...);
        }

        /// As above, returning what the callback returned; an empty object if it was not set, or
        /// if it raised (which is reported rather than propagated, as above).
        template <typename... Args>
        py::object call(Args&&... args) const
        {
            if (!_fn || python_is_finalizing())
                return {};

            py::gil_scoped_acquire gil;
            try
            {
                return (*_fn)(std::forward<Args>(args)...);
            }
            catch (py::error_already_set& e)
            {
                e.discard_as_unraisable(*_fn);
                return {};
            }
        }
    };

    /// An event loop, which runs on its own thread.
    ///
    /// Only worth holding directly in order to share one between endpoints; an Endpoint given no
    /// loop makes its own.
    class PyLoop
    {
        std::shared_ptr<Loop> _loop{std::make_shared<Loop>()};

      public:
        PyLoop() = default;
        PyLoop(const PyLoop&) = delete;
        PyLoop& operator=(const PyLoop&) = delete;

        ~PyLoop()
        {
            gil_release unlock;
            _loop.reset();
        }

        const std::shared_ptr<Loop>& loop() const { return _loop; }
    };

    class PyStream
    {
        observed<Stream> _s;

      public:
        explicit PyStream(const std::shared_ptr<Stream>& s) : _s{s} {}

        /// The stream, or a raised Python exception if its connection has gone away.
        std::shared_ptr<Stream> get() const;
        const observed<Stream>& handle() const { return _s; }

        void send(const py::object& data);
        void send_fin();
        void close(uint64_t error_code);

        void set_data_callback(py::object cb);
        void set_close_callback(py::object cb);
        void set_fin_callback(py::object cb);
    };

    /// An incoming request, reply or error.
    ///
    /// libquic hands these to callbacks by value and they own their data, so unlike a stream or a
    /// connection there is nothing here whose lifetime belongs to something else.
    struct PyMessage
    {
        oxen::quic::message msg;

        explicit PyMessage(oxen::quic::message m) : msg{std::move(m)} {}
    };

    class PyBTStream : public PyStream
    {
      public:
        using PyStream::PyStream;

        /// The stream as a BTRequestStream, or a raised Python exception if it has gone away.
        std::shared_ptr<oxen::quic::BTRequestStream> bt() const;

        void command(std::string endpoint, const py::object& body, py::object on_response, std::optional<double> timeout);
        void register_handler(std::string endpoint, py::object handler);
        void register_generic_handler(py::object handler);
    };

    class PyConnection
    {
        observed<Connection> _c;

      public:
        explicit PyConnection(const std::shared_ptr<Connection>& c) : _c{c} {}

        /// The connection, or a raised Python exception if its endpoint has gone away.
        std::shared_ptr<Connection> get() const;
        const observed<Connection>& handle() const { return _c; }

        py::object open_stream(py::object on_data, py::object on_close, py::object on_fin);

        /// Opens a bt-request stream to the other end, or prepares one for the other end to open.
        /// Both are available on either side of any connection; they are the two halves of a pair,
        /// not a client and a server role.
        py::object open_bt_stream(py::object on_request, py::object on_close);
        py::object queue_incoming_bt_stream(py::object on_request, py::object on_close);

        void send_datagram(const py::object& data);

        void close(uint64_t error_code);
    };

    class PyEndpoint
    {
        // Declared first so that it outlives the endpoint: libquic requires the loop to stay alive
        // for the endpoint's lifetime, and does not itself hold a reference.
        std::shared_ptr<Loop> _loop;
        loop_owned<Endpoint> _ep;

      public:
        PyEndpoint(
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
                py::object on_datagram);

        Endpoint& get() const;

        void listen(
                std::shared_ptr<oxen::quic::TLSCreds> creds,
                py::object on_connection,
                py::object on_connection_closed,
                py::object on_stream_data,
                py::object on_stream_close,
                py::object on_stream_fin,
                py::object on_stream_construct,
                py::object on_stream_open,
                py::object on_datagram);

        py::object connect(
                const py::object& remote,
                const py::object& remote_pubkey,
                std::shared_ptr<oxen::quic::TLSCreds> creds,
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
                py::object on_datagram);

        void close(double wait);
    };

    /// Wraps a libquic object in a fresh Python object.  The GIL must be held.
    ///
    /// Each call makes a new Python object referring to the same underlying stream or connection,
    /// so identity is not preserved across callbacks; equality and hashing are.
    py::object wrap(const std::shared_ptr<Stream>& s);
    py::object wrap(const std::shared_ptr<Connection>& c);

    py::object wrap_bt(const std::shared_ptr<oxen::quic::BTRequestStream>& s);

    /// As above, from the reference a libquic callback is handed.
    py::object wrap_stream(Stream& s);
    py::object wrap_connection(Connection& c);

    /// Builds the libquic callbacks that dispatch into Python.  Each returns an empty function when
    /// given None, so that libquic falls back to its own defaults.
    oxen::quic::stream_data_callback make_stream_data_cb(py::object cb);
    oxen::quic::stream_close_callback make_stream_close_cb(py::object cb);
    oxen::quic::opt::stream_fin_callback make_stream_fin_cb(py::object cb);
    oxen::quic::connection_established_callback make_conn_established_cb(py::object cb);
    oxen::quic::connection_closed_callback make_conn_closed_cb(py::object cb);
    std::function<void(oxen::quic::message)> make_message_cb(py::object cb);
    oxen::quic::stream_constructor_callback make_stream_ctor_cb(py::object cb);
    oxen::quic::stream_open_callback make_stream_open_cb(py::object cb);
    oxen::quic::dgram_data_callback make_dgram_cb(py::object cb);

    /// Assembles opt::enable_datagrams from the keyword arguments that configure it, or nothing at
    /// all when datagrams were not asked for.  Throws if the options were given without enabling.
    std::optional<oxen::quic::opt::enable_datagrams> datagram_option(
            bool enabled, bool splitting, std::optional<int> bufsize, std::optional<size_t> queue_limit);

    // Builders for `opt::` options from omittable Python arguments.  libquic's option handling
    // skips an empty optional, which is what lets its variadic interfaces be driven by keyword
    // arguments without any template machinery at the call site.

    /// From a value that may not have been given.
    template <typename Option, typename T>
    std::optional<Option> value_option(const std::optional<T>& val)
    {
        if (!val)
            return std::nullopt;
        return Option{*val};
    }

    /// From a duration in seconds, as Python expresses one.
    template <typename Option, typename Duration>
    std::optional<Option> duration_option(const std::optional<double>& seconds)
    {
        if (!seconds)
            return std::nullopt;
        return Option{std::chrono::duration_cast<Duration>(std::chrono::duration<double>{*seconds})};
    }

    /// For an option that is simply present or absent.
    template <typename Option>
    std::optional<Option> flag_option(bool enabled)
    {
        if (!enabled)
            return std::nullopt;
        return Option{};
    }

    /// For a callback option, which is "not given" when the Python argument was None.
    template <typename Callback>
    std::optional<Callback> callback_option(Callback cb)
    {
        if (!cb)
            return std::nullopt;
        return std::move(cb);
    }

    void init_endpoint(py::module_& m);
    void init_stream(py::module_& m);
    void init_btstream(py::module_& m);

}  // namespace seshquic
