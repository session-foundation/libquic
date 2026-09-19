#include "wrappers.hpp"

#include <oxen/quic/stream.hpp>

#include <pybind11/pybind11.h>

#include <functional>
#include <string>

namespace seshquic
{
    namespace
    {
        // Raised for a handle whose object is gone.  Not an error the caller could have avoided by
        // checking first -- the connection can go away between the check and the call -- so it is a
        // plain runtime error rather than something to branch on.
        [[noreturn]] void expired(const char* what)
        {
            throw std::runtime_error{std::string{what} + " is no longer available; its owner has been closed"};
        }
    }  // namespace

    std::shared_ptr<Stream> PyStream::get() const
    {
        auto s = _s.lock();
        if (!s)
            expired("stream");
        return s;
    }

    py::object wrap(const std::shared_ptr<Stream>& s)
    {
        // Streams reach Python through callbacks as a plain Stream&, so the subclass has to be
        // recovered here; otherwise a bt-request stream arrives at an on_stream_open callback
        // without the methods that make it one.
        if (auto bt = std::dynamic_pointer_cast<oxen::quic::BTRequestStream>(s))
            return wrap_bt(bt);

        return py::cast(new PyStream{s}, py::return_value_policy::take_ownership);
    }

    py::object wrap_stream(Stream& s)
    {
        // weak_from_this rather than shared_from_this: a close callback can run while the stream is
        // being torn down, where shared_from_this throws.  An empty handle is fine here -- the
        // Python object simply reports the stream as gone.
        return wrap(s.weak_from_this().lock());
    }

    void PyStream::send(const py::object& data)
    {
        // Copied rather than kept as a view: libquic holds the buffer until the data is acked, and
        // a Python buffer can be resized, mutated or freed in the meantime.
        auto buf = to_bytes(data);
        auto s = get();
        without_gil([&] { s->send(std::move(buf)); });
    }

    void PyStream::send_fin()
    {
        auto s = get();
        without_gil([&] { s->send_fin(); });
    }

    void PyStream::close(uint64_t error_code)
    {
        auto s = get();
        without_gil([&] { s->close(error_code); });
    }

    oxen::quic::stream_data_callback make_stream_data_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](Stream& s, std::span<const std::byte> data) {
            py::gil_scoped_acquire gil;
            fn(wrap_stream(s), from_bytes(data));
        };
    }

    oxen::quic::stream_close_callback make_stream_close_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](Stream& s, uint64_t error_code) {
            py::gil_scoped_acquire gil;
            fn(wrap_stream(s), error_code);
        };
    }

    oxen::quic::opt::stream_fin_callback make_stream_fin_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return {};

        return {[fn = std::move(fn)](Stream& s) {
            py::gil_scoped_acquire gil;
            fn(wrap_stream(s));
        }};
    }

    oxen::quic::stream_open_callback make_stream_open_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](Stream& s) -> uint64_t {
            py::gil_scoped_acquire gil;

            // A returned error code closes the stream with it; None (or a callback that raised)
            // accepts it, which is what an ordinary setup function will do.
            auto rv = fn.call(wrap_stream(s));
            if (!rv || rv.is_none())
                return 0;

            try
            {
                return rv.cast<uint64_t>();
            }
            catch (const py::cast_error&)
            {
                py::set_error(PyExc_TypeError, "a stream open callback must return None or an integer error code");
                py::error_already_set e;
                e.discard_as_unraisable("seshquic stream open callback");
                return 0;
            }
        };
    }

    void PyStream::set_data_callback(py::object cb)
    {
        auto f = make_stream_data_cb(std::move(cb));
        auto s = get();
        without_gil([&] { s->set_data_callback(std::move(f)); });
    }

    void PyStream::set_close_callback(py::object cb)
    {
        auto f = make_stream_close_cb(std::move(cb));
        auto s = get();
        without_gil([&] { s->set_close_callback(std::move(f)); });
    }

    void PyStream::set_fin_callback(py::object cb)
    {
        auto f = make_stream_fin_cb(std::move(cb));
        auto s = get();
        without_gil([&] { s->set_fin_callback(std::move(f.cb)); });
    }

    void init_stream(py::module_& m)
    {
        py::class_<PyStream>{m, "Stream", R"(A QUIC stream.

Obtained from `Connection.open_stream()`, or handed to the stream callbacks for streams the
remote opened.  Stream objects compare equal when they refer to the same underlying stream.

A stream is owned by its connection, not by this object: once the connection closes, using this
raises RuntimeError rather than keeping a dead stream alive.
)"}
                .def("send",
                     &PyStream::send,
                     py::arg("data"),
                     R"(Queues a bytes-like object for sending.

The data is copied, so the caller's buffer may be reused immediately.  Returns as soon as the
data is queued, not when it has been sent or acknowledged.
)")
                .def("send_fin", &PyStream::send_fin, R"(Signals that no more data will be sent.

Any data still queued goes out first.  Further `send` calls on the stream are dropped.
)")
                .def("close",
                     &PyStream::close,
                     py::arg("error_code") = 0,
                     "Closes the stream, telling the other end the given application error code.")
                .def_property_readonly(
                        "is_alive",
                        [](const PyStream& s) { return static_cast<bool>(s.handle().lock()); },
                        "False once the stream's connection has gone away, after which the other members raise.")
                .def_property_readonly(
                        "stream_id",
                        [](const PyStream& s) {
                            auto st = s.get();
                            return without_gil([&] { return st->stream_id(); });
                        },
                        "The QUIC stream id, or a negative value if one has not been assigned yet.")
                .def_property_readonly(
                        "is_ready",
                        [](const PyStream& s) {
                            auto st = s.get();
                            return without_gil([&] { return st->is_ready(); });
                        },
                        "True once the stream has an id and can carry data to the other end.")
                .def_property_readonly(
                        "writable",
                        [](const PyStream& s) {
                            auto st = s.get();
                            return without_gil([&] { return st->writable(); });
                        },
                        "True if the stream can still accept data to send.")
                .def_property_readonly(
                        "readable",
                        [](const PyStream& s) {
                            auto st = s.get();
                            return without_gil([&] { return st->readable(); });
                        },
                        "True if more data may still arrive; False once the other end has sent its FIN.")
                .def_property_readonly(
                        "unsent",
                        [](const PyStream& s) {
                            auto st = s.get();
                            return without_gil([&] { return st->unsent(); });
                        },
                        "Bytes queued by `send` that have not yet gone into a QUIC packet.")
                .def_property_readonly(
                        "acked_bytes",
                        [](const PyStream& s) {
                            auto st = s.get();
                            return without_gil([&] { return st->acked_bytes(); });
                        },
                        "Total bytes the other end has acknowledged receiving.")
                .def_property_readonly(
                        "unacked_bytes",
                        [](const PyStream& s) {
                            auto st = s.get();
                            return without_gil([&] { return st->unacked_bytes(); });
                        },
                        "Bytes sent on the wire but not yet acknowledged.")
                .def("_set_data_callback", &PyStream::set_data_callback, py::arg("callback"))
                .def("_set_close_callback", &PyStream::set_close_callback, py::arg("callback"))
                .def("_set_fin_callback", &PyStream::set_fin_callback, py::arg("callback"))
                .def(
                        "__eq__",
                        [](const PyStream& a, const py::object& b) {
                            const auto* other = py::isinstance<PyStream>(b) ? b.cast<const PyStream*>() : nullptr;
                            return other != nullptr && a.handle() == other->handle();
                        },
                        py::arg("other"))
                .def("__hash__", [](const PyStream& s) { return std::hash<const void*>{}(s.handle().identity()); })
                .def("__repr__", [](const PyStream& s) {
                    auto st = s.handle().lock();
                    if (!st)
                        return std::string{"<Stream (closed)>"};
                    return "<Stream id=" + std::to_string(without_gil([&] { return st->stream_id(); })) + ">";
                });
    }

}  // namespace seshquic
