#include "wrappers.hpp"

#include <oxen/quic/btstream.hpp>

#include <pybind11/pybind11.h>

#include <chrono>
#include <optional>
#include <string>
#include <utility>

namespace seshquic
{
    using oxen::quic::BTRequestStream;
    using oxen::quic::message;

    std::shared_ptr<BTRequestStream> PyBTStream::bt() const
    {
        auto s = std::dynamic_pointer_cast<BTRequestStream>(get());
        if (!s)
            throw std::runtime_error{"stream is not a BTRequestStream"};
        return s;
    }

    py::object wrap_bt(const std::shared_ptr<BTRequestStream>& s)
    {
        return py::cast(new PyBTStream{s}, py::return_value_policy::take_ownership);
    }

    std::function<void(message)> make_message_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](message m) {
            py::gil_scoped_acquire gil;
            fn(py::cast(new PyMessage{std::move(m)}, py::return_value_policy::take_ownership));
        };
    }

    void PyBTStream::command(
            std::string endpoint, const py::object& body, py::object on_response, std::optional<double> timeout)
    {
        auto data = to_bytes(body);
        auto cb = make_message_cb(std::move(on_response));
        auto s = bt();

        without_gil([&] {
            // An empty callback is how libquic distinguishes a fire-and-forget command from a
            // request that is owed a response, so it can be passed through either way.
            s->command(
                    std::move(endpoint),
                    std::span<const std::byte>{data},
                    std::move(cb),
                    duration_option<std::chrono::milliseconds, std::chrono::milliseconds>(timeout));
        });
    }

    void PyBTStream::register_handler(std::string endpoint, py::object handler)
    {
        auto cb = make_message_cb(std::move(handler));
        if (!cb)
            throw py::value_error{"a handler is required"};

        auto s = bt();
        without_gil([&] { s->register_handler(std::move(endpoint), std::move(cb)); });
    }

    void PyBTStream::register_generic_handler(py::object handler)
    {
        auto cb = make_message_cb(std::move(handler));
        auto s = bt();
        without_gil([&] { s->register_generic_handler(std::move(cb)); });
    }

    oxen::quic::stream_constructor_callback make_stream_ctor_cb(py::object cb)
    {
        py_callback fn{std::move(cb)};
        if (!fn)
            return nullptr;

        return [fn = std::move(fn)](
                       Connection& c, oxen::quic::Endpoint& e, std::optional<int64_t> id) -> std::shared_ptr<Stream> {
            py::gil_scoped_acquire gil;

            auto want = fn.call(wrap_connection(c), id ? py::cast(*id) : py::none());

            // Only BTRequestStream is built here.  None, seshquic.Stream, and a callback that
            // raised all fall through to libquic's own default, which is a plain Stream already
            // wired up with whatever stream callbacks the endpoint or connect() was given --
            // something this shim has no way to reproduce, since the IOContext holding them is
            // private to the connection.
            if (want && !want.is_none() && want.is(py::type::of<PyBTStream>()))
                return e.job_queue.make_shared<BTRequestStream>(c, e);

            return nullptr;
        };
    }

    void init_btstream(py::module_& m)
    {
        py::class_<PyMessage>{m, "Message", R"(An incoming bt-encoded request, reply or error.

Handed to a request handler for a command the other end invoked, and to a response callback for
the answer to one of ours.  Truthy when it is a successful reply, i.e. neither an error nor a
timeout.
)"}
                .def(
                        "respond",
                        [](const PyMessage& m, const py::object& body, bool error) {
                            auto data = to_bytes(body);
                            without_gil([&] { m.msg.respond(std::span<const std::byte>{data}, error); });
                        },
                        py::arg("body"),
                        py::arg("error") = false,
                        R"(Answers this request.

Raises RuntimeError if the stream it came in on is already gone.
)")
                .def_property_readonly(
                        "body",
                        [](const PyMessage& m) { return from_bytes(m.msg.body<std::byte>()); },
                        "The request or response body.")
                .def_property_readonly(
                        "endpoint",
                        [](const PyMessage& m) { return std::string{m.msg.endpoint()}; },
                        "The name of the endpoint being invoked; empty for a response.")
                .def_property_readonly(
                        "request_id",
                        [](const PyMessage& m) { return m.msg.rid(); },
                        "The request id, which ties a response back to the request that asked for it.")
                .def_property_readonly(
                        "is_error",
                        [](const PyMessage& m) { return m.msg.is_error(); },
                        "True if this is an error response.")
                .def_property_readonly(
                        "timed_out",
                        [](const PyMessage& m) { return m.msg.timed_out; },
                        R"(True if no response arrived in time.

This can fire earlier than the requested timeout when the answer is known to be impossible, such
as the connection closing.
)")
                .def_property_readonly(
                        "stream",
                        [](const PyMessage& m) -> py::object {
                            try
                            {
                                return wrap_bt(m.msg.stream());
                            }
                            catch (const std::exception&)
                            {
                                return py::none();
                            }
                        },
                        "The stream this arrived on, or None if it has gone away.")
                .def("__bool__", [](const PyMessage& m) { return static_cast<bool>(m.msg); })
                .def("__repr__", [](const PyMessage& m) -> std::string {
                    if (m.msg.timed_out)
                        return "<Message timed out>";

                    std::string what = m.msg.is_error()         ? "error"
                                     : m.msg.endpoint().empty() ? "reply"
                                                                : std::string{m.msg.endpoint()};
                    return "<Message " + what + " id=" + std::to_string(m.msg.rid()) + " " +
                           std::to_string(m.msg.body().size()) + " bytes>";
                });

        py::class_<PyBTStream, PyStream>{m, "BTRequestStream", R"(A stream carrying bt-encoded requests.

Obtained from `Connection.open_bt_stream()` for a stream you open, or
`Connection.queue_incoming_bt_stream()` for one the other end will open.  Both ends can do either,
independently, on the same connection.

Requests and handlers are per-stream, so the two directions are separate: registering a handler
here answers commands the other end sends *on this stream*.
)"}
                .def("_command",
                     &PyBTStream::command,
                     py::arg("endpoint"),
                     py::arg("body"),
                     py::arg("on_response") = py::none(),
                     py::arg("timeout") = py::none())
                .def("register_handler",
                     &PyBTStream::register_handler,
                     py::arg("endpoint"),
                     py::arg("handler"),
                     R"(Registers a handler for one endpoint the other end may invoke.

The handler is called with a `Message`; answer it with `message.respond(...)`.  Raising
`seshquic.NoSuchEndpoint` from it returns a not-found error to the caller.
)")
                .def("register_generic_handler",
                     &PyBTStream::register_generic_handler,
                     py::arg("handler"),
                     R"(Registers the handler used when no `register_handler` endpoint matches.

With no individual handlers registered at all, this becomes the single handler for every incoming
command.
)")
                .def_property_readonly(
                        "num_pending",
                        [](const PyBTStream& s) {
                            auto bt = s.bt();
                            return without_gil([&] { return bt->num_pending(); });
                        },
                        "Requests queued here but not yet sent.")
                .def_property_readonly(
                        "num_awaiting_response",
                        [](const PyBTStream& s) {
                            auto bt = s.bt();
                            return without_gil([&] { return bt->num_awaiting_response(); });
                        },
                        "Requests sent whose response has not arrived yet.");
    }

}  // namespace seshquic
