#pragma once

#include <pybind11/pybind11.h>
// Included here rather than per-file on purpose: the std::optional/std::vector casters must be
// visible in *every* translation unit that registers a function using them.  A file that misses it
// silently instantiates a different caster for the same type, and the resulting ODR violation
// breaks conversions in whichever definition the linker keeps -- including in files that did
// include it.
#include <pybind11/stl.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace oxen::quic
{
    struct Address;
}

namespace seshquic
{
    namespace py = pybind11;

    /// Releases the GIL for the duration of the scope, but only if this thread is actually holding
    /// it.  pybind11's gil_scoped_release asserts ownership, and these helpers are reachable both
    /// from Python calls (GIL held) and from libquic's event loop thread (usually not), as well as
    /// nested inside each other during destruction.
    class gil_release
    {
        std::optional<py::gil_scoped_release> _release;

      public:
        gil_release()
        {
            if (PyGILState_Check())
                _release.emplace();
        }
    };

    /// True once the interpreter has started shutting down.
    ///
    /// After that point CPython parks any non-main thread that asks for the GIL, permanently, so
    /// anything running on the event loop thread must check this before trying to take it: the
    /// alternative is a hang at exit rather than an error.
    inline bool python_is_finalizing()
    {
#if PY_VERSION_HEX >= 0x030d0000
        return Py_IsFinalizing() != 0;
#else
        return _Py_IsFinalizing() != 0;
#endif
    }

    /// Owns a libquic object on Python's behalf.
    ///
    /// Endpoints, connections and streams are created with deleters that dispatch destruction to
    /// the event loop thread and block until it finishes.  Python drops its last reference at an
    /// arbitrary point with the GIL held -- during garbage collection, say -- and that block would
    /// then deadlock against the loop thread waiting for the GIL to run a callback.  So the GIL
    /// goes away before the reference does.
    ///
    /// The same applies to anything else that waits on the loop, which is why the wrappers below
    /// call into libquic through `without_gil` rather than holding it across the call.
    template <typename T>
    class loop_owned
    {
        std::shared_ptr<T> _ptr;

      public:
        loop_owned() = default;
        explicit loop_owned(std::shared_ptr<T> ptr) : _ptr{std::move(ptr)} {}

        loop_owned(const loop_owned&) = delete;
        loop_owned& operator=(const loop_owned&) = delete;
        loop_owned(loop_owned&&) = default;
        loop_owned& operator=(loop_owned&&) = default;

        ~loop_owned() { reset(); }

        void reset()
        {
            if (!_ptr)
                return;
            gil_release unlock;
            _ptr.reset();
        }

        const std::shared_ptr<T>& ptr() const { return _ptr; }
        T* get() const { return _ptr.get(); }
        T* operator->() const { return _ptr.get(); }
        T& operator*() const { return *_ptr; }
        explicit operator bool() const { return static_cast<bool>(_ptr); }
    };

    /// Holds a libquic object that Python only observes.
    ///
    /// libquic already has an owner for each of these: an endpoint owns its connections, and a
    /// connection owns its streams.  A strong reference from Python would let one outlive that
    /// owner -- a connection whose endpoint has been closed, say -- and its destructor reaches back
    /// into the owner it has outlived.  Holding a weak reference leaves the C++ ownership exactly
    /// as libquic designed it, and turns a stale Python handle into an exception instead of a
    /// crash.  It also means Python never holds the last reference, so none of the loop-dispatched
    /// destruction that `loop_owned` exists to handle can happen here.
    template <typename T>
    class observed
    {
        std::weak_ptr<T> _ptr;

        // Kept only to give Python stable identity and hashing for a handle whose object may since
        // have gone away; never dereferenced.
        const void* _identity{nullptr};

      public:
        observed() = default;

        explicit observed(const std::shared_ptr<T>& ptr) : _ptr{ptr}, _identity{ptr.get()} {}

        /// The object, or nullptr if whatever owned it has gone away.
        std::shared_ptr<T> lock() const { return _ptr.lock(); }

        const void* identity() const { return _identity; }

        bool operator==(const observed& other) const { return _identity == other._identity; }
    };

    /// Invokes `f` with the GIL released.  Every call into libquic goes through this: most of its
    /// accessors dispatch to the event loop thread and block for the result, which deadlocks
    /// against a loop thread trying to acquire the GIL for a callback.
    template <typename F>
    decltype(auto) without_gil(F&& f)
    {
        gil_release unlock;
        return std::forward<F>(f)();
    }

    /// Copies a Python bytes-like object (anything supporting the buffer protocol: bytes,
    /// bytearray, memoryview, array) into owned storage.
    ///
    /// Callers get a copy rather than a view because libquic holds onto send buffers past the call,
    /// and a Python buffer can be mutated or freed in the meantime.  `str` is deliberately not
    /// accepted: the caller picks the encoding, as they do for a socket.
    std::vector<std::byte> to_bytes(const py::object& obj);

    /// Copies data into a new Python `bytes`.  Views handed to callbacks are only valid for the
    /// duration of the callback, so there is nothing to be gained by trying to avoid the copy.
    inline py::bytes from_bytes(std::span<const std::byte> data)
    {
        return py::bytes{reinterpret_cast<const char*>(data.data()), data.size()};
    }

    inline py::bytes from_bytes(std::span<const unsigned char> data)
    {
        return py::bytes{reinterpret_cast<const char*>(data.data()), data.size()};
    }

    /// Builds an Address from the forms a caller might reasonably write: an Address, a "host:port"
    /// string, or a (host, port) tuple.
    oxen::quic::Address to_address(const py::object& obj);

    /// Backs the Address constructor: a lone string is parsed as the combined "host:port" form, an
    /// explicit port is taken as given.
    oxen::quic::Address make_address(const std::string& addr, std::optional<uint16_t> port);

    void init_address(py::module_& m);
    void init_creds(py::module_& m);
    void init_logging(py::module_& m);

}  // namespace seshquic
