#include "common.hpp"

#include <pybind11/pybind11.h>

namespace seshquic
{
    std::vector<std::byte> to_bytes(const py::object& obj)
    {
        if (py::isinstance<py::str>(obj))
            throw py::type_error{"expected a bytes-like object, not str; encode it first"};

        Py_buffer view;
        if (PyObject_GetBuffer(obj.ptr(), &view, PyBUF_SIMPLE) != 0)
        {
            PyErr_Clear();
            throw py::type_error{"expected a bytes-like object"};
        }

        // The buffer must be released however we leave, including if the allocation below throws.
        struct buffer_release
        {
            Py_buffer& v;
            ~buffer_release() { PyBuffer_Release(&v); }
        } release{view};

        const auto* data = static_cast<const std::byte*>(view.buf);
        return {data, data + view.len};
    }

}  // namespace seshquic
