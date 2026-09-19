find_package(Python 3.9 REQUIRED COMPONENTS Interpreter Development.Module)

if(NOT TARGET pybind11::headers)
    find_package(pybind11 2.12 CONFIG QUIET)
endif()
if(NOT TARGET pybind11::headers)
    check_submodule(pybind11)
    add_subdirectory(${PROJECT_SOURCE_DIR}/external/pybind11 ${CMAKE_CURRENT_BINARY_DIR}/pybind11)
endif()

pybind11_add_module(seshquic_core MODULE
    src/module.cpp
    src/common.cpp
    src/address.cpp
    src/btstream.cpp
    src/creds.cpp
    src/datagram.cpp
    src/endpoint.cpp
    src/logging.cpp
    src/stream.cpp
)

set_target_properties(seshquic_core PROPERTIES OUTPUT_NAME _core)

target_link_libraries(seshquic_core PRIVATE quic libquic_internal-warnings)

# scikit-build-core sets this; a plain cmake build drops the module next to the package sources so
# that an in-tree `python -c 'import seshquic'` works with PYTHONPATH=python.
if(DEFINED SKBUILD_PROJECT_NAME)
    install(TARGETS seshquic_core DESTINATION seshquic)
    install(DIRECTORY seshquic/ DESTINATION seshquic FILES_MATCHING PATTERN "*.py" PATTERN "*.pyi")
else()
    set_target_properties(seshquic_core PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/seshquic)
endif()
