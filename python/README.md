# seshquic

Python bindings for libquic.

```python
import seshquic as quic

with quic.Endpoint("127.0.0.1:0") as client:
    conn = client.connect("example.com:4242", remote_pubkey=pk, creds=creds)
    stream = conn.open_stream()
    stream.send(b"hello")
    stream.send_fin()
    print(stream.read_all())
```

## asyncio

Optional, and a separate import — `import seshquic` does not pull it in, and a program that never
uses it needs no event loop:

```python
import seshquic.aio as quic

async def main():
    async with quic.Endpoint("127.0.0.1:0") as client:
        conn = await client.connect("example.com:4242", remote_pubkey=pk, creds=creds)
        bts = conn.open_bt_stream()
        print(await bts.request("ping"))
```

Only what genuinely waits is a coroutine: connecting, closing, reading a stream, and a bt-request.
See `seshquic/aio.py` for which callbacks run on the asyncio loop and which run on libquic's own
thread, and why.

## Building

From this directory, into your user site-packages (add `--break-system-packages` on a distro that
marks its Python externally managed):

    pip install --user .

That installs a copy, so a change to the C++ needs another `pip install`.  For development an
in-tree CMake build avoids that: it puts the extension module next to the package sources, so the
source tree is directly importable and only the rebuild is needed.

    cd ..
    cmake -B build-py -DLIBQUIC_BUILD_PYTHON=ON -DLIBQUIC_BUILD_TESTS=OFF
    make -C build-py seshquic_core
    PYTHONPATH=python python3 -c 'import seshquic; print(seshquic.__version__)'

`pip install -e .` is not worth reaching for here: scikit-build-core's editable mode copies the
Python sources into site-packages and points its import hook at the copies, so neither Python nor
C++ edits are live without further configuration.

The CMake project is the libquic tree above this directory; `pyproject.toml` points at it with
`cmake.source-dir`, and the extension is the `seshquic_core` target in `CMakeLists.txt` here.

## Tests

    PYTHONPATH=../python python3 -m pytest

`python3-cryptography` is needed to generate the Ed25519 test keys.

## Formatting

`../utils/format.sh` formats the C++ with clang-format and the Python with black; the black
settings live in `pyproject.toml`.  `../utils/format.sh verify` checks without writing.

## Debugging

`seshquic.enable_logging("stderr", "debug")` turns on libquic's internal logging.  Levels go up to
`"trace"`, which records every packet.
