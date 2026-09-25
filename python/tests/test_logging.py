import pytest

import seshquic as quic


def test_enable_logging_to_file(tmp_path):
    logfile = tmp_path / "quic.log"
    quic.enable_logging(str(logfile), "debug")

    with quic.Endpoint("127.0.0.1:0"):
        pass

    quic.flush_logs()

    assert logfile.exists()
    # Not matching on any particular message: what matters is that debug-level output from
    # libquic's own category reached the file we named.
    assert "quic:debug" in logfile.read_text()


def test_enable_logging_rejects_a_bad_level():
    with pytest.raises(Exception):
        quic.enable_logging("stderr", "not-a-level")
