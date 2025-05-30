import pytest
from .securemem import SecureMemory


def test_securemem_write_and_read():
    data = b"supersecretkeymaterial"
    with SecureMemory(len(data)) as smem:
        smem.write(data)
        assert smem.read()[:len(data)] == data


def test_securemem_zero():
    data = b"topsecret"
    with SecureMemory(len(data)) as smem:
        smem.write(data)
        smem.zero()
        assert smem.read() == b"\x00" * len(data)


def test_securemem_type_check():
    with SecureMemory(8) as smem:
        with pytest.raises(TypeError):
            smem.write("notbytes")


def test_securemem_too_large():
    with SecureMemory(4) as smem:
        with pytest.raises(ValueError):
            smem.write(b"12345")


def test_securemem_close_and_double_close():
    data = b"abcde"
    smem = SecureMemory(len(data))
    smem.write(data)
    smem.close()
    # Double close should not error
    smem.close()
    # After close, ptr should be None
    assert smem.ptr is None


def test_securemem_context_manager():
    data = b"context"
    with SecureMemory(len(data)) as smem:
        smem.write(data)
        assert smem.read()[:len(data)] == data
    # After context, ptr should be None
    assert smem.ptr is None
