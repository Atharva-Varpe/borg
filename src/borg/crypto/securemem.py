import ctypes
import os

_libsodium = None

# Try to load libsodium
for libname in ["libsodium.so", "libsodium.dylib", "libsodium.dll"]:
    try:
        _libsodium = ctypes.cdll.LoadLibrary(libname)
        break
    except OSError:
        continue
if _libsodium is None:
    raise ImportError("libsodium not found. Please install libsodium.")

# Initialize sodium
if _libsodium.sodium_init() < 0:
    raise RuntimeError("libsodium initialization failed")

# sodium_malloc and sodium_free
_libsodium.sodium_malloc.restype = ctypes.c_void_p
_libsodium.sodium_malloc.argtypes = [ctypes.c_size_t]
_libsodium.sodium_free.restype = None
_libsodium.sodium_free.argtypes = [ctypes.c_void_p]
_libsodium.sodium_mlock.restype = ctypes.c_int
_libsodium.sodium_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libsodium.sodium_munlock.restype = ctypes.c_int
_libsodium.sodium_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libsodium.sodium_memzero.restype = None
_libsodium.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

class SecureMemory:
    """
    Secure memory buffer using libsodium's sodium_malloc and sodium_free.
    Now supports context manager and explicit close.
    """
    def __init__(self, size):
        self.size = size
        self.ptr = _libsodium.sodium_malloc(size)
        if not self.ptr:
            raise MemoryError("sodium_malloc failed")
        if _libsodium.sodium_mlock(self.ptr, size) != 0:
            _libsodium.sodium_free(self.ptr)
            raise MemoryError("sodium_mlock failed")
        self._as_parameter_ = ctypes.c_void_p(self.ptr)
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if not self._closed and hasattr(self, 'ptr') and self.ptr:
            _libsodium.sodium_memzero(self.ptr, self.size)
            _libsodium.sodium_munlock(self.ptr, self.size)
            _libsodium.sodium_free(self.ptr)
            self.ptr = None
            self._closed = True

    def __del__(self):
        self.close()

    def write(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if len(data) > self.size:
            raise ValueError("data too large for secure buffer")
        ctypes.memmove(self.ptr, data, len(data))
        if len(data) < self.size:
            # Zero the rest
            zero_start = self.ptr + len(data)
            _libsodium.sodium_memzero(zero_start, self.size - len(data))

    def read(self) -> bytes:
        return ctypes.string_at(self.ptr, self.size)

    def zero(self):
        _libsodium.sodium_memzero(self.ptr, self.size)
