"""Atomic, Windows-user protected local storage shared by both processes."""
import ctypes
import json
import os
import threading
from pathlib import Path

DATA = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'ExposureConsole' / 'control'
DATA.mkdir(parents=True, exist_ok=True)
LOCK = threading.RLock()


class Blob(ctypes.Structure):
    _fields_ = [('size', ctypes.c_ulong), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def crypt(data, decrypt=False):
    if os.name != 'nt':
        raise ValueError('凭据存储需要 Windows DPAPI。')
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    fn = ctypes.windll.crypt32.CryptUnprotectData if decrypt else ctypes.windll.crypt32.CryptProtectData
    if not fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ValueError('无法使用当前 Windows 用户解密或保存凭据。')
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        ctypes.windll.kernel32.LocalFree(target.data)


def read(path, default=None):
    with LOCK:
        if not Path(path).exists():
            return default
        return json.loads(crypt(Path(path).read_bytes(), True).decode('utf-8'))


def write(path, value):
    with LOCK:
        path = Path(path)
        temp = path.with_suffix('.new')
        temp.write_bytes(crypt(json.dumps(value, ensure_ascii=False).encode('utf-8')))
        temp.replace(path)
