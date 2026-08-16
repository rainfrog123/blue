"""POST via NSURLConnection (CFNetwork / SecureTransport), not OpenSSL."""
from __future__ import annotations

import ctypes
from ctypes import POINTER, c_char_p, c_double, c_void_p, c_ulong

_objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
_objc.objc_getClass.restype = c_void_p
_objc.objc_getClass.argtypes = [c_char_p]
_objc.sel_registerName.restype = c_void_p
_objc.sel_registerName.argtypes = [c_char_p]
_send = _objc.objc_msgSend

try:
    ctypes.CDLL("/System/Library/Frameworks/Foundation.framework/Foundation")
except OSError:
    ctypes.CDLL(
        "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"
    )


def _cls(name: str) -> int:
    return _objc.objc_getClass(name.encode())


def _sel(name: str) -> int:
    return _objc.sel_registerName(name.encode())


def _msg(obj, selector: str, *args, restype=c_void_p, argtypes=None):
    if obj is None or obj == 0:
        return None
    types = [c_void_p, c_void_p]
    if argtypes is None:
        types.extend([c_void_p] * len(args))
    else:
        types.extend(argtypes)
    _send.restype = restype
    _send.argtypes = types
    return _send(obj, _sel(selector), *args)


def _nsstr(text: str) -> int:
    return _msg(
        _cls("NSString"),
        "stringWithUTF8String:",
        text.encode(),
        argtypes=[c_char_p],
    )


def _nsdata(raw: bytes) -> int:
    return _msg(
        _cls("NSData"),
        "dataWithBytes:length:",
        raw,
        len(raw),
        argtypes=[c_char_p, c_ulong],
    )


def cf_post(url: str, headers: dict, body: bytes, timeout: float = 30.0) -> tuple[int, str, bytes]:
    """Return (status, server, body). Raises OSError on transport failure."""
    ns_url = _msg(_cls("NSURL"), "URLWithString:", _nsstr(url))
    req = _msg(_cls("NSMutableURLRequest"), "requestWithURL:", ns_url)
    _msg(req, "setHTTPMethod:", _nsstr("POST"), restype=None)
    _msg(req, "setHTTPBody:", _nsdata(body), restype=None)
    _msg(
        req,
        "setTimeoutInterval:",
        float(timeout),
        restype=None,
        argtypes=[c_double],
    )
    for key, value in headers.items():
        if value is None:
            continue
        _msg(
            req,
            "setValue:forHTTPHeaderField:",
            _nsstr(str(value)),
            _nsstr(str(key)),
            restype=None,
        )

    resp = c_void_p()
    err = c_void_p()
    data = _msg(
        _cls("NSURLConnection"),
        "sendSynchronousRequest:returningResponse:error:",
        req,
        ctypes.byref(resp),
        ctypes.byref(err),
        argtypes=[c_void_p, POINTER(c_void_p), POINTER(c_void_p)],
    )
    if not data:
        desc = "cfnetwork failed"
        if err.value:
            ns = _msg(err.value, "localizedDescription")
            raw = _msg(ns, "UTF8String", restype=c_char_p)
            if raw:
                desc = raw.decode("utf-8", "replace")
        raise OSError(desc)

    status = int(
        _msg(resp.value, "statusCode", restype=c_ulong) or 0
    ) if resp.value else 0
    server = ""
    if resp.value:
        ns = _msg(resp.value, "allHeaderFields")
        val = _msg(ns, "objectForKey:", _nsstr("Server")) if ns else None
        if val:
            raw = _msg(val, "UTF8String", restype=c_char_p)
            if raw:
                server = raw.decode("utf-8", "replace")

    length = int(_msg(data, "length", restype=c_ulong) or 0)
    ptr = _msg(data, "bytes")
    blob = ctypes.string_at(ptr, length) if ptr and length else b""
    return status, server, blob
