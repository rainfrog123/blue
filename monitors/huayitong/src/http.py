"""JSON POST for Huayitong — CFNetwork on iPhone, urllib everywhere else."""
from __future__ import annotations

import importlib.util
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

from config import settings


@dataclass
class HttpResult:
    status: int
    server: str
    body: bytes
    via: str

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.text())


def _load_cf_post():
    path = settings.PROJECT_ROOT / "iphone" / "cf_post.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("huayitong_cf_post", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return getattr(mod, "cf_post", None)


_CF_POST = None
_CF_TRIED = False


def _cf_post():
    global _CF_POST, _CF_TRIED
    if not _CF_TRIED:
        _CF_TRIED = True
        _CF_POST = _load_cf_post()
    return _CF_POST


def _opener() -> urllib.request.OpenerDirector:
    handlers = []
    proxy = settings.API_PROXY
    if proxy:
        handlers.append(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    ctx = ssl._create_unverified_context() if settings.API_PROXY_INSECURE else ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
) -> HttpResult:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    hdrs = dict(headers or {})
    hdrs.setdefault("Content-Type", "application/json")
    hdrs.setdefault("Accept", "*/*")

    cf = _cf_post()
    if cf is not None:
        try:
            status, server, body = cf(url, hdrs, raw, timeout=timeout)
            return HttpResult(status, server or "", body, "cf")
        except Exception as exc:
            print(f"[http] cfnetwork {type(exc).__name__} {exc} → urllib")

    req = urllib.request.Request(url, data=raw, headers=hdrs, method="POST")
    try:
        with _opener().open(req, timeout=timeout) as resp:
            body = resp.read()
            return HttpResult(
                getattr(resp, "status", None) or resp.getcode(),
                resp.headers.get("Server", "") or "",
                body,
                "urllib",
            )
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return HttpResult(exc.code, exc.headers.get("Server", "") if exc.headers else "", body, "urllib")


def post_form(
    url: str,
    fields: Dict[str, Any],
    timeout: float = 10.0,
) -> HttpResult:
    data = urllib.parse.urlencode({k: str(v) for k, v in fields.items()}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with _opener().open(req, timeout=timeout) as resp:
            body = resp.read()
            return HttpResult(
                getattr(resp, "status", None) or resp.getcode(),
                resp.headers.get("Server", "") or "",
                body,
                "urllib",
            )
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return HttpResult(exc.code, exc.headers.get("Server", "") if exc.headers else "", body, "urllib")


def parse_api_json(result: HttpResult, doctor_name: str = "") -> Dict[str, Any]:
    """Raise if the hospital API did not return JSON code=1."""
    label = doctor_name or "api"
    print(
        f"{_stamp()}  {result.status} {result.server or '-'}  "
        f"{len(result.body)}b {result.via}"
    )
    if result.status != 200:
        raise RuntimeError(f"http_{result.status} {label}")
    text = result.text()
    if "aliyun_waf" in text or text.lstrip().startswith("<"):
        print("not json: " + text[:180].replace("\n", " "))
        raise RuntimeError("waf_or_html")
    data = result.json()
    if not data or data.get("code") != "1":
        raise RuntimeError(
            f"api {data.get('code') if isinstance(data, dict) else '?'} "
            f"{(data or {}).get('errCode') if isinstance(data, dict) else ''} "
            f"{(data or {}).get('msg') if isinstance(data, dict) else ''}".strip()
        )
    return data


def _stamp() -> str:
    from datetime import datetime

    return datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
