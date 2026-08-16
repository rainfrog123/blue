"""Minimal WeCom Receive-Messages URL verifier (GET VerifyURL only)."""
from __future__ import annotations

import os
from urllib.parse import unquote

from flask import Flask, request

from WXBizMsgCrypt import WXBizMsgCrypt

app = Flask(__name__)


def _env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise RuntimeError(f"missing env {name}")
    return val


def _crypt() -> WXBizMsgCrypt:
    return WXBizMsgCrypt(
        _env("WECOM_TOKEN"),
        _env("WECOM_AES_KEY"),
        _env("WECOM_CORP_ID"),
    )


@app.get("/healthz")
def healthz():
    return "ok", 200


@app.get("/")
@app.get("/wecom/callback")
def verify():
    """WeCom Save sends GET with msg_signature, timestamp, nonce, echostr."""
    try:
        msg_signature = request.args.get("msg_signature", "")
        timestamp = request.args.get("timestamp", "")
        nonce = request.args.get("nonce", "")
        echostr = request.args.get("echostr", "")
        # Flask already url-decodes; keep explicit unquote for safety if double-encoded
        if echostr and "%" in echostr:
            echostr = unquote(echostr)

        if not all([msg_signature, timestamp, nonce, echostr]):
            return "missing query params (need msg_signature timestamp nonce echostr)", 400

        ret, plain = _crypt().VerifyURL(msg_signature, timestamp, nonce, echostr)
        if ret != 0 or plain is None:
            return f"verify failed ret={ret}", 403

        # Must be raw plaintext only — no JSON, quotes, BOM, or trailing newline.
        if isinstance(plain, bytes):
            plain = plain.decode("utf-8")
        return plain, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except RuntimeError as exc:
        return str(exc), 500


@app.post("/")
@app.post("/wecom/callback")
def ignore_post():
    """Inbound messages not needed to unlock Trusted IP; acknowledge."""
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
