#!/usr/bin/env python3
"""Stdlib-only 华医通 poller for the jailbroken iPhone (no requests)."""
from __future__ import annotations

import json
import random
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

CST = timezone(timedelta(hours=8))


def now_cst() -> str:
    return datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S CST")

HERE = Path(__file__).resolve().parent
CFG = json.loads((HERE / "phone_config.json").read_text(encoding="utf-8"))
STATE_PATH = HERE / "state.json"
URL = CFG["url"]
CTX = ssl._create_unverified_context()
TAIL = deque(maxlen=int(CFG.get("tail_lines", 5)))
LAST = {
    "ticks": deque(maxlen=int(CFG.get("tail_lines", 5))),
    "slots": [],
    "http": "",
    "err": "",
}


def log(msg: str) -> None:
    print(msg)
    TAIL.append(msg)


def _date_cn(raw: object) -> str:
    s = str(raw or "")
    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        return f"{int(s[5:7])}月{int(s[8:10])}日"
    return s


def _short_dept(dept: object) -> str:
    s = str(dept or "")
    if "特需" in s:
        return "特需"
    return s.split("/")[-1] or s


def format_heartbeat() -> str:
    doctor = (CFG["doctor"]["name"] or "").split()[0] or "华医通"
    hhmm = datetime.now(CST).strftime("%H:%M")
    ok = not LAST["err"] and str(LAST["http"]).startswith("200")
    flag = "正常" if ok else (LAST["err"] or LAST["http"] or "无数据")
    lines = [
        "【心跳】华医通",
        f"【医生】{doctor}",
        f"【时间】{hhmm} · {flag}",
        "────────────",
    ]
    for s in LAST["slots"]:
        lines.append(f"{_date_cn(s.get('date'))} {_short_dept(s.get('dept'))}")
        lines.append(f"　【剩余】{s['remain']}　【费用】¥{s['fee']:g}")
    if LAST["ticks"]:
        lines.append("────────────")
        lines.append(" ".join(LAST["ticks"]))
    elif LAST["err"]:
        lines.append(LAST["err"])
    return "\n".join(lines)


def load_state() -> dict:
    if STATE_PATH.is_file():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {"warm": False, "prev": {}}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def bookable(status: int, avail: int, remain: int) -> bool:
    return status == 1 and (avail > 0 or remain > 0)


def _headers() -> dict:
    return {
        "Mac": "Not Found",
        "Accept": "*/*",
        "Client-Version": "7.1.1",
        "Accept-Language": "en-GB;q=1",
        "Content-Type": "application/json",
        "User-Agent": "hua yi tong/7.1.1 (iPhone; iOS 15.7.1; Scale/3.00)",
        "token": CFG["token"],
        "accessToken": CFG["accessToken"],
        "Cookie": CFG["cookie"],
        "UUID": CFG.get("uuid") or "25FEFB37-9D3D-4FA1-B7E8-81F7FB0A2FAD",
    }


def _parse_body(status: int, server: str, raw: bytes, via: str) -> dict:
    LAST["http"] = f"{status} {via}"
    log(f"{now_cst()}  {status} {server}  {len(raw)}b {via}")
    text = raw.decode("utf-8", "replace")
    if "aliyun_waf" in text or text.lstrip().startswith("<"):
        log("not json: " + text[:180].replace("\n", " "))
        raise RuntimeError("waf_or_html")
    return json.loads(text)


def post(payload: dict) -> dict:
    body = dict(payload)
    body["timestamp"] = str(int(time.time()))
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = _headers()
    try:
        from cf_post import cf_post

        status, server, raw = cf_post(URL, headers, data)
        return _parse_body(status, server, raw, "cf")
    except Exception as exc:
        log(f"{now_cst()} cfnetwork {type(exc).__name__} {exc} → urllib")
    req = urllib.request.Request(URL, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, context=CTX, timeout=30) as resp:
        raw = resp.read()
        return _parse_body(
            resp.status,
            resp.headers.get("Server", ""),
            raw,
            "urllib",
        )


def extract(data: dict) -> list:
    if not data or data.get("code") != "1":
        log(f"api {data.get('code')} {data.get('errCode')} {data.get('msg')}")
        return []
    seen = set()
    out = []
    blob = data.get("data") or {}
    items = list(blob.get("sourceItemsRespVos") or [])
    for area in blob.get("sourceItems") or []:
        items.extend((area or {}).get("sourceItemsRespVos") or [])
    for item in items:
        sid = str(item.get("sysScheduleId") or "")
        if not sid or sid in seen:
            continue
        seen.add(sid)
        rng = int(item.get("scheduleRange") or 0)
        out.append(
            {
                "id": sid,
                "date": item.get("scheduleDate"),
                "dept": item.get("deptName"),
                "area": item.get("hospitalAreaName") or "",
                "loc": item.get("admLocation") or "",
                "period": {0: "上午", 1: "下午"}.get(rng, f"段{rng}"),
                "status": int(item.get("status") or 0),
                "avail": int(item.get("availableCount") or 0),
                "remain": int(item.get("remainingNum") or 0),
                "fee": float(item.get("regFee") or 0) + float(item.get("serviceFee") or 0),
            }
        )
    return out


def wecom_live_url() -> str:
    return (CFG.get("wecom_live") or CFG.get("wecom") or "").strip()


def wecom_test_url() -> str:
    return (CFG.get("wecom_test") or "").strip()


def telegram_creds() -> tuple[str, str]:
    token = (CFG.get("telegram_bot_token") or CFG.get("telegram_token") or "").strip()
    chat = str(CFG.get("telegram_chat_id") or CFG.get("telegram_chat") or "").strip()
    return token, chat


def telegram_send(content: str, wait: bool = False) -> None:
    token, chat = telegram_creds()
    if not token or not chat:
        print("telegram missing")
        return
    t = threading.Thread(target=_telegram_send, args=(token, chat, content), daemon=True)
    t.start()
    if wait:
        t.join(20)


def _telegram_send(token: str, chat: str, content: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps(
        {"chat_id": chat, "text": content},
        ensure_ascii=False,
    ).encode("utf-8")
    try:
        from cf_post import cf_post

        status, server, raw = cf_post(
            url, {"Content-Type": "application/json"}, payload, timeout=8.0
        )
        print("telegram", status, server, raw[:80])
        return
    except Exception as exc:
        print("telegram cf", type(exc).__name__, exc, "-> urllib")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=8) as resp:
            print("telegram", resp.read()[:80])
    except Exception as exc:
        print("telegram err", exc)


def wecom_post(url: str, content: str, tag: str) -> None:
    if not url:
        print(tag, "missing")
        return
    payload = json.dumps(
        {"msgtype": "text", "text": {"content": content}},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=10) as resp:
            print(tag, resp.read()[:80])
    except Exception as exc:
        print(tag, "err", exc)


def _arrow(old, new) -> str:
    return f"{old}→{new}" if old != new else str(new)


def notify(changes: list, doctor: str) -> None:
    """Seat / status edges → live webhook only."""
    if not changes:
        return
    any_open = any(bookable(c["status"], c["avail"], c["remain"]) for c in changes)
    title = "【有号】华西医院" if any_open else "【号变】华西医院"
    lines = [title, f"【共{len(changes)}个】{doctor}", "────────────"]
    for c in changes:
        prev = c.get("from") or {}
        remain = _arrow(prev["remain"], c["remain"]) if "remain" in prev else str(c["remain"])
        avail = _arrow(prev["avail"], c["avail"]) if "avail" in prev else str(c["avail"])
        st = _arrow(prev["status"], c["status"]) if "status" in prev else str(c["status"])
        lines.append(
            f"{c['date']} {c.get('period','')} {c['dept']} "
            f"余{remain} avail{avail} status{st} ¥{c['fee']:g}"
        )
        extra = " ".join(x for x in (c.get("area"), c.get("loc")) if x)
        if extra:
            lines.append(f"　{extra}")
    text = "\n".join(lines)
    wecom_post(wecom_live_url(), text, "wecom_live")
    # telegram_send(text)


def test_wecom() -> None:
    try:
        poll_once()
    except Exception as exc:
        LAST["err"] = f"{type(exc).__name__} {exc}"
        log(f"{now_cst()} err {type(exc).__name__} {exc}")
    wecom_post(wecom_test_url() or wecom_live_url(), format_heartbeat(), "wecom_personal")


def test_telegram() -> None:
    telegram_send(f"【测试】华西 iPhone poller\n【时间】{now_cst()}", wait=True)


def poll_once() -> None:
    doctor = CFG["doctor"]["name"]
    raw = post(CFG["doctor"]["payload"])
    slots = extract(raw)
    state = load_state()
    prev = state.setdefault("prev", {})
    changes = []
    for s in slots:
        key = f"{doctor}:{s['id']}"
        old = prev.get(key)
        prev[key] = [s["status"], s["avail"], s["remain"]]
        now_ok = bookable(s["status"], s["avail"], s["remain"])
        log(
            f"  {s['date']} {s['dept']} status={s['status']} "
            f"avail={s['avail']} remain={s['remain']} ¥{s['fee']:g}"
        )
        if old is None:
            if now_ok and state.get("warm"):
                changes.append(s)
            continue
        if old[0] != s["status"] or old[1] != s["avail"] or old[2] != s["remain"]:
            row = dict(s)
            row["from"] = {"status": old[0], "avail": old[1], "remain": old[2]}
            changes.append(row)
    LAST["slots"] = slots
    LAST["err"] = ""
    LAST["ticks"].append(datetime.now(CST).strftime("%H:%M"))
    if slots:
        state["warm"] = True
    save_state(state)
    if changes:
        log(f"NEW {len(changes)}")
        notify(changes, doctor)
    elif not slots:
        log("no slots")


def main() -> None:
    once = False
    import sys

    if "--test-wecom" in sys.argv:
        test_wecom()
        return
    if "--test-telegram" in sys.argv:
        test_telegram()
        return
    if "--once" in sys.argv:
        once = True
    lo = float(CFG.get("interval_min", 10))
    hi = float(CFG.get("interval_max", 15))
    if hi < lo:
        lo, hi = hi, lo
    tail_sec = float(CFG.get("wecom_tail_sec", 3600))
    print("huayitong phone poller", CFG["doctor"]["name"], f"every {lo:g}-{hi:g}s random")
    print(
        "wecom live set:",
        bool(wecom_live_url()),
        "personal set:",
        bool(wecom_test_url()),
        f"tail -{TAIL.maxlen} every {tail_sec:g}s",
    )
    last_tail = time.monotonic()
    while True:
        try:
            poll_once()
        except Exception as exc:
            LAST["err"] = f"{type(exc).__name__} {exc}"
            LAST["ticks"].append(datetime.now(CST).strftime("%H:%M"))
            log(f"{now_cst()} err {type(exc).__name__} {exc}")
        if once:
            return
        if LAST["ticks"] and time.monotonic() - last_tail >= tail_sec:
            last_tail = time.monotonic()
            wecom_post(wecom_test_url(), format_heartbeat(), "wecom_personal")
        time.sleep(random.uniform(lo, hi))


if __name__ == "__main__":
    main()
