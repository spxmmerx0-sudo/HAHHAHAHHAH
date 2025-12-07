import os
import time
import threading
import urllib.parse
import requests
import json
import random
from flask import Flask, jsonify
from instagrapi import Client  # direct_send, direct_thread, etc. [web:1]
from dotenv import load_dotenv

load_dotenv()

# --------- CONFIG (via env) ----------
SESSION_ID_1 = os.getenv("SESSION_ID_1")
SESSION_ID_2 = os.getenv("SESSION_ID_2")
SESSION_ID_3 = os.getenv("SESSION_ID_3")
SESSION_ID_4 = os.getenv("SESSION_ID_4")
SESSION_ID_5 = os.getenv("SESSION_ID_5")

ACC1_GROUP_IDS_RAW = os.getenv("ACC1_GROUP_IDS", "")
ACC2_GROUP_IDS_RAW = os.getenv("ACC2_GROUP_IDS", "")
ACC3_GROUP_IDS_RAW = os.getenv("ACC3_GROUP_IDS", "")
ACC4_GROUP_IDS_RAW = os.getenv("ACC4_GROUP_IDS", "")
ACC5_GROUP_IDS_RAW = os.getenv("ACC5_GROUP_IDS", "")

MESSAGE_TEXT = os.getenv("MESSAGE_TEXT", "Hello 👋")
SELF_URL = os.getenv("SELF_URL", "")

# timings (seconds)
DELAY_BETWEEN_MSGS = int(os.getenv("DELAY_BETWEEN_MSGS", "30"))
TITLE_DELAY_BETWEEN_GCS = int(os.getenv("TITLE_DELAY_BETWEEN_GCS", "200"))
MSG_REFRESH_DELAY = int(os.getenv("MSG_REFRESH_DELAY", "1"))
BURST_COUNT = int(os.getenv("BURST_COUNT", "1"))
SELF_PING_INTERVAL = int(os.getenv("SELF_PING_INTERVAL", "60"))
COOLDOWN_ON_ERROR = int(os.getenv("COOLDOWN_ON_ERROR", "300"))
DOC_ID = os.getenv("DOC_ID", "29088580780787855")
CSRF_TOKEN = os.getenv("CSRF_TOKEN", "")

TITLES_POOL_RAW = os.getenv("TITLES_POOL", "")

app = Flask(__name__)

# --------- PER-SESSION LOG STORAGE ----------
MAX_SESSION_LOGS = 200
session_logs = {
    "acc1": [],
    "acc2": [],
    "acc3": [],
    "acc4": [],
    "acc5": [],
    "system": []
}
logs_lock = threading.Lock()


def _push_log(session, msg):
    if session not in session_logs:
        session = "system"
    with logs_lock:
        session_logs[session].append(msg)
        if len(session_logs[session]) > MAX_SESSION_LOGS:
            session_logs[session].pop(0)


# --------- Logging helper ----------
def log(msg, session="system"):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    _push_log(session, msg)


# --------- Routes ----------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "message": "Bot process alive"})


def summarize(lines):
    rev = list(reversed(lines))
    last_login = next((l for l in rev if "Logged in" in l), None)
    last_send_ok = next((l for l in rev if "✅" in l and "sent to" in l), None)
    last_send_err = next((l for l in rev if "Send failed" in l or "⚠ send failed" in l), None)
    last_title_ok = next((l for l in rev if "changed title" in l and "📝" in l), None)
    last_title_err = next((l for l in rev if "Title change" in l or "GraphQL title" in l), None)
    return {
        "last_login": last_login,
        "last_send_ok": last_send_ok,
        "last_send_error": last_send_err,
        "last_title_ok": last_title_ok,
        "last_title_error": last_title_err,
    }


@app.route("/status")
def status():
    with logs_lock:
        acc1_logs = session_logs["acc1"][-80:]
        acc2_logs = session_logs["acc2"][-80:]
        acc3_logs = session_logs["acc3"][-80:]
        acc4_logs = session_logs["acc4"][-80:]
        acc5_logs = session_logs["acc5"][-80:]
        system_last = session_logs["system"][-5:]

    return jsonify({
        "ok": True,
        "acc1": summarize(acc1_logs),
        "acc2": summarize(acc2_logs),
        "acc3": summarize(acc3_logs),
        "acc4": summarize(acc4_logs),
        "acc5": summarize(acc5_logs),
        "system_last": system_last
    })


# --------- Utility helpers ----------
def decode_session(session):
    if not session:
        return session
    try:
        return urllib.parse.unquote(session)
    except Exception:
        return session


# --------- Instagram helpers ----------
def login_session(session_id, name_hint=""):
    """Log in using sessionid; returns Client or None"""
    session_id = decode_session(session_id)
    try:
        cl = Client()
        cl.login_by_sessionid(session_id)  # session login [web:46]
        uname = getattr(cl, "username", None) or name_hint or "unknown"
        log(f"✅ Logged in {uname}", session=name_hint or "system")
        return cl
    except Exception as e:
        log(f"❌ Login failed ({name_hint}): {e}", session=name_hint or "system")
        return None


def safe_send_message(cl, gid, msg, acc_name):
    """Send message and handle exceptions. Returns True/False."""
    if cl is None:
        log(f"⚠ Client is None for send -> {gid}", session=acc_name)
        return False
    try:
        cl.direct_send(msg, thread_ids=[int(gid)])  # [web:1]
        log(f"✅ {getattr(cl,'username','?')} sent to {gid}", session=acc_name)
        return True
    except Exception as e:
        log(f"⚠ Send failed ({getattr(cl,'username','?')}) -> {gid}: {e}", session=acc_name)
        return False


def safe_change_title_direct(cl, gid, new_title, acc_name):
    """
    Change title:
    1) Try instagrapi DirectThread.update_title.
    2) If that fails, try GraphQL fallback.
    """
    if cl is None:
        log(f"⚠ Client is None for title change -> {gid}", session=acc_name)
        return False

    # step 1: high-level direct thread
    try:
        tt = cl.direct_thread(int(gid))  # [web:1][web:59]
        try:
            tt.update_title(new_title)
            log(
                f"📝 {getattr(cl,'username','?')} changed title (direct) for {gid} -> {new_title}",
                session=acc_name
            )
            return True
        except Exception:
            log(
                f"⚠ direct .update_title() failed for {gid} — will attempt GraphQL fallback",
                session=acc_name
            )
    except Exception:
        pass

    # step 2: GraphQL fallback if CSRF_TOKEN provided
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "X-CSRFToken": CSRF_TOKEN,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"https://www.instagram.com/direct/t/{gid}/",
        }
        cookies = {"csrftoken": CSRF_TOKEN}
        try:
            cl.private.headers.update(headers)
            cl.private.cookies.update(cookies)
            variables = {"thread_fbid": gid, "new_title": new_title}
            payload = {"doc_id": DOC_ID, "variables": json.dumps(variables)}
            resp = cl.private.post("https://www.instagram.com/api/graphql/", data=payload, timeout=10)
            try:
                result = resp.json()
                if "errors" in result:
                    log(
                        f"❌ GraphQL title change errors for {gid}: {result['errors']}",
                        session=acc_name
                    )
                    return False
                log(
                    f"📝 {getattr(cl,'username','?')} changed title (graphql) for {gid} -> {new_title}",
                    session=acc_name
                )
                return True
            except Exception as e:
                log(
                    f"⚠ Title change unexpected response for {gid}: {e} (status {resp.status_code})",
                    session=acc_name
                )
                return False
        except Exception as e:
            log(f"⚠ Exception performing GraphQL title change for {gid}: {e}", session=acc_name)
            return False
    except Exception as e:
        log(f"⚠ Unexpected fallback error for title change {gid}: {e}", session=acc_name)
        return False


# --------- Loops ----------
def spam_loop_single_account(cl, groups, acc_name):
    """
    For this account only:
    - cycle its own groups list in order with delays and BURST_COUNT.
    """
    if not groups:
        log("⚠ No groups for messaging loop.", session=acc_name)
        return

    while True:
        try:
            for gid in groups:
                for _ in range(BURST_COUNT):
                    ok = safe_send_message(cl, gid, MESSAGE_TEXT, acc_name)
                    if not ok:
                        log(
                            f"⚠ send failed by {getattr(cl,'username','?')}, cooling down {COOLDOWN_ON_ERROR}s",
                            session=acc_name
                        )
                        time.sleep(COOLDOWN_ON_ERROR)
                    time.sleep(MSG_REFRESH_DELAY)
                time.sleep(DELAY_BETWEEN_MSGS)
        except Exception as e:
            log(f"❌ Exception in {acc_name} spam loop: {e}", session=acc_name)


def title_loop_single_account(cl, groups, titles_map, acc_name):
    """
    For this account only:
    - rotate titles per GC using titles_map[gid] list.
    """
    if not groups:
        log("⚠ No groups for title loop.", session=acc_name)
        return

    name_idx = {str(g): 0 for g in groups}

    while True:
        try:
            for gid in groups:
                key = str(gid)
                titles = titles_map.get(key) or [MESSAGE_TEXT[:40]]
                if not titles:
                    titles = [MESSAGE_TEXT[:40]]

                idx = name_idx.get(key, 0) % len(titles)
                new_title = titles[idx]
                name_idx[key] = (idx + 1) % len(titles)

                ok = safe_change_title_direct(cl, gid, new_title, acc_name)
                if not ok:
                    log(
                        f"⚠ Title change failed for {gid} by {getattr(cl,'username','?')}, cooldown {COOLDOWN_ON_ERROR}s",
                        session=acc_name
                    )
                    time.sleep(COOLDOWN_ON_ERROR)

                time.sleep(TITLE_DELAY_BETWEEN_GCS)
        except Exception as e:
            log(f"❌ Exception in {acc_name} title loop: {e}", session=acc_name)


def self_ping_loop():
    while True:
        if SELF_URL:
            try:
                requests.get(SELF_URL, timeout=10)
                log("🔁 Self ping successful", session="system")
            except Exception as e:
                log(f"⚠ Self ping failed: {e}", session="system")
        time.sleep(SELF_PING_INTERVAL)


# --------- Start bot ----------
def parse_group_ids(raw: str):
    return [g.strip() for g in raw.split(",") if g.strip()]


def start_bot():
    log(
        f"STARTUP: SESSION_ID_1={repr(SESSION_ID_1)}, SESSION_ID_2={repr(SESSION_ID_2)}, "
        f"SESSION_ID_3={repr(SESSION_ID_3)}, SESSION_ID_4={repr(SESSION_ID_4)}, SESSION_ID_5={repr(SESSION_ID_5)}, "
        f"MESSAGE_TEXT={repr(MESSAGE_TEXT)}",
        session="system"
    )

    # per-account groups
    acc_groups = {
        "acc1": parse_group_ids(ACC1_GROUP_IDS_RAW),
        "acc2": parse_group_ids(ACC2_GROUP_IDS_RAW),
        "acc3": parse_group_ids(ACC3_GROUP_IDS_RAW),
        "acc4": parse_group_ids(ACC4_GROUP_IDS_RAW),
        "acc5": parse_group_ids(ACC5_GROUP_IDS_RAW),
    }

    # build titles_map per GC using TITLES_POOL, randomized order per GC
    titles_map = {}

    base_titles = []
    if TITLES_POOL_RAW:
        try:
            base_titles = json.loads(TITLES_POOL_RAW)
        except Exception as e:
            log(f"⚠ TITLES_POOL JSON parse error: {e}. Using fallback 1-title list.", session="system")

    if not base_titles:
        base_titles = [MESSAGE_TEXT[:40]]

    # collect all GCs from all accounts
    all_group_ids = set()
    for g_list in acc_groups.values():
        all_group_ids.update(g_list)

    for gid in all_group_ids:
        titles_copy = list(base_titles)
        random.shuffle(titles_copy)
        titles_map[str(gid)] = titles_copy

    # login accounts
    sessions = {
        "acc1": SESSION_ID_1,
        "acc2": SESSION_ID_2,
        "acc3": SESSION_ID_3,
        "acc4": SESSION_ID_4,
        "acc5": SESSION_ID_5,
    }

    clients = {}

    for acc_name, sess in sessions.items():
        if not sess:
            continue
        log(f"🔐 Logging in {acc_name}...", session="system")
        cl = login_session(sess, acc_name)
        if not cl:
            log(f"⚠ {acc_name} login failed — continuing without {acc_name}", session="system")
        else:
            clients[acc_name] = cl

    if not clients:
        log("❌ No accounts logged in; aborting start", session="system")
        return

    # start loops per logged-in account
    for acc_name, cl in clients.items():
        groups = acc_groups.get(acc_name, [])
        if not groups:
            log(f"⚠ {acc_name} has no GROUP_IDS; skipping loops", session="system")
            continue

        try:
            t_msg = threading.Thread(
                target=spam_loop_single_account,
                args=(cl, groups, acc_name),
                daemon=True
            )
            t_msg.start()
            log(f"▶ Started spam loop for {acc_name}", session="system")

            t_title = threading.Thread(
                target=title_loop_single_account,
                args=(cl, groups, titles_map, acc_name),
                daemon=True
            )
            t_title.start()
            log(f"▶ Started title loop for {acc_name}", session="system")
        except Exception as e:
            log(f"❌ Failed to start threads for {acc_name}: {e}", session="system")

    # self-ping
    try:
        t3 = threading.Thread(target=self_ping_loop, daemon=True)
        t3.start()
    except Exception as e:
        log(f"⚠ Failed to start self-ping thread: {e}", session="system")


# -------------------------------------------------
def run_bot_once():
    try:
        threading.Thread(target=start_bot, daemon=True).start()
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ❌ Failed to start bot (import-time): {e}", flush=True)


run_bot_once()
# -------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    log(f"HTTP server starting on port {port}", session="system")
    try:
        app.run(host="0.0.0.0", port=port)
    except Exception as e:
        log(f"❌ Flask run failed: {e}", session="system")
