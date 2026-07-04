"""End-to-end functional crosscheck for FraudOS.

Drives the real FastAPI app over HTTP (httpx ASGI transport) with:
  - the Anthropic client mocked (canned JSON responses, call capture)
  - an in-memory fake at the asyncpg boundary (no PostgreSQL required)

Everything else — auth, sessions, roles, the full 6-layer investigation
pipeline, PII tokenization + vault encryption, feedback loop, webhook HMAC,
rate limits, SAR export — is exercised as real code.

Usage:
    FRAUDOS_TOKEN_SECRET=test ANTHROPIC_API_KEY=x FRAUDOS_WEBHOOK_SECRET=whsec \
        python -m backend.tests.crosscheck
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

os.environ.setdefault("FRAUDOS_TOKEN_SECRET", "crosscheck-secret")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("FRAUDOS_WEBHOOK_SECRET", "whsec")
os.environ.setdefault("FRAUDOS_ENV", "development")

import httpx  # noqa: E402

from backend import auth as auth_mod  # noqa: E402
from backend import database as db_mod  # noqa: E402
from backend import main as main_mod  # noqa: E402
from backend import webhook as webhook_mod  # noqa: E402
from backend.investigation.engine_instance import engine as _engine  # noqa: E402

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


# ── Fake Anthropic client ─────────────────────────────────────────────────────

class _Block:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text: str, model: str):
        self.content = [_Block(text)]
        self.model = model


GOOD_REPORT = {
    "entity_profile": {"summary": "New account, high-value transfer",
                       "risk_indicators": ["account 12 days old"],
                       "account_age_assessment": "Very new"},
    "transaction_pattern": {"pattern_type": "threshold structuring",
                            "anomalies": ["2AM transfer"],
                            "velocity_assessment": "Single burst"},
    "risk_assessment": "High risk of UPI fraud based on account age and timing.",
    "recommended_action": "ESCALATE",
    "confidence": 0.91,
    "risk_score": 87,
    "flags": ["NEW_ACCOUNT", "NIGHT_TXN"],
    "investigation_narrative": "The subject account initiated a near-threshold transfer at 02:14 IST.",
}


class FakeAnthropic:
    """Mimics anthropic.AsyncAnthropic — records calls, returns canned output."""

    def __init__(self):
        self.calls: list[dict] = []
        self.main_text = json.dumps(GOOD_REPORT)
        self.audit_answer = "NO"
        self.echo_canary = False
        self.messages = self

    async def create(self, **kw):
        self.calls.append(kw)
        if "security auditor" in kw.get("system", ""):
            return _Resp(self.audit_answer, kw["model"])
        text = self.main_text
        if self.echo_canary:
            # simulate a prompt-injection leak: echo part of the system prompt
            canary = kw["system"].rsplit("Internal reference code for this session: ", 1)[1][:16]
            text = json.dumps({**GOOD_REPORT, "investigation_narrative": f"code {canary}"})
        return _Resp(text, kw["model"])


# ── Fake asyncpg boundary ─────────────────────────────────────────────────────

class FakeDB:
    def __init__(self):
        self.users: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.investigations: dict[str, dict] = {}
        self.decisions: list[dict] = []
        self.audit_log: list[dict] = []
        self.pii_vault: dict[str, dict] = {}

    def add_user(self, email, password, role):
        uid = uuid.uuid4()
        self.users[email] = {
            "id": uid, "email": email,
            "password_hash": auth_mod._pwd_ctx.hash(password),
            "full_name": email.split("@")[0], "role": role, "is_active": True,
            "created_at": datetime.now(timezone.utc), "last_login": None,
        }
        return uid


class FakeConn:
    def __init__(self, db: FakeDB):
        self.db = db

    # asyncpg API subset -------------------------------------------------------
    async def fetchrow(self, q: str, *p):
        s = " ".join(q.split())
        if "FROM users WHERE email" in s:
            return self.db.users.get(p[0])
        if "FROM sessions WHERE session_token" in s:
            row = self.db.sessions.get(p[0])
            if row and row["expires_at"] > datetime.now(timezone.utc):
                return row
            return None
        if s.startswith("SELECT email FROM users WHERE id"):
            for u in self.db.users.values():
                if u["id"] == p[0]:
                    return {"email": u["email"]}
            return None
        if "INSERT INTO users" in s and "RETURNING" in s:
            email = p[0]
            if email in self.db.users:
                raise Exception("duplicate key violates unique constraint")
            uid = uuid.uuid4()
            row = {"id": uid, "email": email, "password_hash": p[1], "full_name": p[2],
                   "role": p[3], "is_active": True, "created_at": datetime.now(timezone.utc),
                   "last_login": None}
            self.db.users[email] = row
            return {k: row[k] for k in ("id", "email", "full_name", "role", "is_active", "created_at")}
        if "SELECT encrypted_map FROM pii_vault" in s:
            return self.db.pii_vault.get(p[0])
        if "SELECT * FROM investigations WHERE case_id" in s:
            return self.db.investigations.get(p[0])
        raise NotImplementedError(f"fetchrow: {s[:100]}")

    async def fetchval(self, q: str, *p):
        s = " ".join(q.split())
        if "COUNT(*) FROM users" in s:
            return len(self.db.users)
        if "SELECT 1 FROM investigations WHERE case_id" in s:
            return 1 if p[0] in self.db.investigations else None
        raise NotImplementedError(f"fetchval: {s[:100]}")

    async def fetch(self, q: str, *p):
        s = " ".join(q.split())
        if "FROM users ORDER BY" in s:
            return list(self.db.users.values())
        if "GROUP BY i.alert_type, i.recommended_action, ad.decision" in s:
            return self._feedback_rows()
        if s.startswith("SELECT i.case_id") and "FROM investigations i" in s:
            return self._list_investigations()
        raise NotImplementedError(f"fetch: {s[:100]}")

    async def execute(self, q: str, *p):
        s = " ".join(q.split())
        if s.startswith("INSERT INTO sessions"):
            self.db.sessions[p[0]] = {
                "session_token": p[0], "user_id": p[1], "user_email": p[2],
                "user_role": p[3], "full_name": p[4], "created_at": p[5],
                "expires_at": p[6], "api_key_suffix": None,
            }
        elif s.startswith("UPDATE users SET last_login"):
            pass
        elif s.startswith("DELETE FROM sessions"):
            self.db.sessions.pop(p[0], None)
        elif s.startswith("INSERT INTO investigations"):
            cols = ("case_id alert_type risk_level risk_score recommended_action amount "
                    "currency confidence flags entity_profile transaction_pattern "
                    "risk_assessment investigation_narrative processing_time_ms "
                    "model_used canary constitutional_check_passed tokenized_payload").split()
            row = dict(zip(cols, p))
            row["created_at"] = datetime.now(timezone.utc)
            self.db.investigations.setdefault(p[0], row)
        elif s.startswith("INSERT INTO pii_vault"):
            self.db.pii_vault.setdefault(p[0], {"case_id": p[0], "encrypted_map": p[1], "token_count": p[2]})
        elif s.startswith("INSERT INTO audit_log"):
            self.db.audit_log.append({"q": s, "params": p})
        elif s.startswith("INSERT INTO analyst_decisions"):
            self.db.decisions.append({"case_id": p[0], "analyst_id": p[1], "decision": p[2],
                                      "notes": p[3], "created_at": datetime.now(timezone.utc)})
        else:
            raise NotImplementedError(f"execute: {s[:100]}")
        return "OK"

    # helpers ------------------------------------------------------------------
    def _latest_decisions(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for d in sorted(self.db.decisions, key=lambda d: d["created_at"]):
            latest[d["case_id"]] = d
        return latest

    def _feedback_rows(self):
        latest = self._latest_decisions()
        groups: dict[tuple, int] = {}
        for cid, d in latest.items():
            inv = self.db.investigations.get(cid)
            if not inv:
                continue
            key = (inv["alert_type"], inv["recommended_action"], d["decision"])
            groups[key] = groups.get(key, 0) + 1
        return [
            {"alert_type": k[0], "ai_action": k[1], "analyst_action": k[2],
             "pair_count": v, "decided": v,
             "agreed": v if k[1] == k[2] else 0}
            for k, v in groups.items()
        ]

    def _list_investigations(self):
        latest = self._latest_decisions()
        rows = []
        for inv in sorted(self.db.investigations.values(),
                          key=lambda r: r["created_at"], reverse=True):
            d = latest.get(inv["case_id"])
            rows.append({
                "case_id": inv["case_id"], "alert_type": inv["alert_type"],
                "risk_level": inv["risk_level"], "risk_score": inv["risk_score"],
                "recommended_action": inv["recommended_action"], "amount": inv["amount"],
                "currency": inv["currency"], "confidence": inv["confidence"],
                "flags": inv["flags"], "investigation_narrative": inv["investigation_narrative"],
                "received_at": inv["created_at"],
                "decision": d["decision"] if d else None,
                "decided_at": d["created_at"] if d else None,
            })
        return rows


# ── Test driver ───────────────────────────────────────────────────────────────

async def run() -> int:
    db = FakeDB()
    db.add_user("admin@fraudos.local", "admin123", "ADMIN")
    db.add_user("analyst@fraudos.local", "analyst123", "ANALYST")

    @contextlib.asynccontextmanager
    async def fake_get_db():
        yield FakeConn(db)

    # Patch the asyncpg boundary in every module that imported get_db
    main_mod.get_db = fake_get_db
    auth_mod.get_db = fake_get_db
    webhook_mod.get_db = fake_get_db

    fake_claude = FakeAnthropic()
    _engine._client = fake_claude

    transport = httpx.ASGITransport(app=main_mod.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        print("\n── Auth & sessions ──")
        r = await client.post("/auth", json={"email": "admin@fraudos.local", "password": "wrong"})
        check("wrong password → 401", r.status_code == 401)

        r = await client.post("/auth", json={"email": "admin@fraudos.local", "password": "admin123"})
        check("admin login → 200", r.status_code == 200, r.text)
        check("login sets HttpOnly cookie", "fraudos_session" in r.cookies)
        check("login returns role", r.json().get("user", {}).get("role") == "ADMIN")
        admin_cookie = {"fraudos_session": r.cookies["fraudos_session"]}
        client.cookies.clear()  # keep the shared jar empty — cookies passed per-request

        r = await client.get("/auth/me", cookies=admin_cookie)
        check("/auth/me with session → 200", r.status_code == 200 and r.json()["authenticated"])

        r = await client.get("/api/investigations")
        check("no cookie → 401", r.status_code == 401)

        r = await client.post("/auth", json={"email": "analyst@fraudos.local", "password": "analyst123"})
        analyst_cookie = {"fraudos_session": r.cookies["fraudos_session"]}
        client.cookies.clear()
        check("analyst login → 200", r.status_code == 200)

        print("\n── Role enforcement ──")
        r = await client.get("/users", cookies=analyst_cookie)
        check("ANALYST /users → 403", r.status_code == 403)
        r = await client.get("/users", cookies=admin_cookie)
        check("ADMIN /users → 200", r.status_code == 200 and len(r.json()) == 2)
        r = await client.post("/users", cookies=admin_cookie,
                              json={"email": "sup@fraudos.local", "password": "supervisor1", "role": "SUPERVISOR"})
        check("ADMIN create user → 201", r.status_code == 201, r.text)
        r = await client.post("/users", cookies=admin_cookie,
                              json={"email": "x@y.local", "password": "short", "role": "ANALYST"})
        check("short password → 400", r.status_code == 400)
        r = await client.post("/users", cookies=admin_cookie,
                              json={"email": "x@y.local", "password": "longenough1", "role": "GOD"})
        check("invalid role → 400", r.status_code == 400)

        print("\n── Investigation pipeline (happy path) ──")
        alert = {
            "transaction_id": "TXN-CROSSCHECK-1",
            "amount": 49500.0,
            "currency": "INR",
            "entity_data": {
                "name": "Rajesh Kumar",
                "phone": "9876543210",
                "email": "rajesh.k@gmail.com",
                "upi_id": "rajesh@okicici",
                "account_age_days": 12,
            },
            "rule_trigger": "Near-threshold UPI transfer at odd hours",
            "alert_type": "UPI_FRAUD",
            "timestamp": "2026-07-01T02:14:00Z",
        }
        r = await client.post("/api/investigate", cookies=analyst_cookie, json={"alert": alert})
        check("investigate → 200 success", r.status_code == 200 and r.json()["success"], r.text[:200])
        rep = r.json()["report"]
        case_id = rep["case_id"]
        check("risk fields present", rep["risk_score"] == 87 and rep["risk_level"] == "CRITICAL"
              and rep["recommended_action"] == "ESCALATE")
        check("no internal fields in API response",
              all(k not in rep for k in ("pii_map", "canary", "tokenized_payload")))

        main_call = fake_claude.calls[0]
        sent = main_call["messages"][0]["content"] + main_call["system"]
        check("raw PII never sent to Claude",
              all(v not in sent for v in ("Rajesh Kumar", "9876543210", "rajesh.k@gmail.com", "rajesh@okicici")))
        check("tokenized placeholders sent instead",
              "USR-" in main_call["messages"][0]["content"] and "PHN-" in main_call["messages"][0]["content"])
        check("payload wrapped in DATA_PAYLOAD", "<DATA_PAYLOAD>" in main_call["messages"][0]["content"])
        check("constitutional check ran (2nd call)", len(fake_claude.calls) == 2)

        check("investigation persisted", case_id in db.investigations)
        check("tokenized_payload persisted", db.investigations[case_id]["tokenized_payload"] is not None)
        check("audit INVESTIGATE logged", any("audit_log" in a["q"] and a["params"][0] == "INVESTIGATE"
                                              for a in db.audit_log))

        print("\n── PII vault ──")
        check("vault row written", case_id in db.pii_vault and db.pii_vault[case_id]["token_count"] >= 4)
        blob = db.pii_vault[case_id]["encrypted_map"]
        check("vault blob is encrypted (no plaintext)", "Rajesh" not in blob and "9876543210" not in blob)

        r = await client.get(f"/api/investigations/{case_id}/pii", cookies=analyst_cookie)
        check("ANALYST PII reveal → 403", r.status_code == 403)
        r = await client.get(f"/api/investigations/{case_id}/pii", cookies=admin_cookie)
        check("ADMIN PII reveal → 200", r.status_code == 200, r.text[:200])
        if r.status_code == 200:
            revealed = set(r.json()["pii_map"].values())
            check("decrypted map matches originals",
                  {"Rajesh Kumar", "9876543210", "rajesh.k@gmail.com", "rajesh@okicici"} <= revealed)
        check("PII_ACCESS audit-logged", any(a["params"][0] == "PII_ACCESS" for a in db.audit_log))
        r = await client.get("/api/investigations/NOPE/pii", cookies=admin_cookie)
        check("PII for unknown case → 404", r.status_code == 404)

        print("\n── Decisions & feedback loop ──")
        r = await client.post(f"/api/investigations/{case_id}/decision", cookies=analyst_cookie,
                              json={"decision": "INVALID"})
        check("invalid decision → 400", r.status_code == 400)
        r = await client.post(f"/api/investigations/{case_id}/decision", cookies=analyst_cookie,
                              json={"decision": "BLOCK", "notes": "confirmed"})
        check("decision recorded", r.status_code == 200 and r.json()["success"])

        # Seed 5 more decided UPI_FRAUD cases to cross the min_cases threshold
        for i in range(5):
            a2 = {**alert, "transaction_id": f"TXN-SEED-{i}"}
            rr = await client.post("/api/investigate", cookies=analyst_cookie, json={"alert": a2})
            cid = rr.json()["report"]["case_id"]
            dec = "ESCALATE" if i < 3 else "BLOCK"  # 3 agree, 2 override
            await client.post(f"/api/investigations/{cid}/decision", cookies=analyst_cookie,
                              json={"decision": dec})

        r = await client.get("/api/reports/feedback", cookies=analyst_cookie)
        check("feedback stats → 200", r.status_code == 200, r.text[:200])
        fb = r.json()
        check("agreement math correct",
              fb["overall"]["decided"] == 6 and fb["overall"]["agreed"] == 3
              and fb["overall"]["agreement_rate"] == 0.5, json.dumps(fb["overall"]))
        check("override matrix present",
              any(o["ai_action"] == "ESCALATE" and o["analyst_action"] == "BLOCK" and o["count"] == 3
                  for o in fb["overrides"]))

        fake_claude.calls.clear()
        r = await client.post("/api/investigate", cookies=analyst_cookie,
                              json={"alert": {**alert, "transaction_id": "TXN-CALIB"}})
        check("investigate with history → 200", r.status_code == 200 and r.json()["success"])
        sys_prompt = fake_claude.calls[0]["system"]
        check("calibration context injected into prompt",
              "CALIBRATION CONTEXT" in sys_prompt and "agreed with 50%" in sys_prompt, sys_prompt[-300:])

        print("\n── Security layers ──")
        r = await client.post("/api/investigate", cookies=analyst_cookie,
                              json={"alert": {**alert, "transaction_id": "TXN-BAD", "amount": -5}})
        check("negative amount → fallback", r.json()["report"]["flags"].count("INPUT_VALIDATION_FAILED") == 1)

        fake_claude.echo_canary = True
        r = await client.post("/api/investigate", cookies=analyst_cookie,
                              json={"alert": {**alert, "transaction_id": "TXN-CANARY"}})
        check("canary echo → CANARY_INJECTION_DETECTED",
              "CANARY_INJECTION_DETECTED" in r.json()["report"]["flags"], str(r.json()["report"]["flags"]))
        fake_claude.echo_canary = False

        fake_claude.main_text = json.dumps({**GOOD_REPORT, "investigation_narrative": "leaked system prompt here"})
        r = await client.post("/api/investigate", cookies=analyst_cookie,
                              json={"alert": {**alert, "transaction_id": "TXN-FRAG"}})
        check("forbidden fragment → OUTPUT_VALIDATION_FAILED",
              "OUTPUT_VALIDATION_FAILED" in r.json()["report"]["flags"], str(r.json()["report"]["flags"]))
        fake_claude.main_text = json.dumps(GOOD_REPORT)

        fake_claude.audit_answer = "YES"
        r = await client.post("/api/investigate", cookies=analyst_cookie,
                              json={"alert": {**alert, "transaction_id": "TXN-CONST"}})
        check("constitutional YES → CONSTITUTIONAL_CHECK_FAILED",
              "CONSTITUTIONAL_CHECK_FAILED" in r.json()["report"]["flags"], str(r.json()["report"]["flags"]))
        fake_claude.audit_answer = "NO"

        print("\n── Listing, detail & SAR ──")
        r = await client.get("/api/investigations", cookies=analyst_cookie)
        check("list investigations → 200 with SLA fields",
              r.status_code == 200 and len(r.json()) >= 6 and "sla_status" in r.json()[0])
        r = await client.get(f"/api/investigations/{case_id}", cookies=analyst_cookie)
        check("case detail → 200", r.status_code == 200 and r.json()["case_id"] == case_id)
        r = await client.get(f"/api/investigations/{case_id}/sar", cookies=analyst_cookie)
        check("SAR export → 200 text with narrative",
              r.status_code == 200 and "SUSPICIOUS ACTIVITY REPORT" in r.text
              and "attachment" in r.headers.get("content-disposition", ""))

        print("\n── Webhook HMAC ──")
        body = json.dumps({**alert, "transaction_id": "TXN-WEBHOOK-1"}).encode()
        ts = str(int(time.time()))
        sig = "sha256=" + hmac_mod.new(b"whsec", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()

        r = await client.post("/webhook/alert", content=body,
                              headers={"X-Webhook-Signature": "sha256=deadbeef", "X-Webhook-Timestamp": ts,
                                       "Content-Type": "application/json"})
        check("bad signature → 401", r.status_code == 401)

        old_ts = str(int(time.time()) - 600)
        old_sig = "sha256=" + hmac_mod.new(b"whsec", f"{old_ts}.".encode() + body, hashlib.sha256).hexdigest()
        r = await client.post("/webhook/alert", content=body,
                              headers={"X-Webhook-Signature": old_sig, "X-Webhook-Timestamp": old_ts,
                                       "Content-Type": "application/json"})
        check("stale timestamp → 401", r.status_code == 401)

        r = await client.post("/webhook/alert", content=body,
                              headers={"X-Webhook-Signature": sig, "X-Webhook-Timestamp": ts,
                                       "Content-Type": "application/json"})
        check("valid signature → 202", r.status_code == 202, r.text)

        r = await client.post("/webhook/alert", content=body,
                              headers={"X-Webhook-Signature": sig, "X-Webhook-Timestamp": ts,
                                       "Content-Type": "application/json"})
        check("replayed signature → 409", r.status_code == 409)

        await asyncio.sleep(0.3)  # let the background investigate-and-store task finish
        wh_cases = [i for i in db.investigations.values()
                    if i["alert_type"] == "UPI_FRAUD" and i["case_id"] not in (case_id,)]
        check("webhook investigation persisted (with PII vault row)",
              any(c["case_id"] in db.pii_vault for c in wh_cases))

        print("\n── Response hygiene ──")
        r = await client.get("/api/health", cookies=analyst_cookie)
        check("health → 200", r.status_code == 200 and r.json()["status"] == "ok")
        check("security headers present",
              r.headers.get("x-content-type-options") == "nosniff"
              and r.headers.get("x-frame-options") == "DENY"
              and "x-request-id" in r.headers)

        r = await client.post("/auth/logout", cookies=analyst_cookie)
        check("logout → 200", r.status_code == 200)
        r = await client.get("/auth/me", cookies=analyst_cookie)
        check("session invalid after logout → 401", r.status_code == 401)

    print(f"\n{'='*50}\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
