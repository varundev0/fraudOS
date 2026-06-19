"""Push notifications for FraudOS — Slack and email.

Environment variables:
  FRAUDOS_SLACK_WEBHOOK_URL   — Slack incoming-webhook URL; leave blank to disable
  FRAUDOS_ALERT_EMAIL_TO      — comma-separated recipient addresses; leave blank to disable
  FRAUDOS_SMTP_HOST           — SMTP server hostname
  FRAUDOS_SMTP_PORT           — SMTP port (default 587)
  FRAUDOS_SMTP_USER           — SMTP login username
  FRAUDOS_SMTP_PASSWORD       — SMTP login password
  FRAUDOS_SMTP_FROM           — From address (defaults to SMTP user)

All notification paths are best-effort and non-fatal — errors are logged but
never propagate to the caller.
"""

from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from email.message import EmailMessage

import httpx

_logger = logging.getLogger(__name__)


# ── Slack ─────────────────────────────────────────────────────────────────────

async def _post_slack(webhook_url: str, fallback_text: str, blocks: list) -> None:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(webhook_url, json={"text": fallback_text, "blocks": blocks})
            if resp.status_code != 200:
                _logger.warning("Slack notification failed: %s — %s", resp.status_code, resp.text[:200])
    except Exception:
        _logger.exception("Slack notification request failed")


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_email_sync(to: list[str], subject: str, body: str) -> None:
    host = os.getenv("FRAUDOS_SMTP_HOST", "").strip()
    port = int(os.getenv("FRAUDOS_SMTP_PORT", "587"))
    user = os.getenv("FRAUDOS_SMTP_USER", "").strip()
    password = os.getenv("FRAUDOS_SMTP_PASSWORD", "").strip()
    from_addr = os.getenv("FRAUDOS_SMTP_FROM", user).strip() or user

    if not host or not user:
        return  # SMTP not configured

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(user, password)
            server.send_message(msg)
    except Exception:
        _logger.exception("Email notification failed to %s", to)


# ── Public API ────────────────────────────────────────────────────────────────

async def notify_critical_case(
    *,
    case_id: str,
    alert_type: str,
    risk_level: str,
    risk_score: int,
    action: str,
    amount: float,
    currency: str = "INR",
    trigger: str = "CASE_CREATED",
) -> None:
    """Fire Slack + email alert for a critical/block-level case.

    Non-fatal — swallows all exceptions after logging.
    Trigger can be CASE_CREATED or SLA_OVERDUE.
    """
    slack_url = os.getenv("FRAUDOS_SLACK_WEBHOOK_URL", "").strip()
    email_to_raw = os.getenv("FRAUDOS_ALERT_EMAIL_TO", "").strip()
    email_to = [e.strip() for e in email_to_raw.split(",") if e.strip()]

    if not slack_url and not email_to:
        return  # nothing configured — skip silently

    is_sla = trigger == "SLA_OVERDUE"
    emoji = "🚨" if risk_level == "CRITICAL" else "⚠️"
    trigger_label = "SLA OVERDUE" if is_sla else f"{risk_level} · {action}"
    title = f"{emoji} FraudOS Alert — {trigger_label}"

    # Format amount
    if currency == "INR":
        if amount >= 1e7:
            fmt_amount = f"₹{amount / 1e7:.1f}Cr {currency}"
        elif amount >= 1e5:
            fmt_amount = f"₹{amount / 1e5:.1f}L {currency}"
        else:
            fmt_amount = f"₹{amount:,.0f} {currency}"
    else:
        fmt_amount = f"{amount:,.0f} {currency}"

    plain_body = (
        f"FraudOS Alert\n"
        f"{'─' * 40}\n"
        f"Trigger  : {trigger_label}\n"
        f"Case ID  : {case_id}\n"
        f"Alert    : {alert_type}\n"
        f"Risk     : {risk_level} (score {risk_score}/100)\n"
        f"Action   : {action}\n"
        f"Amount   : {fmt_amount}\n"
    )

    tasks = []

    if slack_url:
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": title, "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Case ID*\n`{case_id}`"},
                    {"type": "mrkdwn", "text": f"*Alert Type*\n{alert_type}"},
                    {"type": "mrkdwn", "text": f"*Risk Level*\n{risk_level} ({risk_score}/100)"},
                    {"type": "mrkdwn", "text": f"*Recommended Action*\n{action}"},
                    {"type": "mrkdwn", "text": f"*Amount*\n{fmt_amount}"},
                    {"type": "mrkdwn", "text": f"*Trigger*\n{trigger_label}"},
                ],
            },
        ]
        tasks.append(_post_slack(slack_url, title, blocks))

    if email_to:
        loop = asyncio.get_running_loop()
        tasks.append(loop.run_in_executor(None, _send_email_sync, email_to, title, plain_body))

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception:
        _logger.exception("Notification dispatch error for case %s", case_id)


def notification_status() -> dict:
    """Return a status dict showing which notification channels are configured."""
    slack_url = os.getenv("FRAUDOS_SLACK_WEBHOOK_URL", "").strip()
    email_to = os.getenv("FRAUDOS_ALERT_EMAIL_TO", "").strip()
    smtp_host = os.getenv("FRAUDOS_SMTP_HOST", "").strip()

    return {
        "slack": {
            "configured": bool(slack_url),
            "env_var": "FRAUDOS_SLACK_WEBHOOK_URL",
        },
        "email": {
            "configured": bool(email_to and smtp_host),
            "recipients": email_to,
            "smtp_host": smtp_host or None,
            "env_vars": ["FRAUDOS_ALERT_EMAIL_TO", "FRAUDOS_SMTP_HOST", "FRAUDOS_SMTP_USER", "FRAUDOS_SMTP_PASSWORD"],
        },
        "triggers": ["CRITICAL risk level", "BLOCK action", "SLA overdue"],
    }
