from __future__ import annotations

import resend
from app.core.config import settings


def send_evaluator_invitation(to_email: str, evaluator_name: str, procurement_title: str, invite_url: str) -> None:
    """Send a professional HTML invitation email to a prospective evaluator."""
    if not settings.RESEND_API_KEY or settings.RESEND_API_KEY == "re_your_api_key_here":
        # Development fallback — just print to console
        print(f"[EMAIL] To: {to_email} | Invite URL: {invite_url}")
        return

    resend.api_key = settings.RESEND_API_KEY

    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8"/>
      <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 0; }}
        .container {{ max-width: 600px; margin: 40px auto; background: #1e293b; border-radius: 16px; overflow: hidden; border: 1px solid #334155; }}
        .header {{ background: linear-gradient(135deg, #6366f1, #8b5cf6); padding: 40px 32px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; color: #fff; letter-spacing: -0.5px; }}
        .header p {{ margin: 8px 0 0; color: rgba(255,255,255,0.8); font-size: 14px; }}
        .body {{ padding: 32px; }}
        .body p {{ line-height: 1.7; color: #94a3b8; margin: 0 0 16px; }}
        .body strong {{ color: #e2e8f0; }}
        .btn {{ display: inline-block; margin: 24px 0; padding: 14px 32px; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #fff; text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 16px; }}
        .footer {{ padding: 24px 32px; border-top: 1px solid #334155; font-size: 12px; color: #475569; text-align: center; }}
        .tag {{ display: inline-block; padding: 4px 12px; background: rgba(99,102,241,0.15); border: 1px solid rgba(99,102,241,0.3); border-radius: 999px; font-size: 12px; color: #a5b4fc; margin-bottom: 20px; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔐 CSePS</h1>
          <p>Crypto-Secure e-Procurement System</p>
        </div>
        <div class="body">
          <span class="tag">Evaluator Invitation</span>
          <p>Hello <strong>{evaluator_name or to_email}</strong>,</p>
          <p>
            You have been invited to serve as a <strong>cryptographic evaluator</strong> for the procurement:
          </p>
          <p style="background:#0f172a; border-left: 3px solid #6366f1; padding: 12px 16px; border-radius: 4px; font-size: 18px; color: #e2e8f0;">
            {procurement_title}
          </p>
          <p>
            As an evaluator, you will hold one share of the cryptographic key required to unlock sealed bids
            after the submission deadline. Your participation is essential to the integrity of the process.
          </p>
          <p>Click the button below to accept your invitation and generate your secure key pair:</p>
          <a href="{invite_url}" class="btn">Accept Invitation →</a>
          <p style="font-size: 13px; color: #475569;">
            This link is single-use and expires in 72 hours. Do not share it with anyone.
          </p>
        </div>
        <div class="footer">
          CSePS &mdash; Cryptographically secured procurement. &nbsp;|&nbsp; If you did not expect this email, please ignore it.
        </div>
      </div>
    </body>
    </html>
    """

    resend.Emails.send({
        "from": f"CSePS <noreply@{settings.FRONTEND_URL.replace('https://', '').replace('http://', '')}>",
        "to": [to_email],
        "subject": f"You're invited as an Evaluator — {procurement_title}",
        "html": html_body,
    })
