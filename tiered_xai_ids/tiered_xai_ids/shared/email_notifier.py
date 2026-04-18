import asyncio
import time
from email.message import EmailMessage
from smtplib import SMTP


class EmailNotifier:
    def __init__(
        self,
        *,
        admin_email: str,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        smtp_from: str,
        smtp_use_tls: bool,
        cooldown_seconds: int,
    ) -> None:
        self.admin_email = admin_email.strip()
        self.smtp_host = smtp_host.strip()
        self.smtp_port = int(smtp_port)
        self.smtp_user = smtp_user.strip()
        self.smtp_password = smtp_password
        self.smtp_from = smtp_from.strip() or "ids-alerts@localhost"
        self.smtp_use_tls = bool(smtp_use_tls)
        self.cooldown_seconds = max(0, int(cooldown_seconds))
        self._last_sent: dict[str, float] = {}
        self._lock = asyncio.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.admin_email and self.smtp_host and self.smtp_port > 0)

    async def send_alert(
        self,
        *,
        subject: str,
        body: str,
        dedupe_key: str,
    ) -> tuple[bool, str]:
        if not self.configured:
            return False, "not_configured"
        if not dedupe_key.strip():
            dedupe_key = f"adhoc-{int(time.time())}"

        now = time.time()
        async with self._lock:
            last_sent = self._last_sent.get(dedupe_key)
            if last_sent is not None and (now - last_sent) < self.cooldown_seconds:
                return False, "cooldown"

        try:
            def _wrapper() -> None:
                self._send_blocking(subject=subject, body=body)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _wrapper)
        except Exception as exc:
            text = str(exc).strip()
            return False, text if text else exc.__class__.__name__

        async with self._lock:
            self._last_sent[dedupe_key] = now
            self._trim_history(now)
        return True, "sent"

    def _send_blocking(self, *, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self.smtp_from
        message["To"] = self.admin_email
        message["Subject"] = subject
        message.set_content(body)

        with SMTP(self.smtp_host, self.smtp_port, timeout=12) as smtp:
            smtp.ehlo()
            if self.smtp_use_tls:
                smtp.starttls()
                smtp.ehlo()
            if self.smtp_user and self.smtp_password:
                smtp.login(self.smtp_user, self.smtp_password)
            smtp.send_message(message)

    def _trim_history(self, now: float) -> None:
        if len(self._last_sent) <= 200:
            return
        cutoff = now - max(1, self.cooldown_seconds * 2)
        self._last_sent = {key: ts for key, ts in self._last_sent.items() if ts >= cutoff}
