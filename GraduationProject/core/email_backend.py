"""
Custom Django email backend using the Resend Python SDK.

Replaces SMTP — sends emails directly via Resend's API.
Used for OTP delivery (signup verification, password reset).

Usage: set EMAIL_BACKEND=core.email_backend.ResendEmailBackend in .env
"""

import logging
import resend

from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend

logger = logging.getLogger("accounts")


class ResendEmailBackend(BaseEmailBackend):

    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently, **kwargs)
        resend.api_key = settings.RESEND_API_KEY

    def send_messages(self, email_messages):
        """
        Send a list of Django EmailMessage objects via Resend API.
        Returns the number of successfully sent messages.
        """
        if not email_messages:
            return 0

        sent = 0

        for message in email_messages:
            try:
                params: resend.Emails.SendParams = {
                    "from": message.from_email,
                    "to": list(message.to),
                    "subject": message.subject,
                    "text": message.body,
                }

                # Include HTML version if an alternative was attached
                if hasattr(message, "alternatives"):
                    for content, mimetype in message.alternatives:
                        if mimetype == "text/html":
                            params["html"] = content
                            break

                resend.Emails.send(params)
                sent += 1
                logger.info("Email sent via Resend to %s", message.to)

            except Exception as e:
                logger.error("Resend email failed to %s: %s", message.to, e)
                if not self.fail_silently:
                    raise

        return sent
        