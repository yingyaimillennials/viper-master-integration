"""F-03: Challenge-response nonce flow (prevents replay)."""
import secrets
from datetime import datetime, timezone


class ChallengeStore:
    def __init__(self):
            self._challenges = {}

                def issue(self, subject):
                        nonce = secrets.token_urlsafe(32)
                                self._challenges[nonce] = {
                                            "subject": subject,
                                                        "issued_at": datetime.now(timezone.utc).isoformat(),
                                                                }
                                                                        return nonce

                                                                            def consume(self, nonce, subject):
                                                                                    entry = self._challenges.pop(nonce, None)
                                                                                            if entry is None:
                                                                                                        return False
                                                                                                                return entry["subject"] == subject
