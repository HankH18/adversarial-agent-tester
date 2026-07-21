"""SessionProvider — pluggable authentication for the target.

Real-life best practice for continuous adversarial testing: never hand-manage
cookies inline. Abstract auth behind a provider so the attack engine is oblivious
to *how* a session was obtained. Three backends today:

  * ``AnonymousSession``   — no credentials; exercises the unauthenticated surface
                             (info disclosure, error-oracle, DoS/no-rate-limit,
                             the OAuth flow itself). Always available.
  * ``EnvCookieSession``   — a physician session cookie pasted into ``.env``.
                             Unlocks the authenticated attack plane.
  * ``OAuthSession``       — (stub) automated SMART/OAuth login for hands-off
                             continuous runs. Needs a test-physician credential;
                             wired but not enabled.

The attack engine calls ``headers()`` and ``is_authenticated`` and nothing else, so
adding a backend never touches attack code.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from adversaryforge.config import Settings


class SessionProvider(ABC):
    name: str = "abstract"

    @abstractmethod
    def headers(self) -> dict[str, str]:
        """Auth headers to attach to every target request (may be empty)."""

    @property
    @abstractmethod
    def is_authenticated(self) -> bool:
        """True if this provider carries an identity the target will accept."""


class AnonymousSession(SessionProvider):
    """No credentials. The unauthenticated attack surface is fully reachable and
    is a legitimate, credential-free source of live gate evidence."""

    name = "anonymous"

    def headers(self) -> dict[str, str]:
        return {}

    @property
    def is_authenticated(self) -> bool:
        return False


class EnvCookieSession(SessionProvider):
    """A physician session cookie from ``.env`` (``AGENTFORGE_SESSION_COOKIE``).

    Accepts either a bare ``value`` or a full ``name=value; name2=value2`` header.
    """

    name = "env-cookie"

    def __init__(self, cookie: str) -> None:
        self._cookie = cookie.strip()

    def headers(self) -> dict[str, str]:
        if not self._cookie:
            return {}
        return {"Cookie": self._cookie}

    @property
    def is_authenticated(self) -> bool:
        return bool(self._cookie)


class OAuthSession(SessionProvider):
    """Stub: automated SMART App Launch (authorization-code + PKCE) against the
    target's OpenEMR. Deferred — needs a dedicated test-physician credential.
    Present so the OAuth path drops in without touching the attack engine."""

    name = "oauth"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._bearer: str | None = None

    def headers(self) -> dict[str, str]:
        if self._bearer:
            return {"Authorization": f"Bearer {self._bearer}"}
        return {}

    @property
    def is_authenticated(self) -> bool:
        return self._bearer is not None

    def login(self) -> None:  # pragma: no cover - not enabled
        raise NotImplementedError(
            "OAuth automation deferred: provide a test-physician credential and "
            "implement the authorize→callback exchange here."
        )


def build_session(settings: Settings) -> SessionProvider:
    """Choose the strongest available provider for the current config."""
    if settings.has_session:
        return EnvCookieSession(settings.session_cookie)
    return AnonymousSession()
