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

    The target parses a NAMED cookie (``af_session`` for AgentForge, configurable via
    ``ADVERSARYFORGE_SESSION_COOKIE_NAME``). A pasted bare ``value`` is wrapped as
    ``<name>=<value>``; a value already in ``name=value`` or a full ``a=b; c=d`` header
    form is sent verbatim.
    """

    name = "env-cookie"

    def __init__(self, cookie: str, cookie_name: str = "af_session") -> None:
        self._cookie = cookie.strip()
        self._cookie_name = (cookie_name or "af_session").strip()

    def headers(self) -> dict[str, str]:
        if not self._cookie:
            return {}
        c = self._cookie
        # A bare value must be wrapped as `<name>=<value>` or the target won't parse the
        # session cookie (the bug behind the "authenticated but every request 401s" trap).
        if c.startswith(f"{self._cookie_name}=") or ";" in c:
            header = c
        else:
            header = f"{self._cookie_name}={c}"
        return {"Cookie": header}

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
        return EnvCookieSession(settings.session_cookie, settings.session_cookie_name)
    return AnonymousSession()
