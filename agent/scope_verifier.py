"""JWT scope token verification with CIDR/IP target containment check.

Doctests:

>>> v = ScopeVerifier("test-secret")

# Valid token for 10.0.0.1 — passes
>>> import jwt as _jwt, time as _time
>>> tok = _jwt.encode({"scanId":"S1","targets":["10.0.0.0/24"],"notBefore":int(_time.time())-1,"notAfter":int(_time.time())+3600,"exp":int(_time.time())+3600}, "test-secret", algorithm="HS256")
>>> v.verify(tok, "10.0.0.1")
True

# Target outside CIDR — fails
>>> v.verify(tok, "192.168.1.1")
False

# Exact IP match
>>> tok2 = _jwt.encode({"scanId":"S2","targets":["10.0.0.5"],"notBefore":int(_time.time())-1,"notAfter":int(_time.time())+3600,"exp":int(_time.time())+3600}, "test-secret", algorithm="HS256")
>>> v.verify(tok2, "10.0.0.5")
True

# Hostname match
>>> tok3 = _jwt.encode({"scanId":"S3","targets":["example.com"],"notBefore":int(_time.time())-1,"notAfter":int(_time.time())+3600,"exp":int(_time.time())+3600}, "test-secret", algorithm="HS256")
>>> v.verify(tok3, "example.com")
True

# Expired token — fails
>>> tok4 = _jwt.encode({"scanId":"S4","targets":["10.0.0.1"],"notBefore":int(_time.time())-100,"notAfter":int(_time.time())-1,"exp":int(_time.time())-1}, "test-secret", algorithm="HS256")
>>> v.verify(tok4, "10.0.0.1")
False
"""
from __future__ import annotations

import ipaddress
import logging
import time

import jwt

logger = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    pass


class ScopeVerifier:
    def __init__(self, public_key_or_secret: str) -> None:
        self._secret = public_key_or_secret

    def verify(self, scope_token: str, target: str) -> bool:
        try:
            payload = jwt.decode(
                scope_token,
                self._secret,
                algorithms=["HS256"],
                options={"verify_exp": True},
            )
        except jwt.ExpiredSignatureError:
            logger.warning("Scope token expired for target %s", target)
            return False
        except jwt.InvalidTokenError as exc:
            logger.warning("Invalid scope token: %s", exc)
            return False

        now = time.time()
        not_before = payload.get("notBefore", 0)
        not_after  = payload.get("notAfter",  0)

        if now < not_before:
            logger.warning("Scope token not yet valid (notBefore=%s)", not_before)
            return False
        if not_after and now > not_after:
            logger.warning("Scope token expired via notAfter (target=%s)", target)
            return False

        allowed: list[str] = payload.get("targets", [])
        if not self._is_in_scope(target, allowed):
            logger.warning("Target %s not in scope %s", target, allowed)
            return False

        return True

    def _is_in_scope(self, target: str, allowed: list[str]) -> bool:
        for entry in allowed:
            # Exact string match (handles hostnames)
            if entry == target:
                return True
            # CIDR containment
            try:
                network = ipaddress.ip_network(entry, strict=False)
                addr    = ipaddress.ip_address(target)
                if addr in network:
                    return True
            except ValueError:
                pass
            # Hostname prefix/suffix match
            if entry.lower() == target.lower():
                return True

        return False


if __name__ == "__main__":
    import doctest
    doctest.testmod()
