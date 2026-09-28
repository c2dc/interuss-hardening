#!/usr/bin/env python3
"""Minimal token signer for the local ecosystem's hardened OAuth flow.

Runs behind the `oauth` nginx service, which terminates mutual TLS against the
OpenBao client CA and forwards the verified client identity in the
``X-SSL-Client-Verify`` / ``X-SSL-Client-CN`` headers. This service:

* ``GET /token`` — issues a short-lived RS256 JWT whose ``sub`` is the *verified*
  client-certificate CN (never a request parameter). Signed with a key generated
  fresh in OpenBao per ``up`` and tagged with a ``kid``. Every token also carries
  an RFC 8705 ``cnf.x5t#S256`` claim binding it to the SHA-256 thumbprint of that
  same client certificate.
* ``GET /.well-known/jwks.json`` — publishes the public half so core-service
  (``-jwks_endpoint``) and mock_uss can validate.
* ``GET /verify-cnf`` — internal endpoint used by the DSS's nginx front
  (``core_service.sh``, ``auth_request``) to check that a bearer token is being
  presented by the same certificate that obtained it. Not part of the public
  token API.

``/token`` also enforces PoLP: each identity may only request scopes on its own
allow-list (``ALLOWED_SCOPES`` below).

Env:
  OAUTH_SIGNING_KEY   path to the PEM private key   (default /secrets/oauth/signing.key)
  OAUTH_KID_FILE      path to the key id            (default /secrets/oauth/kid)
  OAUTH_ISSUER        `iss` claim value             (default oauth.authority.localutm)
  OAUTH_MAX_TTL       max token lifetime, seconds   (default 300)
  OAUTH_BIND          host:port to listen on        (default 127.0.0.1:8081)
"""

import base64
import hashlib
import json
import os
import re
import ssl
import time
import urllib.parse
import uuid

import jwt
import jwcrypto.jwk
from flask import Flask, jsonify, request

SIGNING_KEY_PATH = os.environ.get("OAUTH_SIGNING_KEY", "/secrets/oauth/signing.key")
KID_PATH = os.environ.get("OAUTH_KID_FILE", "/secrets/oauth/kid")
ISSUER = os.environ.get("OAUTH_ISSUER", "oauth.authority.localutm")
MAX_TTL = int(os.environ.get("OAUTH_MAX_TTL", "300"))
BIND = os.environ.get("OAUTH_BIND", "127.0.0.1:8081")
# Shared secret proving a /token request actually traversed the mTLS-terminating
# `oauth` nginx front (which injects the X-Proxy-Auth header from this same
# file). Without it, any peer that can reach this service's port could forge the
# X-SSL-Client-* headers the front is meant to be the sole setter of, and mint a
# token as any identity with NO client certificate at all. Defense in depth on
# top of network isolation (oauth-signer now lives on an internal
# oauth_backend_network only the front can reach).
PROXY_SECRET_PATH = os.environ.get("OAUTH_PROXY_SECRET_FILE", "/secrets/oauth/proxy_secret")

with open(SIGNING_KEY_PATH, "rb") as f:
    _SIGNING_KEY = f.read()
with open(KID_PATH) as f:
    _KID = f.read().strip()
try:
    with open(PROXY_SECRET_PATH) as f:
        _PROXY_SECRET = f.read().strip()
except OSError:
    _PROXY_SECRET = ""
if not _PROXY_SECRET:
    # Isolation still protects /token, but log loudly: the front's header trust
    # is meant to be gated by this secret.
    print(
        "oauth_signer: WARNING no proxy secret at "
        f"{PROXY_SECRET_PATH}; /token header trust is ungated (relying on "
        "network isolation alone)",
        flush=True,
    )

# Public JWK (published at the JWKS endpoint) and its PEM form (used locally to
# verify token signatures for /verify-cnf — no network round-trip needed since
# this service already holds the keypair).
_JWK = jwcrypto.jwk.JWK.from_pem(_SIGNING_KEY)
_PUBLIC_JWK = json.loads(_JWK.export_public())
_PUBLIC_JWK.update({"kid": _KID, "use": "sig", "alg": "RS256"})
_PUBLIC_KEY_PEM = _JWK.export_to_pem(private_key=False)

_CN_RE = re.compile(r"CN\s*=\s*([^,/]+)")

# ---------------------------------------------------------------------------
# PoLP scope enforcement.
#
# Each identity's allow-list is the scope vocabulary that role actually needs,
# pulled from the real uas_standards packages this environment's DSS/mock_uss
# code uses (uas_standards.astm.f3411.{v19,v22a}.constants.Scope,
# uas_standards.astm.f3548.v21.constants.Scope, and the interuss
# automated-testing injection-API scope constants), and traced against
# monitoring/mock_uss/docker-compose.yaml's MOCK_USS_AUTH_SPEC/hostname to see
# which identity plays which role:
#
#   uss1 -- scdsc_a (SCD strategic coordination), ridsp v22a (RID service
#           provider), riddp v22a (RID display provider)
#   uss2 -- scdsc_b (SCD strategic coordination), ridsp v19 (RID SP, legacy)
#   uss3 -- riddp v19 (RID DP, legacy) only
#   uss4 -- tracer: a passive interaction observer with no direct DSS
#           protocol role, so no scopes by default
#   uss6 -- scdsc_interaction_log (SCD strategic coordination + logging)
#
# uss_qualifier / uss_qualifier_2 (the test framework) get None (the full
# known vocabulary), not a narrow list: their documented job is to exercise
# DSS's *own* scope-checking logic, which requires legitimately obtaining a
# technically-valid-but-wrong-for-this-specific-call token -- e.g. the
# existing "Interfaces authentication" conformance check intentionally
# requests the RID v19 scope against a v22a endpoint, specifically to prove
# DSS rejects it. This is still a real, bounded allow-list (rejects typos or
# any scope string outside this environment's defined vocabulary) -- it just
# doesn't try to predict which specific call the test framework is making.
_DSS_SCOPES = frozenset(
    {
        "dss.read.identification_service_areas",
        "dss.write.identification_service_areas",
        "rid.display_provider",
        "rid.service_provider",
        "rid.read.enhanced_details",
        "utm.strategic_coordination",
        "utm.constraint_management",
        "utm.constraint_processing",
        "utm.conformance_monitoring_sa",
        "utm.availability_arbitration",
    }
)
_INJECTION_SCOPES = frozenset(
    {
        "rid.inject_test_data",
        "utm.inject_test_data",
        "interuss.flight_planning.direct_automated_test",
        "interuss.flight_planning.plan",
        "interuss.geospatial_map.direct_automated_test",
        "interuss.geospatial_map.query",
        "interuss.versioning.read_system_versions",
        # mock_uss configuration API scope (MOCK_USS_CONFIG_SCOPE in
        # resources/interuss/mock_uss/client.py). uss_qualifier requests it to
        # set mock_uss locality in the `Configure mock_uss locality` scenario
        # (configurations.dev.uspace / uspace_f3548). Same class of PoLP miss as
        # pool_status below — found by running the uspace configs.
        "interuss.mock_uss.configure",
        # interuss DSS aux "pool status" automated-testing scopes
        # (uas_standards.interuss.dss.aux.constants.Scope.PoolStatusRead /
        # .PoolStatusHeartbeatWrite). PoolStatusRead is requested by the
        # `DSS pool information` scenario (scenarios/interuss/dss/pool_info.py,
        # run by configurations.dev.f3548_self_contained). Missed by the initial
        # PoLP allow-list (which enumerated only the F3411/F3548 + injection
        # scope enums) and only surfaced by running f3548_self_contained — the
        # same class of miss as rid.read.enhanced_details.
        "interuss.pool_status.read",
        "interuss.pool_status.heartbeat.write",
    }
)

# utm.conformance_monitoring_sa (CMSA) is required, in addition to
# utm.strategic_coordination, by every SCD strategic-coordination mock USS
# (uss1/scdsc_a, uss2/scdsc_b, uss6/scdsc_interaction_log) whenever it shares an
# operational intent transitioning to a Contingent or Nonconforming state
# (monitorlib/clients/scd.py `_scopes_for_state`). Missed by the initial
# allow-list because minimal_probing / f3548_self_contained never drive a flight
# into a non-conforming state; only surfaced by the uspace / uspace_f3548 /
# utm_implementation_us "not permitted conflict" scenarios, where its absence
# made the mock 500 on flight planning. Same class of PoLP miss as
# rid.read.enhanced_details and pool_status/mock_uss.configure.
ALLOWED_SCOPES: dict[str, frozenset[str] | None] = {
    "uss1": frozenset(
        {
            "utm.strategic_coordination",
            "utm.conformance_monitoring_sa",
            "rid.service_provider",
            "rid.display_provider",
        }
    ),
    "uss2": frozenset(
        {
            "utm.strategic_coordination",
            "utm.conformance_monitoring_sa",
            "dss.write.identification_service_areas",
        }
    ),
    # rid.read.enhanced_details (UPP2_SCOPE_ENHANCED_DETAILS, monitorlib/rid_v1.py) is
    # needed alongside the base read scope: mock_uss's own RID v19 display-provider
    # code (mock_uss/riddp/routes_observation.py) always requests flight *details*
    # with enhanced_details=True, which for v19 requires both scopes together
    # (monitorlib/fetch/rid.py). Found via full-environment testing (netrid_v19
    # config) after the initial PoLP allow-list only checked the core F3411 v19
    # Scope enum and missed this separate UPP2-specific scope constant.
    "uss3": frozenset(
        {"dss.read.identification_service_areas", "rid.read.enhanced_details"}
    ),
    "uss4": frozenset(),
    "uss6": frozenset(
        {"utm.strategic_coordination", "utm.conformance_monitoring_sa"}
    ),
    "uss_qualifier": None,  # full vocabulary -- see comment above
    "uss_qualifier_2": None,
}

app = Flask(__name__)


def _x5t_s256(escaped_pem_cert: str) -> str | None:
    """RFC 8705 `x5t#S256`: base64url(SHA-256(DER bytes)) of a client cert.

    `escaped_pem_cert` is nginx's `$ssl_client_escaped_cert` (URI-encoded PEM,
    empty string if no client cert was presented). Returns None if empty/invalid.
    """
    if not escaped_pem_cert:
        return None
    pem = urllib.parse.unquote(escaped_pem_cert)
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (ssl.SSLError, ValueError):
        return None
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _disallowed_scopes(sub: str, scope: str) -> list[str]:
    """Requested scopes (space-separated) not permitted for `sub`, per ALLOWED_SCOPES.

    A `sub` with no entry at all is treated as allowed-nothing (fail-closed for
    any future/unknown identity). `None` in ALLOWED_SCOPES means "the full
    known vocabulary" (uss_qualifier/uss_qualifier_2 -- see the comment on
    ALLOWED_SCOPES), not "unrestricted": anything outside _DSS_SCOPES |
    _INJECTION_SCOPES is still rejected.
    """
    requested = scope.split()
    if not requested:
        return []  # no scope requested at all -- not this check's concern
    allowed = ALLOWED_SCOPES.get(sub)
    if allowed is None and sub in ALLOWED_SCOPES:
        allowed = _DSS_SCOPES | _INJECTION_SCOPES
    allowed = allowed or frozenset()
    return [s for s in requested if s not in allowed]


@app.get("/.well-known/jwks.json")
def jwks():
    return jsonify({"keys": [_PUBLIC_JWK]})


@app.get("/token")
def token():
    # Provenance gate: the X-SSL-Client-* headers below are trustworthy only
    # because the mTLS-terminating `oauth` front sets them from a *verified*
    # client certificate. Reject any /token request that did not come through
    # that front (it injects X-Proxy-Auth). Without this, forging those headers
    # against a reachable signer would mint a token as any identity, no cert.
    if _PROXY_SECRET and request.headers.get("X-Proxy-Auth", "") != _PROXY_SECRET:
        return jsonify({"error": "forbidden"}), 403

    # Identity: strictly from the mutually-authenticated client certificate.
    if request.headers.get("X-SSL-Client-Verify") != "SUCCESS":
        return jsonify({"error": "client certificate required"}), 403
    dn = request.headers.get("X-SSL-Client-CN", "")
    m = _CN_RE.search(dn)
    if not m:
        return jsonify({"error": f"no CN in client certificate DN: {dn!r}"}), 403
    sub = m.group(1).strip()

    audience = request.args.get("intended_audience")
    if not audience:
        return jsonify({"error": "missing `intended_audience`"}), 400
    scope = request.args.get("scope", "")

    # PoLP: reject the whole request if any requested scope isn't on this
    # identity's allow-list (an empty scope request, used to test DSS's own
    # "missing scope" rejection, is unaffected -- see ALLOWED_SCOPES).
    disallowed = _disallowed_scopes(sub, scope)
    if disallowed:
        return (
            jsonify(
                {
                    "error": f"scope(s) {disallowed} not permitted for '{sub}'",
                }
            ),
            403,
        )

    try:
        requested = int(request.args.get("expire", MAX_TTL))
    except ValueError:
        requested = MAX_TTL
    now = int(time.time())
    ttl = max(1, min(requested if requested > 0 else MAX_TTL, MAX_TTL))

    claims = {
        "sub": sub,
        "client_id": sub,
        "scope": scope,
        "aud": audience,
        "iss": ISSUER,
        "iat": now,
        "nbf": now - 5,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }

    # RFC 8705 sender-constraint: bind this token to the same client certificate
    # that authenticated to get it, so a captured bearer token alone is not
    # enough to use it elsewhere. Every token issued by this environment gets a
    # cnf claim — the client cert was already required above (403 otherwise).
    thumbprint = _x5t_s256(request.headers.get("X-SSL-Client-Cert", ""))
    if thumbprint:
        claims["cnf"] = {"x5t#S256": thumbprint}

    access_token = jwt.encode(
        claims, _SIGNING_KEY, algorithm="RS256", headers={"kid": _KID}
    )
    return jsonify({"access_token": access_token})


@app.get("/verify-cnf")
def verify_cnf():
    """RFC 8705 + issuer enforcement point for the DSS's nginx front (auth_request).

    Not itself authoritative for the token's audience/scope — the DSS's own
    core-service still validates those via JWKS after nginx allows the request
    through. This endpoint answers two questions:

      1. Was this token issued by the authority we trust (`iss` == ISSUER)?
      2. Is the caller presenting it the same client that obtained it (RFC 8705)?

    (2) is the primary control. (1) is defense in depth: core-service
    validates the token's signature and audience but never the *value* of `iss`,
    and the upstream binary exposes no flag to make it (only -accepted_jwt_audiences
    / -jwks_*). Since forging a token requires the signing key — the trust anchor
    itself — this closes a layer rather than an exploitable hole.

    Scope note: this covers the DSS only. mock_uss validates tokens itself
    (monitorlib/auth_validation.py) and does NOT check `iss`; that is the same
    documented DSS-only boundary that already applies to RFC 8705.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing bearer token"}), 401
    token = auth_header[len("Bearer ") :]

    try:
        claims = jwt.decode(
            token,
            _PUBLIC_KEY_PEM,
            algorithms=["RS256"],
            # Rejects a token whose `iss` is absent or is not this authority.
            # PyJWT raises InvalidIssuerError / MissingRequiredClaimError, both
            # InvalidTokenError subclasses, so the handler below returns 401 --
            # the correct status here, and the reason nginx needs no change: its
            # auth_request 403 body states the client certificate is missing or
            # does not match the token binding, which would be a false diagnostic
            # for a token whose cnf binding is perfectly valid. Signature is
            # verified before claims, so tokens signed with an untrusted key
            # (NoAuth / InvalidTokenSignatureAuth in the DSS auth scenarios) still
            # fail on signature and keep their existing 401.
            issuer=ISSUER,
            options={"verify_aud": False},
        )
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"invalid token: {e}"}), 401

    bound = (claims.get("cnf") or {}).get("x5t#S256")
    if not bound:
        return jsonify({"error": "token is not sender-constrained"}), 403

    presented = _x5t_s256(request.headers.get("X-SSL-Client-Cert", ""))
    if not presented:
        return jsonify({"error": "client certificate required"}), 403

    if presented != bound:
        return (
            jsonify({"error": "presented certificate does not match token binding"}),
            403,
        )

    return jsonify({"ok": True})


if __name__ == "__main__":
    host, _, port = BIND.rpartition(":")
    app.run(host=host or "127.0.0.1", port=int(port), threaded=True)
