"""A small, readable SD-JWT implementation (RFC 9901 / draft-ietf-oauth-selective-disclosure-jwt).

What an SD-JWT is, in one paragraph: the issuer signs a JWT whose payload does
not contain the selectively-disclosable values themselves, only SHA-256 digests
of "disclosures". A disclosure is base64url(JSON array):

    object property:  [salt, claim_name, value]   -> digest goes in the parent's `_sd` array
    array element:    [salt, value]               -> element is replaced by {"...": digest}

The holder later presents the signed JWT plus only the disclosures it wants to
reveal, joined with `~`:

    <issuer-signed JWT>~<disclosure 1>~...~<disclosure N>~[<KB-JWT>]

A verifier hashes each presented disclosure and checks the digest appears in the
signed payload, so a holder can hide values but can never change or add them.

Key binding (KB-JWT, `typ: kb+jwt`) proves the presenter holds the key named in
the credential's `cnf` claim and binds the presentation to one verifier (`aud`)
and one challenge (`nonce`). `sd_hash` is the hash of exactly what was presented,
so disclosures cannot be swapped after the KB-JWT is signed.

AP2 chains SD-JWTs for delegation (draft-gco-oauth-delegate-sd-jwt): instead of a
plain KB-JWT, the agent appends a whole SD-JWT signed with the `cnf` key
(`typ: kb+sd-jwt`) whose payload carries the same `aud`/`nonce`/`iat`/`sd_hash`
binding claims plus the closed mandate. Segments are joined with `~~`. Both forms
are implemented here; `kb_sd_jwt_*` reuses the KB-JWT checks.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric import ec

from . import jws
from .b64 import b64url_decode, b64url_encode

SD_ALG = "sha-256"
KB_JWT_TYP = "kb+jwt"
KB_SD_JWT_TYP = "kb+sd-jwt"
CHAIN_SEPARATOR = "~~"


class SDJWTError(ValueError):
    """Any SD-JWT parse or verification failure."""


# --------------------------------------------------------------------------- disclosures


@dataclass(frozen=True)
class SD:
    """Marker: wrap a dict value or a list element in SD(...) to make it
    selectively disclosable when building an SD-JWT payload."""

    value: Any


@dataclass(frozen=True)
class Disclosure:
    encoded: str
    salt: str
    name: str | None  # None for array-element disclosures
    value: Any

    @property
    def digest(self) -> str:
        return digest_of(self.encoded)


def digest_of(encoded_disclosure: str) -> str:
    """Digest over the ASCII base64url string, as the RFC requires (not over the JSON)."""
    return b64url_encode(hashlib.sha256(encoded_disclosure.encode("ascii")).digest())


def make_disclosure(value: Any, name: str | None = None, salt: str | None = None) -> Disclosure:
    salt = salt or b64url_encode(secrets.token_bytes(16))
    if name in ("_sd", "..."):
        raise SDJWTError(f"{name!r} cannot be a disclosed claim name")
    array = [salt, value] if name is None else [salt, name, value]
    encoded = b64url_encode(json.dumps(array, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return Disclosure(encoded, salt, name, value)


def parse_disclosure(encoded: str) -> Disclosure:
    try:
        array = json.loads(b64url_decode(encoded))
    except ValueError as exc:
        raise SDJWTError(f"malformed disclosure: {exc}") from exc
    if not isinstance(array, list) or len(array) not in (2, 3) or not isinstance(array[0], str):
        raise SDJWTError("a disclosure must be [salt, value] or [salt, name, value]")
    if len(array) == 2:
        return Disclosure(encoded, array[0], None, array[1])
    if not isinstance(array[1], str) or array[1] in ("_sd", "..."):
        raise SDJWTError("invalid disclosed claim name")
    return Disclosure(encoded, array[0], array[1], array[2])


def build_payload(claims: Any) -> tuple[Any, list[Disclosure]]:
    """Turn a claims tree containing SD(...) markers into (payload, disclosures).

    Nested markers are supported: the inner value is processed first, so a
    disclosure can itself contain digests (e.g. AP2's open mandate disclosure
    contains `allowed_payees` whose elements are separately disclosable)."""
    disclosures: list[Disclosure] = []

    def walk(node: Any) -> Any:
        if isinstance(node, SD):
            raise SDJWTError("SD(...) must wrap a dict value or a list element")
        if isinstance(node, dict):
            out: dict = {}
            digests = []
            for key, value in node.items():
                if isinstance(value, SD):
                    d = make_disclosure(walk(value.value), name=key)
                    disclosures.append(d)
                    digests.append(d.digest)
                else:
                    out[key] = walk(value)
            if digests:
                # Sorted so the digest order leaks nothing about claim order.
                out["_sd"] = sorted(digests)
            return out
        if isinstance(node, list):
            out_list = []
            for element in node:
                if isinstance(element, SD):
                    d = make_disclosure(walk(element.value))
                    disclosures.append(d)
                    out_list.append({"...": d.digest})
                else:
                    out_list.append(walk(element))
            return out_list
        return node

    return walk(claims), disclosures


def resolve(payload: dict, encoded_disclosures: Iterable[str]) -> dict:
    """Rebuild the plain claims from a signed payload and presented disclosures.

    Enforces the RFC's verifier rules: every presented disclosure must be
    referenced exactly once, digests may not repeat, property disclosures only
    fill `_sd` slots and array disclosures only fill `{"...": d}` slots, and a
    disclosed name may not overwrite a claim already in the payload."""
    by_digest: dict[str, Disclosure] = {}
    for encoded in encoded_disclosures:
        disclosure = parse_disclosure(encoded)
        if disclosure.digest in by_digest:
            raise SDJWTError("the same disclosure was presented twice")
        by_digest[disclosure.digest] = disclosure
    used: set[str] = set()

    def claim(digest: Any) -> Disclosure | None:
        if not isinstance(digest, str):
            raise SDJWTError("digests must be strings")
        if digest in used:
            raise SDJWTError("a digest is referenced more than once")
        found = by_digest.get(digest)
        if found is not None:
            used.add(digest)
        return found

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out = {k: walk(v) for k, v in node.items() if k != "_sd"}
            sd_list = node.get("_sd", [])
            if not isinstance(sd_list, list):
                raise SDJWTError("_sd must be an array")
            for digest in sd_list:
                d = claim(digest)
                if d is None:
                    continue  # not disclosed: stays hidden
                if d.name is None:
                    raise SDJWTError("array-element disclosure used for an object property")
                if d.name in out:
                    raise SDJWTError(f"disclosed claim {d.name!r} would overwrite an existing claim")
                out[d.name] = walk(d.value)
            return out
        if isinstance(node, list):
            out_list = []
            for element in node:
                if isinstance(element, dict) and set(element) == {"..."}:
                    d = claim(element["..."])
                    if d is None:
                        continue
                    if d.name is not None:
                        raise SDJWTError("property disclosure used for an array element")
                    out_list.append(walk(d.value))
                else:
                    out_list.append(walk(element))
            return out_list
        return node

    claims = walk(payload)
    unreferenced = set(by_digest) - used
    if unreferenced:
        raise SDJWTError("a presented disclosure is not referenced by the signed payload")
    claims.pop("_sd_alg", None)
    return claims


# --------------------------------------------------------------------------- serialization


@dataclass
class SdJwt:
    issuer_jwt: str
    disclosures: list[str] = field(default_factory=list)
    kb_jwt: str | None = None

    def without_kb(self) -> str:
        """The `<jwt>~<d1>~...~` prefix that `sd_hash` is computed over."""
        return self.issuer_jwt + "~" + "".join(d + "~" for d in self.disclosures)

    def serialize(self) -> str:
        return self.without_kb() + (self.kb_jwt or "")

    def sd_hash(self) -> str:
        return b64url_encode(hashlib.sha256(self.without_kb().encode("ascii")).digest())

    def decoded_disclosures(self) -> list[Disclosure]:
        return [parse_disclosure(d) for d in self.disclosures]


def parse(serialized: str) -> SdJwt:
    if not isinstance(serialized, str) or "~" not in serialized:
        raise SDJWTError("an SD-JWT must contain '~'")
    parts = serialized.split("~")
    issuer_jwt, disclosures, last = parts[0], parts[1:-1], parts[-1]
    if not issuer_jwt or any(d == "" for d in disclosures):
        raise SDJWTError("empty SD-JWT component")
    return SdJwt(issuer_jwt, disclosures, last or None)


def join_chain(tokens: list[SdJwt]) -> str:
    """AP2 delegation chain: each non-final token loses its trailing '~' and the
    segments are joined with '~~' (as in the AP2 reference SDK)."""
    pieces = []
    for i, token in enumerate(tokens):
        text = token.serialize()
        if i < len(tokens) - 1:
            if token.kb_jwt:
                raise SDJWTError("only the last token in a chain may carry a KB-JWT")
            text = text[:-1]
        pieces.append(text)
    return CHAIN_SEPARATOR.join(pieces)


def split_chain(serialized: str) -> list[SdJwt]:
    segments = serialized.split(CHAIN_SEPARATOR)
    tokens = []
    for i, segment in enumerate(segments):
        if i < len(segments) - 1:
            segment += "~"
        tokens.append(parse(segment))
    return tokens


def present(token: SdJwt, keep: Iterable[str]) -> SdJwt:
    """A presentation that reveals only the disclosures whose digests are in `keep`."""
    keep = set(keep)
    return SdJwt(token.issuer_jwt, [d for d in token.disclosures if digest_of(d) in keep])


# --------------------------------------------------------------------------- issuing & verifying


@dataclass(frozen=True)
class VerifiedSdJwt:
    header: dict
    payload: dict  # as signed (digests, no plaintext)
    claims: dict  # resolved with the presented disclosures


def issue(claims: dict, key: ec.EllipticCurvePrivateKey, header: dict) -> SdJwt:
    """Issue a full SD-JWT (all disclosures included) signed by `key`."""
    payload, disclosures = build_payload(claims)
    payload["_sd_alg"] = SD_ALG
    issuer_jwt = jws.sign(header, payload, key)
    return SdJwt(issuer_jwt, [d.encoded for d in disclosures])


def verify(token: SdJwt, key: ec.EllipticCurvePublicKey, expected_typ: str | None = None) -> VerifiedSdJwt:
    try:
        decoded = jws.verify(token.issuer_jwt, key, expected_typ=expected_typ)
    except jws.JWSError as exc:
        raise SDJWTError(f"signature: {exc}") from exc
    if decoded.payload.get("_sd_alg", SD_ALG) != SD_ALG:
        raise SDJWTError("unsupported _sd_alg")
    claims = resolve(decoded.payload, token.disclosures)
    return VerifiedSdJwt(decoded.header, decoded.payload, claims)


def _binding_claims(prev: SdJwt, aud: str, nonce: str, iat: int) -> dict:
    return {"iat": iat, "aud": aud, "nonce": nonce, "sd_hash": prev.sd_hash()}


def check_binding(payload: dict, prev: SdJwt, aud: str, nonce: str, now: int, max_age: int) -> None:
    if payload.get("aud") != aud:
        raise SDJWTError("key binding: wrong audience")
    if not isinstance(payload.get("nonce"), str) or payload.get("nonce") != nonce:
        raise SDJWTError("key binding: wrong nonce")
    iat = payload.get("iat")
    if not isinstance(iat, int) or iat > now + 60 or iat < now - max_age:
        raise SDJWTError("key binding: iat outside the accepted window")
    if payload.get("sd_hash") != prev.sd_hash():
        raise SDJWTError("key binding: sd_hash does not match the presented SD-JWT")


def create_kb_jwt(token: SdJwt, holder_key: ec.EllipticCurvePrivateKey, aud: str, nonce: str, iat: int) -> SdJwt:
    """Attach a standard KB-JWT (`typ: kb+jwt`) to a presentation."""
    kb = jws.sign({"typ": KB_JWT_TYP}, _binding_claims(token, aud, nonce, iat), holder_key)
    return SdJwt(token.issuer_jwt, list(token.disclosures), kb)


def verify_kb_jwt(token: SdJwt, holder_key: ec.EllipticCurvePublicKey, aud: str, nonce: str,
                  now: int, max_age: int = 300) -> dict:
    if not token.kb_jwt:
        raise SDJWTError("key binding JWT missing")
    try:
        decoded = jws.verify(token.kb_jwt, holder_key, expected_typ=KB_JWT_TYP)
    except jws.JWSError as exc:
        raise SDJWTError(f"key binding: {exc}") from exc
    check_binding(decoded.payload, token, aud, nonce, now, max_age)
    return decoded.payload


def create_kb_sd_jwt(prev: SdJwt, holder_key: ec.EllipticCurvePrivateKey, claims: dict,
                     aud: str, nonce: str, iat: int) -> SdJwt:
    """AP2 terminal delegation hop: an SD-JWT signed with the `cnf` key of `prev`,
    carrying the KB binding claims plus its own (selectively disclosable) claims."""
    payload, disclosures = build_payload(claims)
    payload.update(_binding_claims(prev, aud, nonce, iat))
    payload["_sd_alg"] = SD_ALG
    issuer_jwt = jws.sign({"typ": KB_SD_JWT_TYP}, payload, holder_key)
    return SdJwt(issuer_jwt, [d.encoded for d in disclosures])


def verify_kb_sd_jwt(token: SdJwt, prev: SdJwt, holder_key: ec.EllipticCurvePublicKey,
                     aud: str, nonce: str, now: int, max_age: int = 300) -> VerifiedSdJwt:
    verified = verify(token, holder_key, expected_typ=KB_SD_JWT_TYP)
    check_binding(verified.payload, prev, aud, nonce, now, max_age)
    return verified
