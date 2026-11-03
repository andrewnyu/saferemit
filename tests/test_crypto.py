import json

import pytest

from padala.crypto import jws, sdjwt
from padala.crypto.b64 import b64url_decode, b64url_encode
from padala.crypto.jwk import generate_private_key, load_public_jwk, public_jwk, thumbprint
from padala.crypto.sdjwt import SD, SDJWTError

NOW = 1_800_000_000


# ----------------------------------------------------------------------------- base64url / JWK


def test_b64url_roundtrip_and_strictness():
    for data in [b"", b"\x00", b"hello", bytes(range(256))]:
        assert b64url_decode(b64url_encode(data)) == data
    assert "=" not in b64url_encode(b"ab")
    for bad in ["ab=", "a+b", "a/b", "a b", "a"]:
        with pytest.raises(ValueError):
            b64url_decode(bad)


def test_rfc7638_thumbprint_canonical_form():
    # RFC 7638: only the required members (crv, kty, x, y), sorted, no whitespace.
    # Optional members such as use/kid must not change the thumbprint.
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    }
    import hashlib

    canonical = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (jwk["x"], jwk["y"])
    expected = b64url_encode(hashlib.sha256(canonical.encode()).digest())
    assert thumbprint({**jwk, "use": "sig", "kid": "ignored"}) == expected


def test_jwk_roundtrip_and_rejections():
    key = generate_private_key()
    jwk = public_jwk(key)
    assert load_public_jwk(jwk).public_numbers() == key.public_key().public_numbers()
    with pytest.raises(ValueError):
        load_public_jwk({**jwk, "crv": "P-384"})
    with pytest.raises(ValueError):
        load_public_jwk({**jwk, "d": "AAAA"})
    with pytest.raises(ValueError):
        load_public_jwk({**jwk, "x": b64url_encode(b"\x01" * 31)})
    with pytest.raises(ValueError):  # point not on the curve
        load_public_jwk({**jwk, "y": b64url_encode(b"\x01" * 32)})


# ----------------------------------------------------------------------------- JWS


def test_jws_sign_verify():
    key = generate_private_key()
    token = jws.sign({"typ": "test+jwt"}, {"hello": "mundo", "n": 1}, key)
    decoded = jws.verify(token, key.public_key(), expected_typ="test+jwt")
    assert decoded.payload == {"hello": "mundo", "n": 1}
    assert decoded.header["alg"] == "ES256"
    assert len(decoded.signature) == 64  # raw r||s, like WebCrypto


def test_jws_tamper_cases():
    key = generate_private_key()
    other = generate_private_key()
    token = jws.sign({"typ": "t"}, {"amount": 100}, key)
    h, p, s = token.split(".")
    forged_payload = b64url_encode(json.dumps({"amount": 999}).encode())
    with pytest.raises(jws.JWSError):
        jws.verify(f"{h}.{forged_payload}.{s}", key.public_key())
    with pytest.raises(jws.JWSError):
        jws.verify(token, other.public_key())
    with pytest.raises(jws.JWSError):  # alg=none downgrade
        none_header = b64url_encode(json.dumps({"alg": "none"}).encode())
        jws.verify(f"{none_header}.{p}.", key.public_key())
    with pytest.raises(jws.JWSError):
        jws.verify(token, key.public_key(), expected_typ="other")
    with pytest.raises(jws.JWSError):  # flipped signature bit
        sig = bytearray(b64url_decode(s))
        sig[5] ^= 1
        jws.verify(f"{h}.{p}.{b64url_encode(bytes(sig))}", key.public_key())


# ----------------------------------------------------------------------------- SD-JWT


@pytest.fixture
def issued():
    key = generate_private_key()
    claims = {
        "iss": "ofw",
        "name": SD("Maria"),
        "address": SD({"city": SD("Bacolod"), "country": "PH"}),
        "payees": [SD({"id": "school"}), SD({"id": "power"}), {"id": "always-visible"}],
    }
    token = sdjwt.issue(claims, key, {"typ": "example+sd-jwt"})
    return key, token


def test_sd_jwt_full_disclosure(issued):
    key, token = issued
    verified = sdjwt.verify(sdjwt.parse(token.serialize()), key.public_key(), "example+sd-jwt")
    assert verified.claims == {
        "iss": "ofw",
        "name": "Maria",
        "address": {"city": "Bacolod", "country": "PH"},
        "payees": [{"id": "school"}, {"id": "power"}, {"id": "always-visible"}],
    }
    assert verified.payload["_sd_alg"] == "sha-256"
    assert "Maria" not in json.dumps(verified.payload)  # plaintext never in the signed payload


def test_sd_jwt_selective_presentation(issued):
    key, token = issued
    keep = {d.digest for d in token.decoded_disclosures()
            if d.value == {"id": "power"} or d.name == "address"}
    presented = sdjwt.present(token, keep)
    claims = sdjwt.verify(presented, key.public_key()).claims
    assert claims["payees"] == [{"id": "power"}, {"id": "always-visible"}]
    assert claims["address"] == {"country": "PH"}  # nested city stays hidden
    assert "name" not in claims


def test_sd_jwt_disclosure_tamper(issued):
    key, token = issued
    d = token.decoded_disclosures()[0]
    forged = sdjwt.make_disclosure("Mallory", name=d.name, salt=d.salt)
    tampered = sdjwt.SdJwt(token.issuer_jwt, [forged.encoded] + token.disclosures[1:])
    with pytest.raises(SDJWTError, match="not referenced"):
        sdjwt.verify(tampered, key.public_key())


def test_sd_jwt_rejects_duplicates_and_misplaced(issued):
    key, token = issued
    with pytest.raises(SDJWTError, match="twice"):
        sdjwt.verify(sdjwt.SdJwt(token.issuer_jwt, token.disclosures + token.disclosures[:1]),
                     key.public_key())
    with pytest.raises(SDJWTError):
        sdjwt.verify(sdjwt.SdJwt(token.issuer_jwt, ["not-base64!"]), key.public_key())


def test_sd_jwt_overwrite_attack():
    # An issuer payload that has both a plain claim and a digest for the same name
    # must not let the disclosure override the plain value.
    key = generate_private_key()
    d = sdjwt.make_disclosure("evil", name="role")
    payload = {"role": "family", "_sd": [d.digest], "_sd_alg": "sha-256"}
    token = sdjwt.SdJwt(jws.sign({}, payload, key), [d.encoded])
    with pytest.raises(SDJWTError, match="overwrite"):
        sdjwt.verify(token, key.public_key())


def test_sd_jwt_wrong_issuer_key(issued):
    _, token = issued
    with pytest.raises(SDJWTError, match="signature"):
        sdjwt.verify(token, generate_private_key().public_key())


def test_kb_jwt(issued):
    key, token = issued
    holder = generate_private_key()
    presented = sdjwt.create_kb_jwt(token, holder, aud="gateway", nonce="n-1", iat=NOW)
    parsed = sdjwt.parse(presented.serialize())
    header = jws.decode_unverified(parsed.kb_jwt).header
    assert header["typ"] == "kb+jwt"
    payload = sdjwt.verify_kb_jwt(parsed, holder.public_key(), "gateway", "n-1", now=NOW)
    assert set(payload) == {"iat", "aud", "nonce", "sd_hash"}

    with pytest.raises(SDJWTError, match="audience"):
        sdjwt.verify_kb_jwt(parsed, holder.public_key(), "someone-else", "n-1", now=NOW)
    with pytest.raises(SDJWTError, match="nonce"):
        sdjwt.verify_kb_jwt(parsed, holder.public_key(), "gateway", "n-2", now=NOW)
    with pytest.raises(SDJWTError, match="iat"):
        sdjwt.verify_kb_jwt(parsed, holder.public_key(), "gateway", "n-1", now=NOW + 3600)
    with pytest.raises(SDJWTError, match="signature"):
        sdjwt.verify_kb_jwt(parsed, generate_private_key().public_key(), "gateway", "n-1", now=NOW)
    # Dropping a disclosure after signing breaks sd_hash.
    stripped = sdjwt.SdJwt(parsed.issuer_jwt, parsed.disclosures[1:], parsed.kb_jwt)
    with pytest.raises(SDJWTError, match="sd_hash"):
        sdjwt.verify_kb_jwt(stripped, holder.public_key(), "gateway", "n-1", now=NOW)


def test_kb_sd_jwt_chain(issued):
    key, token = issued
    holder = generate_private_key()
    closed = sdjwt.create_kb_sd_jwt(token, holder, {"vct": "x", "secret": SD(42)},
                                    aud="gw", nonce="abc", iat=NOW)
    wire = sdjwt.join_chain([token, closed])
    assert "~~" in wire
    first, second = sdjwt.split_chain(wire)
    assert first.serialize() == token.serialize()
    verified = sdjwt.verify_kb_sd_jwt(second, first, holder.public_key(), "gw", "abc", now=NOW)
    assert verified.claims["secret"] == 42
    assert verified.header["typ"] == "kb+sd-jwt"

    # Re-pointing the closed hop at a different open presentation fails sd_hash.
    narrower = sdjwt.present(first, [first.decoded_disclosures()[0].digest])
    with pytest.raises(SDJWTError, match="sd_hash"):
        sdjwt.verify_kb_sd_jwt(second, narrower, holder.public_key(), "gw", "abc", now=NOW)
