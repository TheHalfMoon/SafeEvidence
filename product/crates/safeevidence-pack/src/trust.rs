//! Clean-room RFC 8032 Ed25519 pack signature verification & synthetic pack trust root (`TA-06`,
//! `TA-28`).
//!
//! Implements strict canonical RFC 8032 §5.1 Ed25519 (rejecting non-canonical `y >= p` and
//! `S >= L` signature malleability) in 100% safe Rust (`#![forbid(unsafe_code)]`) using
//! `num-bigint` and `sha2::Sha512`. Never claims `OS_CA_CODE_SIGNED` (`ADR-0004`).

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha512};

/// Synthetic pack trust root identifier (`READY_BASE` engineering/research packs; `release_ready = false`).
pub const SYNTHETIC_PACK_TRUST_ROOT_ID: &str = "synthetic-pack-trust-v1";

/// Deterministic synthetic test seed used only for synthetic fixture signing (`TA-06` / `TA-28`).
const SYNTHETIC_PACK_SEED: [u8; 32] = *b"SAFEVD-SYNTH-PACK-ROOT-SEED-0001";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackTrustError {
    UnknownTrustRoot,
    InvalidEncoding,
    VerifyFailed,
}

#[derive(Clone, Debug)]
struct ExtPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

struct CurveParams {
    p: BigUint,
    l: BigUint,
    d: BigUint,
    two_d: BigUint,
    sqrt_m1: BigUint,
    base: ExtPoint,
}

fn field_add(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let s = a + b;
    if &s >= p { s - p } else { s }
}

fn field_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b { a - b } else { (a + p) - b }
}

fn field_mul(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a * b) % p
}

fn field_inv(a: &BigUint, p: &BigUint) -> BigUint {
    a.modpow(&(p - 2_u32), p)
}

fn curve() -> CurveParams {
    let one = BigUint::one();
    let p = (&one << 255_usize) - BigUint::from(19_u32);
    let l_tail = BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
        .expect("RFC 8032 L tail");
    let l = (&one << 252_usize) + l_tail;

    let c_num = field_sub(&p, &BigUint::from(121_665_u32), &p);
    let c_den = field_inv(&BigUint::from(121_666_u32), &p);
    let d = field_mul(&c_num, &c_den, &p);
    let two_d = field_add(&d, &d, &p);

    let exp_sqrt_m1 = (&p - 1_u32) >> 2_usize;
    let sqrt_m1 = BigUint::from(2_u32).modpow(&exp_sqrt_m1, &p);

    let by = field_mul(
        &BigUint::from(4_u32),
        &field_inv(&BigUint::from(5_u32), &p),
        &p,
    );
    let bx = recover_x(&by, false, &p, &d, &sqrt_m1).expect("RFC 8032 basepoint x");
    let bt = field_mul(&bx, &by, &p);
    let base = ExtPoint {
        x: bx,
        y: by,
        z: one,
        t: bt,
    };
    CurveParams {
        p,
        l,
        d,
        two_d,
        sqrt_m1,
        base,
    }
}

fn recover_x(
    y: &BigUint,
    sign_odd: bool,
    p: &BigUint,
    d: &BigUint,
    sqrt_m1: &BigUint,
) -> Option<BigUint> {
    if y >= p {
        return None;
    }
    let y2 = field_mul(y, y, p);
    let u = field_sub(&y2, &BigUint::one(), p);
    let v = field_add(&field_mul(d, &y2, p), &BigUint::one(), p);

    let v3 = field_mul(&field_mul(&v, &v, p), &v, p);
    let v7 = field_mul(&field_mul(&v3, &v3, p), &v, p);
    let uv7 = field_mul(&u, &v7, p);
    let exp = (p - 5_u32) >> 3_usize;
    let mut x = field_mul(&field_mul(&u, &v3, p), &uv7.modpow(&exp, p), p);

    let vx2 = field_mul(&v, &field_mul(&x, &x, p), p);
    if vx2 != u {
        let neg_u = field_sub(p, &u, p);
        if vx2 == neg_u {
            x = field_mul(&x, sqrt_m1, p);
        } else {
            return None;
        }
    }
    if x.is_zero() && sign_odd {
        return None;
    }
    let is_odd = x.bit(0);
    if is_odd != sign_odd {
        x = field_sub(p, &x, p);
    }
    Some(x)
}

fn identity_point() -> ExtPoint {
    ExtPoint {
        x: BigUint::zero(),
        y: BigUint::one(),
        z: BigUint::one(),
        t: BigUint::zero(),
    }
}

fn add_extended(p1: &ExtPoint, p2: &ExtPoint, cp: &CurveParams) -> ExtPoint {
    let p = &cp.p;
    let a = field_mul(&field_sub(&p1.y, &p1.x, p), &field_sub(&p2.y, &p2.x, p), p);
    let b = field_mul(&field_add(&p1.y, &p1.x, p), &field_add(&p2.y, &p2.x, p), p);
    let c = field_mul(&field_mul(&p1.t, &cp.two_d, p), &p2.t, p);
    let z1_2 = field_add(&p1.z, &p1.z, p);
    let d = field_mul(&z1_2, &p2.z, p);
    let e = field_sub(&b, &a, p);
    let f = field_sub(&d, &c, p);
    let g = field_add(&d, &c, p);
    let h = field_add(&b, &a, p);
    ExtPoint {
        x: field_mul(&e, &f, p),
        y: field_mul(&g, &h, p),
        z: field_mul(&f, &g, p),
        t: field_mul(&e, &h, p),
    }
}

fn scalar_mul(pt: &ExtPoint, scalar: &BigUint, cp: &CurveParams) -> ExtPoint {
    let mut acc = identity_point();
    let mut cur = pt.clone();
    let bits = scalar.bits();
    for i in 0..bits {
        if scalar.bit(i) {
            acc = add_extended(&acc, &cur, cp);
        }
        cur = add_extended(&cur, &cur, cp);
    }
    acc
}

fn to_le_32(n: &BigUint) -> [u8; 32] {
    let raw = n.to_bytes_le();
    let mut out = [0_u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}

fn encode_point(pt: &ExtPoint, cp: &CurveParams) -> [u8; 32] {
    let z_inv = field_inv(&pt.z, &cp.p);
    let x = field_mul(&pt.x, &z_inv, &cp.p);
    let y = field_mul(&pt.y, &z_inv, &cp.p);
    let mut bytes = to_le_32(&y);
    if x.bit(0) {
        bytes[31] |= 0x80;
    }
    bytes
}

fn decode_point(bytes: &[u8; 32], cp: &CurveParams) -> Option<ExtPoint> {
    let sign_odd = (bytes[31] & 0x80) != 0;
    let mut y_bytes = *bytes;
    y_bytes[31] &= 0x7f;
    let y = BigUint::from_bytes_le(&y_bytes);
    let x = recover_x(&y, sign_odd, &cp.p, &cp.d, &cp.sqrt_m1)?;
    let t = field_mul(&x, &y, &cp.p);
    Some(ExtPoint {
        x,
        y,
        z: BigUint::one(),
        t,
    })
}

/// Derives the 32-byte RFC 8032 Ed25519 verifying key from a 32-byte secret seed.
#[must_use]
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let cp = curve();
    let digest = Sha512::digest(seed);
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&digest[..32]);
    s_bytes[0] &= 248;
    s_bytes[31] &= 127;
    s_bytes[31] |= 64;
    let s = BigUint::from_bytes_le(&s_bytes);
    let a = scalar_mul(&cp.base, &s, &cp);
    encode_point(&a, &cp)
}

/// Computes a 64-byte deterministic RFC 8032 Ed25519 signature.
#[must_use]
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let cp = curve();
    let digest = Sha512::digest(seed);
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&digest[..32]);
    s_bytes[0] &= 248;
    s_bytes[31] &= 127;
    s_bytes[31] |= 64;
    let prefix = &digest[32..64];

    let s = BigUint::from_bytes_le(&s_bytes);
    let a_bytes = encode_point(&scalar_mul(&cp.base, &s, &cp), &cp);

    let mut r_hasher = Sha512::new();
    r_hasher.update(prefix);
    r_hasher.update(message);
    let r = BigUint::from_bytes_le(&r_hasher.finalize()) % &cp.l;
    let r_bytes = encode_point(&scalar_mul(&cp.base, &r, &cp), &cp);

    let mut k_hasher = Sha512::new();
    k_hasher.update(r_bytes);
    k_hasher.update(a_bytes);
    k_hasher.update(message);
    let k = BigUint::from_bytes_le(&k_hasher.finalize()) % &cp.l;

    let cap_s = (&r + (&k * &s)) % &cp.l;
    let cap_s_bytes = to_le_32(&cap_s);

    let mut sig = [0_u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&cap_s_bytes);
    sig
}

/// Verifies a 64-byte RFC 8032 Ed25519 signature (cofactored + strict canonical `y < p` & `S < L`).
pub fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), PackTrustError> {
    let cp = curve();
    let mut r_bytes = [0_u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    let cap_s = BigUint::from_bytes_le(&s_bytes);
    if cap_s >= cp.l {
        return Err(PackTrustError::VerifyFailed);
    }
    let a_pt = decode_point(public_key, &cp).ok_or(PackTrustError::InvalidEncoding)?;
    let r_pt = decode_point(&r_bytes, &cp).ok_or(PackTrustError::InvalidEncoding)?;

    let mut k_hasher = Sha512::new();
    k_hasher.update(r_bytes);
    k_hasher.update(public_key);
    k_hasher.update(message);
    let k = BigUint::from_bytes_le(&k_hasher.finalize()) % &cp.l;

    let eight = BigUint::from(8_u32);
    let lhs = scalar_mul(&cp.base, &(eight.clone() * cap_s), &cp);
    let rhs_r = scalar_mul(&r_pt, &eight, &cp);
    let rhs_ka = scalar_mul(&a_pt, &(eight * k), &cp);
    let rhs = add_extended(&rhs_r, &rhs_ka, &cp);

    if encode_point(&lhs, &cp) == encode_point(&rhs, &cp) {
        Ok(())
    } else {
        Err(PackTrustError::VerifyFailed)
    }
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Canonical length-prefixed domain-separated signing payload for `PackManifestV0` (`TA-06` /
/// `TA-28`). Binds `pack_id`, `version`, `pack_epoch`, `content_digest_hex`, `rights_uri`,
/// `sbom_ref`, `runtime_requirements`, and `benchmark_links` without delimiter ambiguity.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn pack_signing_payload(
    pack_id: &str,
    version: &str,
    pack_epoch: u64,
    content_digest_hex: &str,
    rights_uri: &str,
    sbom_ref: &str,
    runtime_requirements: &str,
    benchmark_links: &[String],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SAFEVD/PACK/MANIFEST/v0");
    append_len_prefixed(&mut out, pack_id.as_bytes());
    append_len_prefixed(&mut out, version.as_bytes());
    out.extend_from_slice(&pack_epoch.to_be_bytes());
    let digest_norm = content_digest_hex.trim().to_ascii_lowercase();
    append_len_prefixed(&mut out, digest_norm.as_bytes());
    append_len_prefixed(&mut out, rights_uri.as_bytes());
    append_len_prefixed(&mut out, sbom_ref.as_bytes());
    append_len_prefixed(&mut out, runtime_requirements.as_bytes());
    out.extend_from_slice(&(benchmark_links.len() as u64).to_be_bytes());
    for link in benchmark_links {
        append_len_prefixed(&mut out, link.as_bytes());
    }
    out
}

/// Signs `payload` with the synthetic pack trust seed (for synthetic tests and local research fixtures).
#[must_use]
pub fn sign_pack_payload(payload: &[u8]) -> String {
    hex::encode(ed25519_sign(&SYNTHETIC_PACK_SEED, payload))
}

/// Verifies `signature_hex` against `trust_root_id` and `payload`.
pub fn verify_pack_signature(
    trust_root_id: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), PackTrustError> {
    if trust_root_id != SYNTHETIC_PACK_TRUST_ROOT_ID {
        return Err(PackTrustError::UnknownTrustRoot);
    }
    if signature_hex.len() != 128
        || !signature_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(PackTrustError::InvalidEncoding);
    }
    let raw = hex::decode(signature_hex).map_err(|_| PackTrustError::InvalidEncoding)?;
    let sig: [u8; 64] = raw
        .try_into()
        .map_err(|_| PackTrustError::InvalidEncoding)?;
    let pk = ed25519_public_key(&SYNTHETIC_PACK_SEED);
    ed25519_verify(&pk, payload, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_official_test_vectors_1_and_2() {
        // RFC 8032 §7.1 TEST 1 (empty message)
        let sk1: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_pk1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let expected_sig1 = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        let pk1 = ed25519_public_key(&sk1);
        assert_eq!(hex::encode(pk1), expected_pk1);
        let sig1 = ed25519_sign(&sk1, b"");
        assert_eq!(hex::encode(sig1), expected_sig1);
        assert_eq!(ed25519_verify(&pk1, b"", &sig1), Ok(()));
        assert_eq!(
            ed25519_verify(&pk1, b"x", &sig1),
            Err(PackTrustError::VerifyFailed)
        );

        // RFC 8032 §7.1 TEST 2 (1-byte message 0x72)
        let sk2: [u8; 32] =
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_pk2 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        let expected_sig2 = concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        let pk2 = ed25519_public_key(&sk2);
        assert_eq!(hex::encode(pk2), expected_pk2);
        let sig2 = ed25519_sign(&sk2, &[0x72]);
        assert_eq!(hex::encode(sig2), expected_sig2);
        assert_eq!(ed25519_verify(&pk2, &[0x72], &sig2), Ok(()));
    }
}
