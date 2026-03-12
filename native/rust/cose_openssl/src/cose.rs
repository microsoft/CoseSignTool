use crate::cbor::CborValue;
use crate::ossl_wrappers::{
    EvpKey, KeyType, WhichEC, ecdsa_der_to_fixed, ecdsa_fixed_to_der,
};

#[cfg(feature = "pqc")]
use crate::ossl_wrappers::WhichMLDSA;

const COSE_SIGN1_TAG: u64 = 18;
const COSE_HEADER_ALG: i64 = 1;
const SIG_STRUCTURE1_CONTEXT: &str = "Signature1";
const CBOR_SIMPLE_VALUE_NULL: u8 = 22;

/// Return the COSE algorithm identifier for a given key.
/// https://www.iana.org/assignments/cose/cose.xhtml
fn cose_alg(key: &EvpKey) -> Result<i64, String> {
    match &key.typ {
        KeyType::EC(WhichEC::P256) => Ok(-7),
        KeyType::EC(WhichEC::P384) => Ok(-35),
        KeyType::EC(WhichEC::P521) => Ok(-36),
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(which) => match which {
            WhichMLDSA::P44 => Ok(-48),
            WhichMLDSA::P65 => Ok(-49),
            WhichMLDSA::P87 => Ok(-50),
        },
    }
}

/// Parse a COSE_Sign1 envelope and return (phdr_bytes, payload, signature).
fn parse_cose_sign1(
    envelope: &[u8],
) -> Result<(Vec<u8>, CborValue, CborValue), String> {
    let parsed = CborValue::from_bytes(envelope)?;

    let inner = match parsed {
        CborValue::Tagged { tag, payload } if tag == COSE_SIGN1_TAG => *payload,
        CborValue::Tagged { tag, .. } => {
            return Err(format!(
                "Wrong COSE tag: expected {COSE_SIGN1_TAG}, got {tag}"
            ));
        }
        _ => return Err("Expected COSE_Sign1 tagged item".to_string()),
    };

    let items = match inner {
        CborValue::Array(items) => items,
        _ => {
            return Err("Expected COSE_Sign1 array inside tag".to_string());
        }
    };

    if items.len() != 4 {
        return Err("COSE_Sign1 array length is not 4".to_string());
    }

    let mut items = items.into_iter();
    let phdr = items.next().unwrap();
    let _uhdr = items.next().unwrap();
    let payload = items.next().unwrap();
    let signature = items.next().unwrap();

    let phdr_bytes = match phdr {
        CborValue::ByteString(b) => b,
        _ => {
            return Err("Protected header is not a byte string".to_string());
        }
    };

    Ok((phdr_bytes, payload, signature))
}

/// Insert alg(1) into a CborValue map, return error if already exists.
fn insert_alg_value(
    key: &EvpKey,
    phdr: CborValue,
) -> Result<CborValue, String> {
    let mut entries = match phdr {
        CborValue::Map(entries) => entries,
        _ => {
            return Err("Protected header is not a CBOR map".to_string());
        }
    };

    let alg_key = CborValue::Int(COSE_HEADER_ALG);
    if entries.iter().any(|(k, _)| k == &alg_key) {
        return Err("Algorithm already set in protected header".to_string());
    }

    let alg_val = CborValue::Int(cose_alg(key)?);
    entries.insert(0, (alg_key, alg_val));

    Ok(CborValue::Map(entries))
}

/// To-be-signed (TBS).
/// https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4.
fn sig_structure(phdr: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    CborValue::Array(vec![
        CborValue::TextString(SIG_STRUCTURE1_CONTEXT.to_string()),
        CborValue::ByteString(phdr.to_vec()),
        CborValue::ByteString(vec![]),
        CborValue::ByteString(payload.to_vec()),
    ])
    .to_bytes()
}

/// Produce a COSE_Sign1 envelope from CborValue headers.
pub fn cose_sign1(
    key: &EvpKey,
    phdr: CborValue,
    uhdr: CborValue,
    payload: &[u8],
    detached: bool,
) -> Result<Vec<u8>, String> {
    let phdr_with_alg = insert_alg_value(key, phdr)?;
    let phdr_bytes = phdr_with_alg.to_bytes()?;
    let tbs = sig_structure(&phdr_bytes, payload)?;
    let sig = crate::sign::sign(key, &tbs)?;

    let sig = match &key.typ {
        KeyType::EC(_) => ecdsa_der_to_fixed(&sig, key.ec_field_size()?)?,
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(_) => sig,
    };

    let payload_item = if detached {
        CborValue::Simple(CBOR_SIMPLE_VALUE_NULL)
    } else {
        CborValue::ByteString(payload.to_vec())
    };

    let envelope = CborValue::Tagged {
        tag: COSE_SIGN1_TAG,
        payload: Box::new(CborValue::Array(vec![
            CborValue::ByteString(phdr_bytes),
            uhdr,
            payload_item,
            CborValue::ByteString(sig),
        ])),
    };

    envelope.to_bytes()
}

/// Produce a COSE_Sign1 envelope from pre-encoded CBOR bytes.
pub fn cose_sign1_encoded(
    key: &EvpKey,
    phdr: &[u8],
    uhdr: &[u8],
    payload: &[u8],
    detached: bool,
) -> Result<Vec<u8>, String> {
    let phdr_value = CborValue::from_bytes(phdr)?;
    let uhdr_value = CborValue::from_bytes(uhdr)?;
    cose_sign1(key, phdr_value, uhdr_value, payload, detached)
}

/// Check that the algorithm encoded in the phdr matches the key type.
fn check_phdr_alg(key: &EvpKey, phdr_bytes: &[u8]) -> Result<(), String> {
    let parsed = CborValue::from_bytes(phdr_bytes)?;

    let alg = parsed
        .map_at_int(COSE_HEADER_ALG)
        .map_err(|_| "Algorithm not found in protected header".to_string())?;

    let expected = cose_alg(key)?;
    match alg {
        CborValue::Int(v) if *v == expected => Ok(()),
        CborValue::Int(_) => {
            Err("Algorithm mismatch between protected header and key"
                .to_string())
        }
        _ => {
            Err("Algorithm value in protected header is not an integer"
                .to_string())
        }
    }
}

/// Verify a COSE_Sign1 envelope. If `payload` is `Some`, it is used
/// as the detached payload; otherwise the embedded payload is used.
pub fn cose_verify1(
    key: &EvpKey,
    envelope: &[u8],
    payload: Option<&[u8]>,
) -> Result<bool, String> {
    let (phdr_bytes, cose_payload, cose_sig) = parse_cose_sign1(envelope)?;

    check_phdr_alg(key, &phdr_bytes)?;

    let actual_payload = match payload {
        Some(p) => p.to_vec(),
        None => match cose_payload {
            CborValue::ByteString(b) => b,
            _ => {
                return Err("Embedded payload is not a byte string".to_string());
            }
        },
    };

    let sig = match cose_sig {
        CborValue::ByteString(b) => b,
        _ => return Err("Signature is not a byte string".to_string()),
    };

    let sig = match &key.typ {
        KeyType::EC(_) => ecdsa_fixed_to_der(&sig, key.ec_field_size()?)?,
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(_) => sig,
    };

    let tbs = sig_structure(&phdr_bytes, &actual_payload)?;
    crate::verify::verify(key, &sig, &tbs)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex string");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const TEST_PHDR: &str = "A319018B020FA3061A698B72820173736572766963652E6578616D706C652E636F6D02706C65646765722E7369676E6174757265666363662E7631A1647478696465322E313334";

    #[test]
    fn test_parse_cose() {
        let in_str = "d284588da50138220458406661363331386532666561643537313035326231383230393236653865653531313030623630633161383239393362333031353133383561623334343237303019018b020fa3061a698b72820173736572766963652e6578616d706c652e636f6d02706c65646765722e7369676e6174757265666363662e7631a1647478696465322e313334a119018ca12081590100a2018358204208b5b5378c253f49641ab2edb58b557c75cdbb85ae9327930362c84ebba694784963653a322e3133333a3066646666336265663338346237383231316363336434306463363333663336383364353963643930303864613037653030623266356464323734613365633758200000000000000000000000000000000000000000000000000000000000000000028382f5582081980abb4e161b2f3d306c185ef9f7ce84cf5a3b0c8978da82e049d761adfd0082f55820610e8b89721667f99305e7ce4befe0b3b393821a3f72713f89961ebc7e81de6382f55820cbe0d3307b00aa9f324e29c8fb26508404af81044c7adcd4f5b41043d92aff23f6586005784bfccce87452a35a0cd14df5ed8a38c8937f63fb6b522fb94a1551c0e061893bb35fba1fa6fea322b080a14c0894c3864bf4e76df04ffb0f7c350366f91c0d522652d8fa3ebad6ba0270b48e43a065312c759d8bc9a413d4270d5ba86182";
        let v = hex_decode(in_str);
        let (_phdr, _payload, _sig) = parse_cose_sign1(&v).unwrap();
    }

    #[test]
    fn test_insert_alg() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let phdr_with_alg = insert_alg_value(&key, phdr).unwrap();

        // Verify alg is present.
        let alg = phdr_with_alg.map_at_int(COSE_HEADER_ALG).unwrap();
        assert_eq!(alg, &CborValue::Int(cose_alg(&key).unwrap()));

        // Inserting again must fail.
        assert!(insert_alg_value(&key, phdr_with_alg).is_err());
    }

    fn sign_verify_cose_encoded(key_type: KeyType) {
        let key = EvpKey::new(key_type).unwrap();
        let phdr = hex_decode(TEST_PHDR);
        let uhdr = b"\xa0"; // empty map
        let payload = b"Good boy...";

        let envelope =
            cose_sign1_encoded(&key, &phdr, uhdr, payload, false).unwrap();
        assert!(cose_verify1(&key, &envelope, None).unwrap());
    }

    fn sign_verify_cose(key_type: KeyType) {
        let key = EvpKey::new(key_type).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]); // empty map
        let payload = b"Good boy...";

        let envelope = cose_sign1(&key, phdr, uhdr, payload, false).unwrap();
        assert!(cose_verify1(&key, &envelope, None).unwrap());
    }

    #[test]
    fn cose_ec_p256() {
        sign_verify_cose(KeyType::EC(WhichEC::P256));
    }

    #[test]
    fn cose_ec_p384() {
        sign_verify_cose(KeyType::EC(WhichEC::P384));
    }

    #[test]
    fn cose_ec_p521() {
        sign_verify_cose(KeyType::EC(WhichEC::P521));
    }

    #[test]
    fn cose_encoded_ec_p256() {
        sign_verify_cose_encoded(KeyType::EC(WhichEC::P256));
    }

    #[test]
    fn cose_encoded_ec_p384() {
        sign_verify_cose_encoded(KeyType::EC(WhichEC::P384));
    }

    #[test]
    fn cose_encoded_ec_p521() {
        sign_verify_cose_encoded(KeyType::EC(WhichEC::P521));
    }

    #[test]
    fn cose_detached_payload() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"Good boy...";

        let envelope = cose_sign1(&key, phdr, uhdr, payload, true).unwrap();

        // Verify with the detached payload supplied externally.
        assert!(cose_verify1(&key, &envelope, Some(payload)).unwrap());

        // Verify without supplying the payload must fail.
        assert!(cose_verify1(&key, &envelope, None).is_err());
    }

    #[test]
    fn cose_detached_payload_encoded() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr = hex_decode(TEST_PHDR);
        let uhdr = b"\xa0"; // empty map
        let payload = b"Good boy...";

        let envelope =
            cose_sign1_encoded(&key, &phdr, uhdr, payload, true).unwrap();

        // Verify with the detached payload supplied externally.
        assert!(cose_verify1(&key, &envelope, Some(payload)).unwrap());

        // Verify without supplying the payload must fail.
        assert!(cose_verify1(&key, &envelope, None).is_err());
    }

    #[test]
    fn cose_with_der_imported_key() {
        // Create key pair
        let original_key = EvpKey::new(KeyType::EC(WhichEC::P384)).unwrap();

        // Export private key to DER and reimport for signing
        let priv_der = original_key.to_der_private().unwrap();
        let signing_key = EvpKey::from_der_private(&priv_der).unwrap();

        // Export public key DER and reimport for verification
        let pub_der = original_key.to_der_public().unwrap();
        let verification_key = EvpKey::from_der_public(&pub_der).unwrap();

        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"test with DER-imported key";

        // Sign with DER-reimported private key
        let envelope =
            cose_sign1(&signing_key, phdr, uhdr, payload, false).unwrap();

        // Verify with DER-imported public key
        assert!(cose_verify1(&verification_key, &envelope, None).unwrap());
    }

    #[cfg(feature = "pqc")]
    mod pqc_tests {
        use super::*;
        #[test]
        fn cose_mldsa44() {
            sign_verify_cose(KeyType::MLDSA(WhichMLDSA::P44));
        }
        #[test]
        fn cose_mldsa65() {
            sign_verify_cose(KeyType::MLDSA(WhichMLDSA::P65));
        }
        #[test]
        fn cose_mldsa87() {
            sign_verify_cose(KeyType::MLDSA(WhichMLDSA::P87));
        }

        #[test]
        fn cose_mldsa_with_der_imported_key() {
            // Create ML-DSA key pair
            let original_key =
                EvpKey::new(KeyType::MLDSA(WhichMLDSA::P65)).unwrap();

            // Export private key to DER and reimport for signing
            let priv_der = original_key.to_der_private().unwrap();
            let signing_key = EvpKey::from_der_private(&priv_der).unwrap();

            // Export public key DER and reimport for verification
            let pub_der = original_key.to_der_public().unwrap();
            let verification_key = EvpKey::from_der_public(&pub_der).unwrap();

            let phdr_bytes = hex_decode(TEST_PHDR);
            let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
            let uhdr = CborValue::Map(vec![]);
            let payload = b"ML-DSA with DER-imported key";

            // Sign with DER-reimported private key
            let envelope =
                cose_sign1(&signing_key, phdr, uhdr, payload, false).unwrap();

            // Verify with DER-imported public key
            assert!(cose_verify1(&verification_key, &envelope, None).unwrap());
        }
    }
}
