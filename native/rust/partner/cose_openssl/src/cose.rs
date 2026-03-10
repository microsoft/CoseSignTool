use crate::ossl_wrappers::{
    EvpKey, KeyType, WhichEC, ecdsa_der_to_fixed, ecdsa_fixed_to_der,
};
use cborrs_nondet::cbornondet::*;

#[cfg(feature = "pqc")]
use crate::ossl_wrappers::WhichMLDSA;

const COSE_SIGN1_TAG: u64 = 18;
const COSE_HEADER_ALG: u64 = 1;
const SIG_STRUCTURE1_CONTEXT: &str = "Signature1";
const CBOR_SIMPLE_VALUE_NULL: u8 = 22;

fn cbor_serialize(item: CborNondet) -> Result<Vec<u8>, String> {
    let sz = cbor_nondet_size(item, usize::MAX)
        .ok_or("Failed to estimate CBOR serialization size")?;
    let mut buf = vec![0u8; sz];

    let written = cbor_nondet_serialize(item, &mut buf)
        .ok_or("Failed to serialize CBOR item")?;

    if sz != written {
        return Err(format!(
            "Failed to serialize CBOR, written {written} != expected {sz}"
        ));
    }

    Ok(buf)
}

fn cose_alg(key: &EvpKey) -> Result<(CborNondetIntKind, u64), String> {
    // EverCBOR starts counting negs from -1, so Neg 7 is -8, for instance.
    // Therefore, substract 1 from the absolute value before convertion.
    //
    // https://www.iana.org/assignments/cose/cose.xhtml
    match &key.typ {
        KeyType::EC(WhichEC::P256) => Ok((CborNondetIntKind::NegInt64, 7 - 1)),
        KeyType::EC(WhichEC::P384) => Ok((CborNondetIntKind::NegInt64, 35 - 1)),
        KeyType::EC(WhichEC::P521) => Ok((CborNondetIntKind::NegInt64, 36 - 1)),
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(which) => match which {
            WhichMLDSA::P44 => Ok((CborNondetIntKind::NegInt64, 48 - 1)),
            WhichMLDSA::P65 => Ok((CborNondetIntKind::NegInt64, 49 - 1)),
            WhichMLDSA::P87 => Ok((CborNondetIntKind::NegInt64, 50 - 1)),
        },
    }
}

/// Parse a COSE_Sign1 envelope and return (phdr, payload, signature).
fn parse_cose_sign1<'a>(
    envelope: &'a [u8],
) -> Result<(CborNondet<'a>, CborNondet<'a>, CborNondet<'a>), String> {
    let (tag, _) = cbor_nondet_parse(None, false, envelope)
        .ok_or("Failed to parse COSE envelope")?;

    let rest = match cbor_nondet_destruct(tag) {
        CborNondetView::Tagged { tag, payload } if tag == COSE_SIGN1_TAG => {
            Ok(payload)
        }
        CborNondetView::Tagged { tag, .. } => Err(format!(
            "Wrong COSE tag: expected {COSE_SIGN1_TAG}, got {tag}"
        )),
        _ => Err("Expected COSE_Sign1 tagged item".to_string()),
    }?;

    let arr = match cbor_nondet_destruct(rest) {
        CborNondetView::Array { _0 } => Ok(_0),
        _ => Err("Expected COSE_Sign1 array inside tag".to_string()),
    }?;

    if cbor_nondet_get_array_length(arr) != 4 {
        return Err("COSE_Sign1 array length is not 4".to_string());
    }

    let phdr = cbor_nondet_get_array_item(arr, 0)
        .ok_or("Failed to get protected header from COSE array")?;
    let payload = cbor_nondet_get_array_item(arr, 2)
        .ok_or("Failed to get payload from COSE array")?;
    let signature = cbor_nondet_get_array_item(arr, 3)
        .ok_or("Failed to get signature from COSE array")?;

    Ok((phdr, payload, signature))
}

/// Insert alg(1), return error if already exists.
fn insert_alg(key: &EvpKey, phdr: &[u8]) -> Result<Vec<u8>, String> {
    let (parsed, _) = cbor_nondet_parse(None, false, phdr)
        .ok_or("Failed to parse protected header map")?;

    let entries = match cbor_nondet_destruct(parsed) {
        CborNondetView::Map { _0 } => Ok(_0),
        _ => Err("Protected header is not a CBOR map".to_string()),
    }?;

    let alg_label =
        cbor_nondet_mk_int64(CborNondetIntKind::UInt64, COSE_HEADER_ALG);
    if cbor_nondet_map_get(entries, alg_label).is_some() {
        return Err("Algorithm already set in protected header".to_string());
    }

    // Insert alg(1) to the beginning.
    let (kind, val) = cose_alg(key)?;
    let mut map = Vec::<CborNondetMapEntry>::new();
    map.push(cbor_nondet_mk_map_entry(
        cbor_nondet_mk_int64(CborNondetIntKind::UInt64, COSE_HEADER_ALG),
        cbor_nondet_mk_int64(kind, val),
    ));

    for entry in entries {
        map.push(entry);
    }

    let map = cbor_nondet_mk_map(&mut map)
        .ok_or("Failed to build protected header map")?;

    cbor_serialize(map)
}

/// To-be-signed (TBS).
/// https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4.
fn sig_structure(phdr: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let items = [
        cbor_nondet_mk_text_string(SIG_STRUCTURE1_CONTEXT)
            .ok_or("Failed to make Sig_structure context string")?,
        cbor_nondet_mk_byte_string(phdr)
            .ok_or("Failed to make protected header byte string")?,
        cbor_nondet_mk_byte_string(&[])
            .ok_or("Failed to make external AAD byte string")?,
        cbor_nondet_mk_byte_string(payload)
            .ok_or("Failed to make payload byte string")?,
    ];
    let arr =
        cbor_nondet_mk_array(&items).ok_or("Failed to build TBS array")?;

    cbor_serialize(arr)
}

/// Produce a COSE_Sign1 envelope.
pub fn cose_sign1(
    key: &EvpKey,
    phdr: &[u8],
    uhdr: &[u8],
    payload: &[u8],
    detached: bool,
) -> Result<Vec<u8>, String> {
    let phdr_bytes = insert_alg(key, phdr)?;
    let tbs = sig_structure(&phdr_bytes, payload)?;
    let sig = crate::sign::sign(key, &tbs)?;

    let sig = match &key.typ {
        KeyType::EC(_) => ecdsa_der_to_fixed(&sig, key.ec_field_size()?)?,
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(_) => sig,
    };

    let payload_item = if detached {
        cbor_nondet_mk_simple_value(CBOR_SIMPLE_VALUE_NULL)
            .ok_or("Failed to make CBOR null for detached payload")?
    } else {
        cbor_nondet_mk_byte_string(payload)
            .ok_or("Failed to make payload byte string")?
    };

    // Parse uhdr so we can embed it as-is.
    let (uhdr_item, _) = cbor_nondet_parse(None, false, uhdr)
        .ok_or("Failed to parse unprotected header")?;

    let arr = [
        cbor_nondet_mk_byte_string(&phdr_bytes)
            .ok_or("Failed to make protected header byte string")?,
        uhdr_item,
        payload_item,
        cbor_nondet_mk_byte_string(&sig)
            .ok_or("Failed to make signature byte string")?,
    ];

    let inner =
        cbor_nondet_mk_array(&arr).ok_or("Failed to build COSE_Sign1 array")?;
    let tagged = cbor_nondet_mk_tagged(COSE_SIGN1_TAG, &inner);

    cbor_serialize(tagged)
}

/// Check that the algorithm encoded in the phdr matches the key type.
fn check_phdr_alg(key: &EvpKey, phdr_bytes: &[u8]) -> Result<(), String> {
    let (parsed, _) = cbor_nondet_parse(None, false, phdr_bytes)
        .ok_or("Failed to parse protected header for algorithm check")?;
    let entries = match cbor_nondet_destruct(parsed) {
        CborNondetView::Map { _0 } => Ok(_0),
        _ => Err("Protected header is not a CBOR map".to_string()),
    }?;

    let alg_label =
        cbor_nondet_mk_int64(CborNondetIntKind::UInt64, COSE_HEADER_ALG);
    let alg_item = cbor_nondet_map_get(entries, alg_label)
        .ok_or("Algorithm not found in protected header")?;

    let (phdr_kind, phdr_val) =
        match cbor_nondet_destruct(alg_item) {
            CborNondetView::Int64 { kind, value } => Ok((kind, value)),
            _ => Err("Algorithm value in protected header is not an integer"
                .to_string()),
        }?;

    let (key_kind, key_val) = cose_alg(key)?;
    if phdr_kind != key_kind || phdr_val != key_val {
        return Err(
            "Algorithm mismatch between protected header and key".to_string()
        );
    }
    Ok(())
}

/// Verify a COSE_Sign1 envelope. If `payload` is `Some`, it is used
/// as the detached payload; otherwise the embedded payload is used.
pub fn cose_verify1(
    key: &EvpKey,
    envelope: &[u8],
    payload: Option<&[u8]>,
) -> Result<bool, String> {
    let (cose_phdr, cose_payload, cose_sig) = parse_cose_sign1(envelope)?;

    let phdr_bytes = match cbor_nondet_destruct(cose_phdr) {
        CborNondetView::ByteString { payload } => Ok(payload.to_vec()),
        _ => Err("Protected header is not a byte string".to_string()),
    }?;

    check_phdr_alg(key, &phdr_bytes)?;

    let actual_payload = match payload {
        Some(p) => p.to_vec(),
        None => match cbor_nondet_destruct(cose_payload) {
            CborNondetView::ByteString { payload } => Ok(payload.to_vec()),
            _ => Err("Embedded payload is not a byte string".to_string()),
        }?,
    };

    let sig = match cbor_nondet_destruct(cose_sig) {
        CborNondetView::ByteString { payload } => Ok(payload.to_vec()),
        _ => Err("Signature is not a byte string".to_string()),
    }?;

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
    use hex;

    const TEST_PHDR: &str = "A319018B020FA3061A698B72820173736572766963652E6578616D706C652E636F6D02706C65646765722E7369676E6174757265666363662E7631A1647478696465322E313334";

    #[test]
    fn test_parse_cose() {
        let in_str = "d284588da50138220458406661363331386532666561643537313035326231383230393236653865653531313030623630633161383239393362333031353133383561623334343237303019018b020fa3061a698b72820173736572766963652e6578616d706c652e636f6d02706c65646765722e7369676e6174757265666363662e7631a1647478696465322e313334a119018ca12081590100a2018358204208b5b5378c253f49641ab2edb58b557c75cdbb85ae9327930362c84ebba694784963653a322e3133333a3066646666336265663338346237383231316363336434306463363333663336383364353963643930303864613037653030623266356464323734613365633758200000000000000000000000000000000000000000000000000000000000000000028382f5582081980abb4e161b2f3d306c185ef9f7ce84cf5a3b0c8978da82e049d761adfd0082f55820610e8b89721667f99305e7ce4befe0b3b393821a3f72713f89961ebc7e81de6382f55820cbe0d3307b00aa9f324e29c8fb26508404af81044c7adcd4f5b41043d92aff23f6586005784bfccce87452a35a0cd14df5ed8a38c8937f63fb6b522fb94a1551c0e061893bb35fba1fa6fea322b080a14c0894c3864bf4e76df04ffb0f7c350366f91c0d522652d8fa3ebad6ba0270b48e43a065312c759d8bc9a413d4270d5ba86182";
        let v = hex::decode(in_str).unwrap();
        let (_phdr, _payload, _sig) = parse_cose_sign1(&v).unwrap();
    }

    #[test]
    fn test_insert_alg() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr = hex::decode(TEST_PHDR).unwrap();
        let phdr = insert_alg(&key, &phdr).unwrap();

        // Parse result and verify alg is present.
        let (parsed, _) = cbor_nondet_parse(None, false, &phdr).unwrap();
        let entries = match cbor_nondet_destruct(parsed) {
            CborNondetView::Map { _0 } => _0,
            _ => panic!("Expected map"),
        };

        // Check alg.
        let alg_label =
            cbor_nondet_mk_int64(CborNondetIntKind::UInt64, COSE_HEADER_ALG);
        let alg_item = cbor_nondet_map_get(entries, alg_label)
            .expect("Algorithm not found in protected header");
        let (kind, val) = match cbor_nondet_destruct(alg_item) {
            CborNondetView::Int64 { kind, value } => (kind, value),
            _ => panic!("Algorithm value is not an integer"),
        };
        let (expected_kind, expected_val) = cose_alg(&key).unwrap();
        assert!(kind == expected_kind);
        assert!(val == expected_val);

        // Inserting again must fail.
        assert!(insert_alg(&key, &phdr).is_err());
    }

    fn sign_verify_cose(key_type: KeyType) {
        let key = EvpKey::new(key_type).unwrap();
        let phdr = hex::decode(TEST_PHDR).unwrap();
        let uhdr = b"\xa0"; // empty map
        let payload = b"Good boy...";

        let envelope = cose_sign1(&key, &phdr, uhdr, payload, false).unwrap();
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
    fn cose_detached_payload() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr = hex::decode(TEST_PHDR).unwrap();
        let uhdr = b"\xa0"; // empty map
        let payload = b"Good boy...";

        let envelope = cose_sign1(&key, &phdr, uhdr, payload, true).unwrap();

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

        let phdr = hex::decode(TEST_PHDR).unwrap();
        let uhdr = b"\xa0";
        let payload = b"test with DER-imported key";

        // Sign with DER-reimported private key
        let envelope =
            cose_sign1(&signing_key, &phdr, uhdr, payload, false).unwrap();

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

            let phdr = hex::decode(TEST_PHDR).unwrap();
            let uhdr = b"\xa0";
            let payload = b"ML-DSA with DER-imported key";

            // Sign with DER-reimported private key
            let envelope =
                cose_sign1(&signing_key, &phdr, uhdr, payload, false).unwrap();

            // Verify with DER-imported public key
            assert!(cose_verify1(&verification_key, &envelope, None).unwrap());
        }
    }
}
