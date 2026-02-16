//! Builder for STAS v2 locking scripts.

use bsv_script::Address;
use bsv_script::Script;

use crate::error::TokenError;

/// The full STAS v2 template (1431 bytes) with zero placeholders for owner (bytes 3..23)
/// and redemption PKH (bytes 1411..1431).
const STAS_V2_TEMPLATE_HEX: &str = concat!(
    "76a914", "0000000000000000000000000000000000000000",
    "88ac6976aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
    "7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
    "01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00",
    "7d976e7c5296a06394677768827601249301307c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027e7c7e7c",
    "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
    "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
    "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
    "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
    "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
    "01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad",
    "547f7701207f01207f7701247f517f7801007e8102fd00a063546752687f7801007e817f727e7b01177f777b557a766471567a577a786354807e7e676d68",
    "aa880067765158a569765187645294567a5379587a7e7e78637c8c7c53797e577a7e6878637c8c7c53797e577a7e6878637c8c7c53797e577a7e68",
    "78637c8c7c53797e577a7e6878637c8c7c53797e577a7e6867567a6876aa587a7d54807e577a597a5a7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa",
    "587a7d877663516752687c72879b69537a647500687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81",
    "6854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e81",
    "7602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e81",
    "7602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81",
    "687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e81",
    "7602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75537f7c0376a9148801147f775379645579887567726881766968789263556753687a76",
    "026c057f7701147f8263517f7c766301007e817f7c6775006877686b537992635379528763547a6b547a6b677c6b567a6b537a7c717c71716868",
    "547a587f7c81547a557964936755795187637c686b687c547f7701207f75748c7a7669765880748c7a76567a876457790376a9147e7c7e557967",
    "041976a9147c7e0288ac687e7e5579636c766976748c7a9d58807e6c0376a9147e748c7a7e6c7e7e676c766b8263828c007c80517e846864745aa063",
    "7c748c7a76697d937b7b58807e56790376a9147e748c7a7e55797e7e6868686c567a5187637500678263828c007c80517e846868647459a063",
    "7c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e687459a0637c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e",
    "68687c537a9d547963557958807e041976a91455797e0288ac7e7e68aa87726d77776a14",
    "0000000000000000000000000000000000000000"
);

/// Build a STAS v2 locking script.
///
/// The script locks tokens to `owner` with redemption rights held by the
/// address whose PKH matches `redemption_pkh`.
///
/// # Arguments
/// * `owner` - The address that owns (can spend) the token
/// * `redemption_pkh` - The 20-byte public key hash for redemption
/// * `splittable` - Whether the token can be split
pub fn build_stas_locking_script(
    owner: &Address,
    redemption_pkh: &[u8; 20],
    splittable: bool,
) -> Result<Script, TokenError> {
    let mut script = hex::decode(STAS_V2_TEMPLATE_HEX)
        .map_err(|e| TokenError::InvalidScript(format!("template decode error: {e}")))?;

    debug_assert_eq!(script.len(), 1431, "STAS v2 template must be 1431 bytes");

    // Patch owner PKH at bytes 3..23
    script[3..23].copy_from_slice(&owner.public_key_hash);

    // Patch redemption PKH at bytes 1411..1431
    script[1411..1431].copy_from_slice(redemption_pkh);

    // Append flags: OP_DATA_1 + flags byte
    let flags_byte = if splittable { 0x00 } else { 0x01 };
    script.push(0x01); // OP_DATA_1
    script.push(flags_byte);

    Ok(Script::from_bytes(&script))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::reader::read_locking_script;
    use crate::ScriptType;
    use bsv_script::Address;

    fn test_address(pkh: [u8; 20]) -> Address {
        Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet)
    }

    #[test]
    fn build_and_read_roundtrip_splittable() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let script = build_stas_locking_script(&owner, &redemption_pkh, true).unwrap();
        let parsed = read_locking_script(script.to_bytes());

        assert_eq!(parsed.script_type, ScriptType::Stas);
        let stas = parsed.stas.unwrap();
        assert_eq!(stas.owner_hash, owner_pkh);
        assert_eq!(stas.redemption_hash, redemption_pkh);
        assert_eq!(stas.flags, vec![0x00]);
    }

    #[test]
    fn build_and_read_roundtrip_non_splittable() {
        let owner_pkh = [0xcc; 20];
        let redemption_pkh = [0xdd; 20];
        let owner = test_address(owner_pkh);

        let script = build_stas_locking_script(&owner, &redemption_pkh, false).unwrap();
        let parsed = read_locking_script(script.to_bytes());

        assert_eq!(parsed.script_type, ScriptType::Stas);
        let stas = parsed.stas.unwrap();
        assert_eq!(stas.owner_hash, owner_pkh);
        assert_eq!(stas.redemption_hash, redemption_pkh);
        assert_eq!(stas.flags, vec![0x01]);
    }

    #[test]
    fn build_preserves_token_id() {
        let owner_pkh = [0x11; 20];
        let redemption_pkh = [0x22; 20];
        let owner = test_address(owner_pkh);

        let script = build_stas_locking_script(&owner, &redemption_pkh, true).unwrap();
        let parsed = read_locking_script(script.to_bytes());

        let stas = parsed.stas.unwrap();
        assert_eq!(stas.token_id.public_key_hash(), &redemption_pkh);
    }
}
