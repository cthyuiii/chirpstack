use aes::{Aes256, cipher::KeyInit};
use anyhow::Result;
use cmac::{Cmac, Mac};

use crate::{AES256Key, EUI64, NetID};

/// For LoRaWAN 1.0: SNwkSIntKey = NwkSEncKey = FNwkSIntKey = NwkSKey
pub fn get_f_nwk_s_int_key(
    opt_neg: bool,
    nwk_key: &AES256Key,
    net_id: &NetID,
    join_eui: &EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<AES256Key> {
    get_s_key(
        opt_neg, 0x01, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

pub fn get_app_s_key(
    opt_neg: bool,
    nwk_key: &AES256Key,
    net_id: &NetID,
    join_eui: &EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<AES256Key> {
    get_s_key(
        opt_neg, 0x02, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

pub fn get_s_nwk_s_int_key(
    opt_neg: bool,
    nwk_key: &AES256Key,
    net_id: &NetID,
    join_eui: &EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<AES256Key> {
    get_s_key(
        opt_neg, 0x03, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

pub fn get_nwk_s_enc_key(
    opt_neg: bool,
    nwk_key: &AES256Key,
    net_id: &NetID,
    join_eui: &EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<AES256Key> {
    get_s_key(
        opt_neg, 0x04, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

pub fn get_js_enc_key(dev_eui: &EUI64, nwk_key: &AES256Key) -> Result<AES256Key> {
    get_js_key(0x05, dev_eui, nwk_key)
}

pub fn get_js_int_key(dev_eui: &EUI64, nwk_key: &AES256Key) -> Result<AES256Key> {
    get_js_key(0x06, dev_eui, nwk_key)
}

/// Note: For LoRaWAN 1.0.x, use the NwkSKey as nwk_s_enc_key.
pub fn get_root_wor_s_key(nwk_s_enc_key: &AES256Key) -> Result<AES256Key> {
    let mut b: [u8; 16] = [0; 16];
    b[0] = 0x01;

    Ok(kdf(nwk_s_enc_key, &b))
}

/// Derives a 32-byte key from a root key and LoRaWAN's 16-byte derivation block (key type | fields | zero
/// padding), where LoRaWAN encrypts the block once and gets only 16 bytes: NIST SP 800-108's KDF in counter mode
/// with AES-256-CMAC, the block as the label, no context, L = 256 bits:
/// CMAC(root, 00000001 | block | 00 | 00000100) | CMAC(root, 00000002 | block | 00 | 00000100).
pub fn kdf(root: &AES256Key, block: &[u8; 16]) -> AES256Key {
    let mut out = [0u8; 32];
    for (i, half) in out.chunks_exact_mut(16).enumerate() {
        let mut mac = Cmac::<Aes256>::new_from_slice(&root.to_bytes()).unwrap();
        mac.update(&(i as u32 + 1).to_be_bytes());
        mac.update(block);
        mac.update(&[0x00]);
        mac.update(&256u32.to_be_bytes());
        half.copy_from_slice(&mac.finalize().into_bytes());
    }

    AES256Key::from_bytes(out)
}

fn get_s_key(
    opt_neg: bool,
    typ: u8,
    nwk_key: &AES256Key,
    net_id: &NetID,
    join_eui: &EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<AES256Key> {
    let mut b: [u8; 16] = [0; 16];

    b[0] = typ;
    if opt_neg {
        b[1..4].clone_from_slice(&join_nonce.to_le_bytes()[0..3]);
        b[4..12].clone_from_slice(&join_eui.to_le_bytes());
        b[12..14].clone_from_slice(&dev_nonce.to_le_bytes()[0..2]);
    } else {
        b[1..4].clone_from_slice(&join_nonce.to_le_bytes()[0..3]);
        b[4..7].clone_from_slice(&net_id.to_le_bytes());
        b[7..9].clone_from_slice(&dev_nonce.to_le_bytes()[0..2]);
    }

    Ok(kdf(nwk_key, &b))
}

fn get_js_key(typ: u8, dev_eui: &EUI64, nwk_key: &AES256Key) -> Result<AES256Key> {
    let mut b: [u8; 16] = [0; 16];
    b[0] = typ;
    b[1..9].clone_from_slice(&dev_eui.to_le_bytes());

    Ok(kdf(nwk_key, &b))
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use super::*;

    // The expected keys are the openssl vectors of scripts/aes256_vectors.sh (V8, V10) in the IoT-PQC repository,
    // not values this code produced.

    fn key(s: &str) -> AES256Key {
        AES256Key::from_str(s).unwrap()
    }

    fn join_eui() -> EUI64 {
        EUI64::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    }

    fn dev_eui() -> EUI64 {
        EUI64::from_be_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    }

    fn net_id() -> NetID {
        NetID::from_be_bytes([0x00, 0x00, 0x13])
    }

    #[test]
    fn kdf_is_openssl_kbkdf() {
        // openssl kdf -keylen 32 -kdfopt mac:CMAC -kdfopt cipher:AES-256-CBC -kdfopt hexkey:603d.. -kdfopt hexsalt:0101.. KBKDF
        assert_eq!(
            key("0bd47479295a2d2008786d966ee19161759336fc72847b05a3a3ed86675e292e"),
            kdf(
                &key("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
                &[1, 1, 0, 0, 0x13, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
            )
        );
    }

    #[test]
    fn lorawan_1_0() {
        // V8: AppKey a0..bf, JoinNonce 1, NetID 000013, DevNonce 1
        let app_key = key("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");

        let nwk_s_key = get_f_nwk_s_int_key(false, &app_key, &net_id(), &join_eui(), 1, 1).unwrap();
        let app_s_key = get_app_s_key(false, &app_key, &net_id(), &join_eui(), 1, 1).unwrap();

        assert_eq!(
            key("24e1abfe96dadf7c39554fbeef6fbcaf1eb40db3a0bad61f5262da0841d493d4"),
            nwk_s_key
        );
        assert_eq!(
            key("1d25efdb4e5bda08d8d3e6b9134e3a6b8b8fc5b5001f72b2a13f7bc2ba75ce6d"),
            app_s_key
        );
        assert_eq!(
            key("54fabed270b0e83075f46ccebf929e9e4a2c2f8796c6058b782fa245ebbf08ac"),
            get_root_wor_s_key(&nwk_s_key).unwrap()
        );
    }

    #[test]
    fn lorawan_1_1() {
        // V10: NwkKey c0..df, AppKey e0..ff, JoinNonce 1, JoinEUI 1122334455667788, DevEUI 0102030405060708,
        // DevNonce 1
        let nwk_key = key("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        let app_key = key("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        assert_eq!(
            key("66bea5492e78763d16f359a45cf3fb1db37bc02458bee1370fe90fd978f92f24"),
            get_js_int_key(&dev_eui(), &nwk_key).unwrap()
        );
        assert_eq!(
            key("623ccd1346f51fce3b7d583390fa3dfb4deeca686f072d514d6c2e34de002be2"),
            get_js_enc_key(&dev_eui(), &nwk_key).unwrap()
        );
        assert_eq!(
            key("ee721af87f630a64f6943a8bbb3fafe2442dace93331ba441c8601fc05f07523"),
            get_f_nwk_s_int_key(true, &nwk_key, &net_id(), &join_eui(), 1, 1).unwrap()
        );
        assert_eq!(
            key("5aa0dfcfacbf19288136a689ab18c1bb6685dae2529a016823b210fbb178cde5"),
            get_s_nwk_s_int_key(true, &nwk_key, &net_id(), &join_eui(), 1, 1).unwrap()
        );
        assert_eq!(
            key("a496763652fdca82b5d7caf81189fb69e131b8345fa538448890e2b322e38897"),
            get_nwk_s_enc_key(true, &nwk_key, &net_id(), &join_eui(), 1, 1).unwrap()
        );
        assert_eq!(
            key("b0fcc761250f51aea1620b827eeef9ef18b84b1099658423c01fa486040cbdcc"),
            get_app_s_key(true, &app_key, &net_id(), &join_eui(), 1, 1).unwrap()
        );
    }
}
