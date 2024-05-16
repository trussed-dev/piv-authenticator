// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html

use hex_literal::hex;

use crate::state::AdministrationAlgorithm;

pub const RID_LENGTH: usize = 5;

// top nibble of first byte is "category", here "A" = International
// this category has 5 byte "registered application provider identifier"
// (international RID, the other 9 nibbles is between 0x0 and 0x9).
pub const NIST_RID: &[u8; RID_LENGTH] = &hex!("A000000 308");
pub const YUBICO_RID: &[u8; RID_LENGTH] = &hex!("A000000 527");
// our very own RID (847 = 7*11*11 FWIW)
pub const SOLOKEYS_RID: &[u8; RID_LENGTH] = &hex!("A000000 847");

pub const PIV_APP: [u8; 4] = hex!("0000 1000");
pub const DERIVED_PIV_APP: [u8; 4] = hex!("0000 2000");
pub const PIV_VERSION: [u8; 2] = hex!("0100");
pub const PIV_PIX: [u8; 6] = hex!("0000 1000 0100");
pub const DERIVED_PIV_PIX: [u8; 6] = hex!("0000 2000 0100");

pub const PIV_TRUNCATED_AID: [u8; 9] = hex!("A000000308 00001000");

// pub const PIV_AID: &[u8] = &hex!("A000000308 00001000 0100");
pub const PIV_AID: iso7816::Aid =
    iso7816::Aid::new_truncatable(&hex!("A000000308 00001000 0100"), 9);

pub const DERIVED_PIV_AID: [u8; 11] = hex!("A000000308 00002000 0100");

pub const NITROKEY_APPLICATION_LABEL: &[u8] = b"Nitrokey PIV";
pub const NITROKEY_APPLICATION_URL: &[u8] = b"https://github.com/Nitrokey/piv-authenticator";

pub const YUBICO_DEFAULT_MANAGEMENT_KEY: &[u8; 24] = &hex!(
    "
    0102030405060708
    0102030405060708
    0102030405060708
"
);

pub const YUBICO_DEFAULT_MANAGEMENT_KEY_ALG: AdministrationAlgorithm =
    AdministrationAlgorithm::Tdes;

pub const DISCOVERY_OBJECT: [u8; 18] = hex!(
    "
    4f 0b // PIV AID
       a000000308000010000100
    5f2f 02 // PIN usage Policy
         4010"
);

pub const CARD_CAP: [u8; 27] = hex!(
    "
    F0 00 // card identifier
    F1 00 // capability container version
    F2 00 // capability container grammar
    F3 00 // application card url
    F4 00 // pkcs15
    F5 01 10 // registereddata model number
    F6 00 // access control rule table
    F7 00 // card apdus
    FA 00 // redirection tag
    FB 00 // capability tuples
    FC 00 // status tuples
    FD 00 // next ccc
    FE 00 // Error detection code
"
);

use crate::Container;
pub const RETIRED_CERTS: [Container; 20] = [
    Container::RetiredCert01,
    Container::RetiredCert02,
    Container::RetiredCert03,
    Container::RetiredCert04,
    Container::RetiredCert05,
    Container::RetiredCert06,
    Container::RetiredCert07,
    Container::RetiredCert08,
    Container::RetiredCert09,
    Container::RetiredCert10,
    Container::RetiredCert11,
    Container::RetiredCert12,
    Container::RetiredCert13,
    Container::RetiredCert14,
    Container::RetiredCert15,
    Container::RetiredCert16,
    Container::RetiredCert17,
    Container::RetiredCert18,
    Container::RetiredCert19,
    Container::RetiredCert20,
];
