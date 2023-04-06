// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html

use hex_literal::hex;

use crate::state::AdministrationAlgorithm;

pub const RID_LENGTH: usize = 5;

// top nibble of first byte is "category", here "A" = International
// this category has 5 byte "registered application provider identifier"
// (international RID, the other 9 nibbles is between 0x0 and 0x9).
pub const NIST_RID: &[u8; 5] = &hex!("A000000 308");
pub const YUBICO_RID: &[u8; 5] = &hex!("A000000 527");
// our very own RID (847 = 7*11*11 FWIW)
pub const SOLOKEYS_RID: &[u8; 5] = &hex!("A000000 847");

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

pub const APPLICATION_LABEL: &[u8] = b"SoloKeys PIV";
pub const APPLICATION_URL: &[u8] = b"https://github.com/solokeys/piv-authenticator";
// pub const APPLICATION_URL: &[u8] = b"https://piv.is/SoloKeys/PIV/1.0.0-alpha1";

// https://git.io/JfWuD
pub const YUBICO_OTP_PIX: [u8; 3] = hex!("200101");
pub const YUBICO_OTP_AID: iso7816::Aid = iso7816::Aid::new(&hex!("A000000527 200101"));
// they use it to "deauthenticate user PIN and mgmt key": https://git.io/JfWgN
pub const YUBICO_MGMT_PIX: [u8; 3] = hex!("471117");
pub const YUBICO_MGMT_AID: [u8; 8] = hex!("A000000527 471117");

// https://git.io/JfW28
// const (
// 	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=17
// 	algTag     = 0x80
// 	alg3DES    = 0x03
// 	algRSA1024 = 0x06
// 	algRSA2048 = 0x07
// 	algECCP256 = 0x11
// 	algECCP384 = 0x14

// 	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=16
// 	keyAuthentication     = 0x9a
// 	keyCardManagement     = 0x9b
// 	keySignature          = 0x9c
// 	keyKeyManagement      = 0x9d
// 	keyCardAuthentication = 0x9e
// 	keyAttestation        = 0xf9

// 	insVerify             = 0x20
// 	insChangeReference    = 0x24
// 	insResetRetry         = 0x2c
// 	insGenerateAsymmetric = 0x47
// 	insAuthenticate       = 0x87
// 	insGetData            = 0xcb
// 	insPutData            = 0xdb
// 	insSelectApplication  = 0xa4
// 	insGetResponseAPDU    = 0xc0

// 	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.h#L656
// 	insGetSerial     = 0xf8
// 	insAttest        = 0xf9
// 	insSetPINRetries = 0xfa
// 	insReset         = 0xfb
// 	insGetVersion    = 0xfd
// 	insImportKey     = 0xfe
// 	insSetMGMKey     = 0xff
// )

pub const OK: &[u8; 2] = &[0x90, 0x00];

// pub const SELECT: (u8, u8, u8, u8, usize) = (
pub const SELECT: (u8, u8, u8, u8) = (
    0x00, // interindustry, channel 0, no chain, no secure messaging,
    0xa4, // SELECT
    // p1
    0x04, // data is DF name, may be AID, possibly right-truncated
    // p2: i think this is dummy here
    0x00, // b2, b1 zero means "file occurence": first/only occurence,
          // b4, b3 zero means "file control information": return FCI template
          // 256,
);

//
// See SP 800-73 Part 1, Table 7
// for list of all objects and minimum container capacity
// - CCC: 287
// - CHUID: 2916
// - discovery: 19
// - key history: 256
// - x5c: 1905B
// - etc.
//
// pub const GET_DATA: (u8, u8, u8, u8, usize) = (
pub const GET_DATA: (u8, u8, u8, u8) = (
    0x00, // as before, would be 0x0C for secure messaging
    0xCB, // GET DATA. There's also `CA`, setting bit 1 here
    // means (7816-4, sec. 5.1.2): use BER-TLV, as opposed
    // to "no indication provided".
    // P1, P2: 7816-4, sec. 7.4.1: bit 1 of INS set => P1,P2 identifies
    // a file. And 0x3FFF identifies current DF
    0x3F, 0xFF,
    // 256,
);

// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DataObjects {}
#[allow(non_upper_case_globals)]
impl DataObjects {
    pub const DiscoveryObject: &'static [u8] = &[0x7e];
    pub const BiometricInformationTemplate: &'static [u8] = &[0x7f, 0x61];

    pub const X509CertificateForCardAuthentication: &'static [u8] = &[0x5f, 0xc1, 0x01];
    // CHUID, contains GUID
    pub const CardHolderUniqueIdentifier: &'static [u8] = &[0x5f, 0xc1, 0x02];
    pub const X509CertificateForPivAuthentication: &'static [u8] = &[0x5f, 0xc1, 0x05];
    pub const X509CertificateForDigitalSignature: &'static [u8] = &[0x5f, 0xc1, 0x0a];
    pub const X509CertificateForKeyManagement: &'static [u8] = &[0x5f, 0xc1, 0x0b];

    pub const KeyHistoryObject: &'static [u8] = &[0x5f, 0xc1, 0x0c];
}

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
         4000"
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
