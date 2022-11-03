// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html

use hex_literal::hex;

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

// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct YubicoObjects {}
#[allow(non_upper_case_globals)]
impl YubicoObjects {
    pub const AttestationCertificate: &'static [u8] = &hex!("5fff01");
}

pub const YUBICO_PIV_AUTHENTICATION_CERTIFICATE: &[u8; 351] = &hex!(
    "
    5382 015b 7082 0152 3082 014e 3081 f5a0
    0302 0102 0211 008e 4632 d8f0 c1f7 c14d
    67d1 4bfd e364 8e30 0a06 082a 8648 ce3d
    0403 0230 2a31 1630 1406 0355 040a 130d
    7975 6269 6b65 792d 6167 656e 7431 1030
    0e06 0355 040b 1307 2864 6576 656c 2930
    2017 0d32 3030 3530 3931 3230 3034 395a
    180f 3230 3632 3035 3039 3133 3030 3439
    5a30 1231 1030 0e06 0355 0403 1307 5353
    4820 6b65 7930 5930 1306 072a 8648 ce3d
    0201 0608 2a86 48ce 3d03 0107 0342 0004
    832a 9247 8b4e b57a 461b 2a5e 0e44 2503
    9bfb 2794 5678 ed48 2b1c f221 616d dabd
    3d8f b62b 75c6 ac3f 834a 594e 5adf ede7
    3ae4 991a e733 2f61 2bcf 6c0e d678 72eb
    a312 3010 300e 0603 551d 0f01 01ff 0404
    0302 0388 300a 0608 2a86 48ce 3d04 0302
    0348 0030 4502 2003 09e2 8447 dcb7 c532
    ee97 5b9e 44fa 4206 f226 67c1 a6c6 4adc
    6a0b 5da9 8763 8b02 2100 bb4e cb18 72cc
    1239 d3d4 1836 1418 e4a9 f383 814b 740f
    9333 b847 a973 c282 923e 7101 00fe 00      
"
);

pub const YUBICO_ATTESTATION_CERTIFICATE: &[u8; 754] = &hex!(
    "      
    5382 02ee 7082 02ea 3082 02e6 3082 01ce
    a003 0201 0202 0900 a485 22aa 34af ae4f
    300d 0609 2a86 4886 f70d 0101 0b05 0030
    2b31 2930 2706 0355 0403 0c20 5975 6269
    636f 2050 4956 2052 6f6f 7420 4341 2053
    6572 6961 6c20 3236 3337 3531 3020 170d
    3136 3033 3134 3030 3030 3030 5a18 0f32
    3035 3230 3431 3730 3030 3030 305a 3021
    311f 301d 0603 5504 030c 1659 7562 6963
    6f20 5049 5620 4174 7465 7374 6174 696f
    6e30 8201 2230 0d06 092a 8648 86f7 0d01
    0101 0500 0382 010f 0030 8201 0a02 8201
    0100 aba9 0b16 9bef 31cc 3eac 185a 2d45
    8075 70c7 58b0 6c3f 1b59 0d49 b989 e86f
    cebb 276f d83c 603a 8500 ef5c bc40 993d
    41ee eac0 817f 7648 e4a9 4cbc d56b e11f
    0a60 93c6 feaa d28d 8ee2 b7cd 8b2b f79b
    dd5a ab2f cfb9 0e54 ceec 8df5 5ed7 7b91
    c3a7 569c dcc1 0686 7636 4453 fb08 25d8
    06b9 068c 81fd 6367 ca3c a8b8 ea1c a6ca
    db44 7b12 cab2 3401 7e73 e436 83df ebf9
    2300 0701 6a07 198a 6456 9d10 8ac5 7302
    3d18 6eaf 3fc3 02a7 c0f7 a2fd 6d5a 4276
    4ed6 c01e d6c0 c6aa 5da7 1a9f 10db 3057
    185c b5b5 fd0c be49 2422 af1e 564a 3444
    d4aa d4e1 ae95 4c75 c088 61f4 8c7e 54f3
    13eb 0fe5 2b52 605a 6eba d7e5 8c63 da51
    1abb 225c 372b d7d1 7057 4c2e dc35 3c22
    989b 0203 0100 01a3 1530 1330 1106 0a2b
    0601 0401 82c4 0a03 0304 0304 0303 300d
    0609 2a86 4886 f70d 0101 0b05 0003 8201
    0100 5280 5a6d c39e df47 a8f1 b2a5 9ca3
    8081 3b1d 6aeb 6a12 624b 11fd 8d30 f17b
    fc71 10c9 b208 fcd1 4e35 7f45 f210 a252
    b9d4 b302 1a01 5607 6bfa 64a7 08f0 03fb
    27a9 608d 0dd3 ac5a 10cf 2096 4e82 bc9d
    e337 dac1 4c50 e13d 16b4 caf4 1bff 0864
    c974 4f2a 3a43 e0de 4279 f213 ae77 a1e2
    ae6b df72 a5b6 ced7 4c90 13df dedb f28b
    3445 8b30 dc51 aba9 34f8 a9e5 0c47 29aa
    2f42 54f2 f819 5ab4 89fe 1b9f 197a 16c8
    c8ba 8f18 177a 07a9 97a1 56b9 525d a121
    c081 672d e80e a651 b908 b09d d360 1c70
    a30f fad8 62d8 792b 0ae6 42fc f82d f5e4
    cdfb 1596 23ff b6c0 a7a7 e285 83f9 70c8
    196b f3c1 3f37 4465 27fb 6788 c883 b72f
    851f 8044 bb72 ce06 8259 2d83 00e1 948d
    a085
"
);

pub const YUBICO_ATTESTATION_CERTIFICATE_FOR_9A: &[u8; 584] = &hex!(
    "      
    3082 0244 3082 012c a003 0201 0202 1100
    c636 e7b3 a5a5 a498 5d13 6e43 362d 13f7
    300d 0609 2a86 4886 f70d 0101 0b05 0030
    2131 1f30 1d06 0355 0403 0c16 5975 6269
    636f 2050 4956 2041 7474 6573 7461 7469
    6f6e 3020 170d 3136 3033 3134 3030 3030
    3030 5a18 0f32 3035 3230 3431 3730 3030
    3030 305a 3025 3123 3021 0603 5504 030c
    1a59 7562 694b 6579 2050 4956 2041 7474
    6573 7461 7469 6f6e 2039 6130 5930 1306
    072a 8648 ce3d 0201 0608 2a86 48ce 3d03
    0107 0342 0004 832a 9247 8b4e b57a 461b
    2a5e 0e44 2503 9bfb 2794 5678 ed48 2b1c
    f221 616d dabd 3d8f b62b 75c6 ac3f 834a
    594e 5adf ede7 3ae4 991a e733 2f61 2bcf
    6c0e d678 72eb a33c 303a 3011 060a 2b06
    0104 0182 c40a 0303 0403 0403 0430 1306
    0a2b 0601 0401 82c4 0a03 0704 0502 0352
    f743 3010 060a 2b06 0104 0182 c40a 0308
    0402 0202 300d 0609 2a86 4886 f70d 0101
    0b05 0003 8201 0100 0217 38a8 f61d 1735
    e130 9dd2 d5c4 d4d0 0de1 9f37 9abe cf63
    6a0e 2bd0 d7a4 045c 407d f743 9be4 ee7d
    9655 d291 dc32 8254 fe2d 9f19 2354 bbdd
    7d6b e961 2a1d c813 65e2 049f a287 de61
    92d5 de46 d4a4 c2a6 b480 5d4a a4d1 1ba7
    34f2 977b 7a5a ad9a a85d 2ad4 7fb1 57bf
    261d 3da6 b3ea 3d3d f794 cd16 3640 24cd
    7c8e 7adb 2df9 22da 26b3 c1c8 00a3 4797
    5210 1273 4baf 12fe b70d 9e91 30a7 52cf
    12d8 2bdf 126a b62f 3924 c604 a26f ed70
    b5f2 0d2a 73e3 38a9 9cfe 353e dc17 4055
    d595 7f05 8e24 c2b3 b105 2d69 0ccf 5bf7
    0640 1736 0ac3 a5db 3cda 62f8 532d f13f
    0455 700c 437b 1fa3 63b1 a05e 8928 5b4f
    76a7 05e1 4c45 5514 ff10 1089 696a 133d
    89f2 cafd 149a c4d0
"
);

// pub const YUBICO_DEFAULT_MANAGEMENT_KEY: & [u8; 24] = b"123456781234567812345678";
pub const YUBICO_DEFAULT_MANAGEMENT_KEY: &[u8; 24] = &hex!(
    "
    0102030405060708
    0102030405060708
    0102030405060708
"
);

// stolen from le yubico
pub const DISCOVERY_OBJECT: &[u8; 20] =
    b"~\x12O\x0b\xa0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00_/\x02@\x00";
