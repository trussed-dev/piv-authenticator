// Copyright (C) 2022 Nicolas Stalder AND Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "virtual")]

mod setup;

use std::borrow::Cow;

use aes::Aes256Enc;
use hex_literal::hex;
use serde::Deserialize;
use trussed::types::GenericArray;

// iso7816::Status doesn't support serde
#[derive(Deserialize, Debug, PartialEq, Clone, Copy)]
enum Status {
    Success,
    MoreAvailable(u8),
    VerificationFailed,
    RemainingRetries(u8),
    UnspecifiedNonpersistentExecutionError,
    UnspecifiedPersistentExecutionError,
    WrongLength,
    LogicalChannelNotSupported,
    SecureMessagingNotSupported,
    CommandChainingNotSupported,
    SecurityStatusNotSatisfied,
    ConditionsOfUseNotSatisfied,
    OperationBlocked,
    IncorrectDataParameter,
    FunctionNotSupported,
    NotFound,
    NotEnoughMemory,
    IncorrectP1OrP2Parameter,
    KeyReferenceNotFound,
    InstructionNotSupportedOrInvalid,
    ClassNotSupported,
    UnspecifiedCheckingError,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug, Deserialize)]
pub enum Algorithm {
    Tdes = 0x3,
    Rsa1024 = 0x6,
    Rsa2048 = 0x7,
    Aes128 = 0x8,
    Aes192 = 0xA,
    Aes256 = 0xC,
    P256 = 0x11,
    P384 = 0x14,

    P521 = 0x15,
    // non-standard!
    Rsa3072 = 0xE0,
    Rsa4096 = 0xE1,
    Ed25519 = 0xE2,
    X25519 = 0xE3,
    Ed448 = 0xE4,
    X448 = 0xE5,

    // non-standard! picked by Alex, but maybe due for removal
    P256Sha1 = 0xF0,
    P256Sha256 = 0xF1,
    P384Sha1 = 0xF2,
    P384Sha256 = 0xF3,
    P384Sha384 = 0xF4,
}
impl Algorithm {
    pub fn challenge_len(self) -> usize {
        match self {
            Self::Tdes => 8,
            Self::Aes256 => 16,
            _ => panic!(),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Tdes => 24,
            Self::Aes256 => 32,
            _ => panic!(),
        }
    }
}

fn serialize_len(len: usize) -> heapless::Vec<u8, 3> {
    let mut buf = heapless::Vec::new();
    if let Ok(len) = u8::try_from(len) {
        if len <= 0x7f {
            buf.extend_from_slice(&[len]).ok();
        } else {
            buf.extend_from_slice(&[0x81, len]).ok();
        }
    } else if let Ok(len) = u16::try_from(len) {
        let arr = len.to_be_bytes();
        buf.extend_from_slice(&[0x82, arr[0], arr[1]]).ok();
    } else {
    }
    buf
}

fn tlv(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(tag);
    buf.extend_from_slice(&serialize_len(data.len()));
    buf.extend_from_slice(data);
    buf
}

fn build_command(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u16) -> Vec<u8> {
    let mut res = vec![cla, ins, p1, p2];
    let lc = data.len();
    let extended = if lc == 0 {
        false
    } else if let Ok(len) = lc.try_into() {
        res.push(len);
        false
    } else {
        let len: u16 = lc.try_into().unwrap();
        res.push(0);
        res.extend_from_slice(&len.to_be_bytes());
        true
    };

    res.extend_from_slice(data);

    if le == 0 {
        return res;
    }

    if let Ok(len) = (le - 1).try_into() {
        let _: u8 = len;
        res.push(len.wrapping_add(1));
    } else if extended {
        res.extend_from_slice(&le.to_be_bytes());
    } else {
        res.push(0);
        res.extend_from_slice(&le.to_be_bytes());
    }

    res
}

impl TryFrom<u16> for Status {
    type Error = u16;
    fn try_from(sw: u16) -> Result<Self, Self::Error> {
        Ok(match sw {
            0x6300 => Self::VerificationFailed,
            sw @ 0x63c0..=0x63cf => Self::RemainingRetries((sw as u8) & 0xf),

            0x6400 => Self::UnspecifiedNonpersistentExecutionError,
            0x6500 => Self::UnspecifiedPersistentExecutionError,

            0x6700 => Self::WrongLength,

            0x6881 => Self::LogicalChannelNotSupported,
            0x6882 => Self::SecureMessagingNotSupported,
            0x6884 => Self::CommandChainingNotSupported,

            0x6982 => Self::SecurityStatusNotSatisfied,
            0x6985 => Self::ConditionsOfUseNotSatisfied,
            0x6983 => Self::OperationBlocked,

            0x6a80 => Self::IncorrectDataParameter,
            0x6a81 => Self::FunctionNotSupported,
            0x6a82 => Self::NotFound,
            0x6a84 => Self::NotEnoughMemory,
            0x6a86 => Self::IncorrectP1OrP2Parameter,
            0x6a88 => Self::KeyReferenceNotFound,

            0x6d00 => Self::InstructionNotSupportedOrInvalid,
            0x6e00 => Self::ClassNotSupported,
            0x6f00 => Self::UnspecifiedCheckingError,

            0x9000 => Self::Success,
            sw @ 0x6100..=0x61FF => Self::MoreAvailable(sw as u8),
            other => return Err(other),
        })
    }
}

impl Default for Status {
    fn default() -> Status {
        Status::Success
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct IoTest {
    name: String,
    cmd_resp: Vec<IoCmd>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
enum OutputMatcher {
    Len(usize),
    // The () at the end are here to workaround a compiler bug. See:
    // https://github.com/rust-lang/rust/issues/89940#issuecomment-1282321806
    And(Cow<'static, [OutputMatcher]>, #[serde(default)] ()),
    Or(Cow<'static, [OutputMatcher]>, #[serde(default)] ()),
    /// HEX data
    Data(Cow<'static, str>),
    Bytes(Cow<'static, [u8]>),
    NonZero,
}

impl Default for OutputMatcher {
    fn default() -> Self {
        MATCH_EMPTY
    }
}

fn parse_hex(data: &str) -> Vec<u8> {
    let tmp: String = data.split_whitespace().collect();
    hex::decode(tmp).unwrap()
}

impl OutputMatcher {
    fn validate(&self, data: &[u8]) -> bool {
        match self {
            Self::NonZero => data.iter().max() != Some(&0),
            Self::Data(expected) => {
                println!("Validating output with {expected}");
                data == parse_hex(expected)
            }
            Self::Bytes(expected) => {
                println!("Validating output with {expected:x?}");
                data == &**expected
            }
            Self::Len(len) => data.len() == *len,
            Self::And(matchers, _) => matchers.iter().filter(|m| !m.validate(data)).count() == 0,
            Self::Or(matchers, _) => matchers.iter().filter(|m| m.validate(data)).count() != 0,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ManagementKey {
    algorithm: Algorithm,
    key: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
enum IoCmd {
    IoData {
        input: String,
        #[serde(default)]
        output: OutputMatcher,
        #[serde(default)]
        expected_status: Status,
    },
    VerifyDefaultApplicationPin {
        #[serde(default)]
        expected_status: Status,
    },
    VerifyDefaultGlobalPin {
        #[serde(default)]
        expected_status: Status,
    },
    SetManagementKey {
        key: ManagementKey,
        #[serde(default)]
        expected_status: Status,
    },
    AuthenticateManagement {
        key: ManagementKey,
        #[serde(default)]
        expected_status_challenge: Status,
        #[serde(default)]
        expected_status_response: Status,
    },
    Select,
}

const MATCH_EMPTY: OutputMatcher = OutputMatcher::Len(0);
const MATCH_ANY: OutputMatcher = OutputMatcher::And(Cow::Borrowed(&[]), ());

impl IoCmd {
    fn run(&self, card: &mut setup::Piv) {
        match self {
            Self::IoData {
                input,
                output,
                expected_status,
            } => Self::run_iodata(input, output, *expected_status, card),
            Self::VerifyDefaultApplicationPin { expected_status } => {
                Self::run_verify_default_application_pin(*expected_status, card)
            }
            Self::VerifyDefaultGlobalPin { expected_status } => {
                Self::run_verify_default_global_pin(*expected_status, card)
            }
            Self::AuthenticateManagement {
                key,
                expected_status_challenge,
                expected_status_response,
            } => Self::run_authenticate_management(
                key.algorithm,
                &key.key,
                *expected_status_challenge,
                *expected_status_response,
                card,
            ),
            Self::SetManagementKey {
                key,
                expected_status,
            } => Self::run_set_administration_key(key.algorithm, &key.key, *expected_status, card),
            Self::Select => Self::run_select(card),
        }
    }

    fn run_set_administration_key(
        alg: Algorithm,
        key: &str,
        expected_status: Status,
        card: &mut setup::Piv,
    ) {
        let mut key_data = parse_hex(key);
        let mut data = vec![alg as u8, 0x9b, key_data.len() as u8];
        data.append(&mut key_data);

        Self::run_bytes(
            &build_command(0x00, 0xff, 0xff, 0xff, &data, 0),
            &MATCH_ANY,
            expected_status,
            card,
        );
    }

    fn run_bytes(
        input: &[u8],
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut setup::Piv,
    ) -> heapless::Vec<u8, 1024> {
        println!("Command: {:x?}", input);
        let mut rep: heapless::Vec<u8, 1024> = heapless::Vec::new();
        let cmd: iso7816::Command<{ setup::COMMAND_SIZE }> = iso7816::Command::try_from(input)
            .unwrap_or_else(|err| {
                panic!("Bad command: {err:?}, for command: {}", hex::encode(input))
            });
        let status: Status = card
            .respond(&cmd, &mut rep)
            .err()
            .map(|s| TryFrom::<u16>::try_from(s.into()).unwrap())
            .unwrap_or_default();

        println!("Output: {:?}\nStatus: {status:?}", hex::encode(&rep));

        if !output.validate(&rep) {
            panic!("Bad output. Expected {:?}", output);
        }
        if status != expected_status {
            panic!("Bad status. Expected {:?}", expected_status);
        }
        rep
    }

    fn run_iodata(
        input: &str,
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut setup::Piv,
    ) {
        Self::run_bytes(&parse_hex(input), output, expected_status, card);
    }

    fn run_authenticate_management(
        alg: Algorithm,
        key: &str,
        expected_status_challenge: Status,
        expected_status_response: Status,
        card: &mut setup::Piv,
    ) {
        use des::{
            cipher::{BlockEncrypt, KeyInit},
            TdesEde3,
        };
        let command = build_command(0x00, 0x87, alg as u8, 0x9B, &hex!("7C 02 81 00"), 0);
        let mut res = Self::run_bytes(&command, &MATCH_ANY, expected_status_challenge, card);
        let key = parse_hex(key);
        if expected_status_challenge != Status::Success && res.is_empty() {
            res = heapless::Vec::from_slice(&vec![0; alg.challenge_len() + 6]).unwrap();
        }

        // Remove header
        let challenge = &mut res[6..][..alg.challenge_len()];
        match alg {
            Algorithm::Tdes => {
                let cipher = TdesEde3::new(GenericArray::from_slice(&key));
                cipher.encrypt_block(GenericArray::from_mut_slice(challenge));
            }
            Algorithm::Aes256 => {
                let cipher = Aes256Enc::new(GenericArray::from_slice(&key));
                cipher.encrypt_block(GenericArray::from_mut_slice(challenge));
            }
            _ => panic!(),
        }
        let second_data = tlv(&[0x7C], &tlv(&[0x82], challenge));
        let command = build_command(0x00, 0x87, alg as u8, 0x9B, &second_data, 0);
        Self::run_bytes(&command, &MATCH_ANY, expected_status_response, card);
    }

    fn run_verify_default_global_pin(expected_status: Status, card: &mut setup::Piv) {
        Self::run_bytes(
            &hex!("00 20 00 00 08 313233343536FFFF"),
            &MATCH_EMPTY,
            expected_status,
            card,
        );
    }

    fn run_verify_default_application_pin(expected_status: Status, card: &mut setup::Piv) {
        Self::run_bytes(
            &hex!("00 20 00 80 08 313233343536FFFF"),
            &MATCH_EMPTY,
            expected_status,
            card,
        );
    }

    fn run_select(card: &mut setup::Piv) {
        let matcher = OutputMatcher::Bytes(Cow::Borrowed(&hex!(
            "
            61 63 // Card application property template
                4f 06 000010000100 // Application identifier
                50 0c 536f6c6f4b65797320504956 // Application label = b\"Solokeys PIV\"

                // URL = b\"https://github.com/solokeys/piv-authenticator\"
                5f50 2d 68747470733a2f2f6769746875622e636f6d2f736f6c6f6b6579732f7069762d61757468656e74696361746f72 
            
                // Cryptographic Algorithm Identifier Template
                ac 12 
                    80 01 03 // TDES - ECB
                    80 01 0c // AES256 - ECB
                    80 01 11 // P-256
                    80 01 e2 // Ed25519
                    80 01 e3 // X25519
                    06 01 00
                // Coexistent Tag Allocation Authority Template 
                79 07 
                    4f 05 a000000308    
        "
        )));
        Self::run_bytes(
            &hex!("00 A4 04 00 0C A000000308000010000100 00"),
            &matcher,
            Status::Success,
            card,
        );
    }
}

#[test_log::test]
fn command_response() {
    let data = std::fs::read_to_string("tests/command_response.ron").unwrap();
    let tests: Vec<IoTest> = ron::from_str(&data).unwrap();
    for t in tests {
        println!("\n\n===========================================================",);
        println!("Running {}", t.name);
        setup::piv(|card| {
            for io in t.cmd_resp {
                io.run(card);
            }
        });
    }
}
