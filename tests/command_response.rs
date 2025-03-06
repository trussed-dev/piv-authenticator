#![cfg(feature = "virt")]

mod setup;

use std::borrow::Cow;

use hex_literal::hex;
use rand::thread_rng;
use serde::Deserialize;
use trussed::types::GenericArray;

macro_rules! assert_eq_hex {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    panic!("assertion `left == right` failed\n  left: {left_val:02x?}\n right: {right_val:02x?}");
                }
            }
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    panic!("assertion `left == right` failed\n  left: {left_val:02x?}\n right: {right_val:02x?}");
                }
            }
        }
    };
}

// iso7816::Status doesn't support serde
#[derive(Deserialize, Debug, PartialEq, Clone, Copy, Default)]
enum Status {
    #[default]
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

impl From<iso7816::Status> for Status {
    fn from(value: iso7816::Status) -> Self {
        let tmp: u16 = value.into();
        tmp.try_into().unwrap()
    }
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
        panic!("Length is too long to be serialized");
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
    iso7816::command::CommandBuilder::new(cla.try_into().unwrap(), ins.into(), p1, p2, data, le)
        .serialize_to_vec()
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

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct IoTest {
    name: String,
    cmd_resp: Vec<IoCmd>,
    #[serde(default)]
    uuid_config: UuidConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
enum OutputMatcher {
    Len(usize),
    // The () at the end are here to workaround a compiler bug. See:
    // https://github.com/rust-lang/rust/issues/89940#issuecomment-1282321806
    All(
        #[serde(default)] Cow<'static, [OutputMatcher]>,
        #[serde(default)] (),
    ),
    Any(
        #[serde(default)] Cow<'static, [OutputMatcher]>,
        #[serde(default)] (),
    ),
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
                println!("Validating output with {expected:02x?}");
                data == &**expected
            }
            Self::Len(len) => data.len() == *len,
            Self::All(matchers, _) => matchers.iter().filter(|m| !m.validate(data)).count() == 0,
            Self::Any(matchers, _) => matchers.iter().filter(|m| m.validate(data)).count() != 0,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ManagementKey {
    algorithm: Algorithm,
    key: String,
}

fn default_app_pin() -> String {
    "313233343536FFFF".into()
}

fn default_puk() -> String {
    "3132333435363738".into()
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
    GetData {
        input: String,
        #[serde(default)]
        output: OutputMatcher,
        #[serde(default)]
        expected_status: Status,
    },
    PutData {
        input: String,
        #[serde(default)]
        output: OutputMatcher,
        #[serde(default)]
        expected_status: Status,
    },
    VerifyApplicationPin {
        #[serde(default = "default_app_pin")]
        pin: String,
        #[serde(default)]
        expected_status: Status,
    },
    VerifyGlobalPin {
        #[serde(default = "default_app_pin")]
        pin: String,
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
        mutual: bool,
        #[serde(default)]
        expected_status_challenge: Status,
        #[serde(default)]
        expected_status_response: Status,
    },
    ChangePin {
        #[serde(default = "default_app_pin")]
        old: String,
        new: String,
        #[serde(default)]
        expected_status: Status,
    },
    ChangePuk {
        #[serde(default = "default_puk")]
        old: String,
        new: String,
        #[serde(default)]
        expected_status: Status,
    },
    // Only works for 0x9A
    ImportRsaKey {
        p: String,
        q: String,
        e: String,
        #[serde(default)]
        expected_status: Status,
    },
    Sign {
        algo: u8,
        key_reference: u8,
        data: String,
        output: OutputMatcher,
        #[serde(default)]
        expected_status: Status,
    },
    Select,
    Reset {
        #[serde(default)]
        expected_status: Status,
    },
}

const MATCH_EMPTY: OutputMatcher = OutputMatcher::Len(0);
const MATCH_ANY: OutputMatcher = OutputMatcher::All(Cow::Borrowed(&[]), ());

impl IoCmd {
    fn run(&self, card: &mut setup::Piv) {
        println!("Running {self:?}");
        match self {
            Self::IoData {
                input,
                output,
                expected_status,
            } => Self::run_iodata(input, output, *expected_status, card),
            Self::GetData {
                input,
                output,
                expected_status,
            } => Self::run_get_data(input, output, *expected_status, card),
            Self::PutData {
                input,
                output,
                expected_status,
            } => Self::run_put_data(input, output, *expected_status, card),
            Self::VerifyApplicationPin {
                pin,
                expected_status,
            } => Self::run_verify_application_pin(pin, *expected_status, card),
            Self::VerifyGlobalPin {
                pin,
                expected_status,
            } => Self::run_verify_global_pin(pin, *expected_status, card),
            Self::AuthenticateManagement {
                key,
                mutual: false,
                expected_status_challenge,
                expected_status_response,
            } => Self::run_authenticate_management_single(
                key.algorithm,
                &key.key,
                *expected_status_challenge,
                *expected_status_response,
                card,
            ),
            Self::AuthenticateManagement {
                key,
                mutual: true,
                expected_status_challenge,
                expected_status_response,
            } => Self::run_authenticate_management_mutual(
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
            Self::ChangePin {
                old,
                new,
                expected_status,
            } => Self::run_change_pin(old, new, *expected_status, card),
            Self::ChangePuk {
                old,
                new,
                expected_status,
            } => Self::run_change_puk(old, new, *expected_status, card),
            Self::ImportRsaKey {
                p,
                q,
                e,
                expected_status,
            } => Self::run_import_rsa_key(p, q, e, *expected_status, card),
            Self::Sign {
                algo,
                key_reference,
                data,
                output,
                expected_status,
            } => Self::run_sign(*algo, *key_reference, data, output, *expected_status, card),
            Self::Select => Self::run_select(card),
            Self::Reset { expected_status } => Self::run_reset(*expected_status, card),
        }
    }

    fn run_sign(
        algo: u8,
        key_ref: u8,
        data: &str,
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut setup::Piv,
    ) {
        let data = parse_hex(data);
        let data_intermediary: Vec<u8> = [tlv(&[0x81], &data), tlv(&[0x82], &[])]
            .into_iter()
            .flatten()
            .collect();
        let data = tlv(&[0x7C], &data_intermediary);
        Self::run_bytes(
            &build_command(0x00, 0x87, algo, key_ref, &data, 0xFF),
            output,
            expected_status,
            card,
        );
    }
    fn run_import_rsa_key(
        p: &str,
        q: &str,
        e: &str,
        expected_status: Status,
        card: &mut setup::Piv,
    ) {
        let p = parse_hex(p);
        let q = parse_hex(q);
        let e = parse_hex(e);
        let data: Vec<u8> = [tlv(&[0x01], &p), tlv(&[0x02], &q), tlv(&[0x03], &e)]
            .into_iter()
            .flatten()
            .collect();
        let algo = match p.len() {
            128 => 0x07,
            192 => 0x05,
            256 => 0x16,
            _ => panic!("Invalid RSA key size"),
        };
        Self::run_bytes(
            &build_command(0x00, 0xFE, algo, 0x9A, &data, 0),
            &MATCH_EMPTY,
            expected_status,
            card,
        );
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
        println!("Command: {input:02x?}");
        let mut rep: heapless::Vec<u8, 1024> = heapless::Vec::new();
        let cmd: iso7816::Command<{ setup::COMMAND_SIZE }> = iso7816::Command::try_from(input)
            .unwrap_or_else(|err| {
                panic!("Bad command: {err:?}, for command: {}", hex::encode(input))
            });
        let status: Status = card
            .respond(cmd.as_view(), &mut rep)
            .err()
            .map(Into::into)
            .unwrap_or_default();

        println!(
            "Output({}): {:?}\nStatus: {status:?}",
            rep.len(),
            hex::encode(&rep)
        );

        if !output.validate(&rep) {
            panic!("Bad output. Expected {output:02x?}");
        }
        if status != expected_status {
            panic!("Bad status. Expected {expected_status:?}, got {status:?}");
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

    fn run_get_data(
        input: &str,
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut setup::Piv,
    ) {
        Self::run_bytes(
            &build_command(0x00, 0xCB, 0x3F, 0xFF, &parse_hex(input), 0),
            output,
            expected_status,
            card,
        );
    }

    fn run_put_data(
        input: &str,
        output: &OutputMatcher,
        expected_status: Status,
        card: &mut setup::Piv,
    ) {
        Self::run_bytes(
            &build_command(0x00, 0xDB, 0x3F, 0xFF, &parse_hex(input), 0),
            output,
            expected_status,
            card,
        );
    }

    fn run_authenticate_management_single(
        alg: Algorithm,
        key: &str,
        expected_status_challenge: Status,
        expected_status_response: Status,
        card: &mut setup::Piv,
    ) {
        use aes::Aes256Enc;
        use des::{
            cipher::{BlockEncrypt, KeyInit},
            TdesEde3,
        };
        let command = build_command(0x00, 0x87, alg as u8, 0x9B, &hex!("7C 02 81 00"), 0);
        let mut res = Self::run_bytes(&command, &MATCH_ANY, expected_status_challenge, card);
        let key = parse_hex(key);
        if expected_status_challenge != Status::Success {
            return;
        }

        assert_eq_hex!(
            res[..4],
            [
                0x7C,
                alg.challenge_len() as u8 + 2,
                0x81,
                alg.challenge_len() as u8
            ]
        );
        // Remove header
        let challenge = &mut res[4..];
        assert_eq_hex!(challenge.len(), alg.challenge_len());
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

    fn run_authenticate_management_mutual(
        alg: Algorithm,
        key: &str,
        expected_status_challenge: Status,
        expected_status_response: Status,
        card: &mut setup::Piv,
    ) {
        use aes::Aes256Dec;
        use des::{
            cipher::{BlockDecrypt, KeyInit},
            TdesEde3,
        };
        use rand::RngCore;
        let command = build_command(0x00, 0x87, alg as u8, 0x9B, &hex!("7C 02 80 00"), 0);
        let mut res = Self::run_bytes(&command, &MATCH_ANY, expected_status_challenge, card);
        let key = parse_hex(key);
        if expected_status_challenge != Status::Success {
            return;
        }

        assert_eq_hex!(
            res[..4],
            [
                0x7C,
                alg.challenge_len() as u8 + 2,
                0x80,
                alg.challenge_len() as u8
            ]
        );
        // Remove header
        let challenge = &mut res[4..];
        assert_eq_hex!(challenge.len(), alg.challenge_len());
        match alg {
            Algorithm::Tdes => {
                let cipher = TdesEde3::new(GenericArray::from_slice(&key));
                cipher.decrypt_block(GenericArray::from_mut_slice(challenge));
            }
            Algorithm::Aes256 => {
                let cipher = Aes256Dec::new(GenericArray::from_slice(&key));
                cipher.decrypt_block(GenericArray::from_mut_slice(challenge));
            }
            _ => panic!(),
        }
        let mut random_challenge = vec![0; alg.challenge_len()];
        thread_rng().fill_bytes(&mut random_challenge);
        let challenge_and_random: Vec<u8> =
            [tlv(&[0x80], challenge), tlv(&[0x81], &random_challenge)]
                .into_iter()
                .flatten()
                .collect();
        let second_data = tlv(&[0x7C], &challenge_and_random);
        let command = build_command(0x00, 0x87, alg as u8, 0x9B, &second_data, 0);
        let mut res = Self::run_bytes(&command, &MATCH_ANY, expected_status_response, card);
        if expected_status_response != Status::Success {
            return;
        }
        assert_eq_hex!(
            res[..4],
            [
                0x7C,
                alg.challenge_len() as u8 + 2,
                0x82,
                alg.challenge_len() as u8
            ]
        );
        // Remove header
        let response_challenge = &mut res[4..];
        assert_eq_hex!(response_challenge.len(), alg.challenge_len());
        match alg {
            Algorithm::Tdes => {
                let cipher = TdesEde3::new(GenericArray::from_slice(&key));
                cipher.decrypt_block(GenericArray::from_mut_slice(response_challenge));
            }
            Algorithm::Aes256 => {
                let cipher = Aes256Dec::new(GenericArray::from_slice(&key));
                cipher.decrypt_block(GenericArray::from_mut_slice(response_challenge));
            }
            _ => panic!(),
        }
        assert_eq_hex!(response_challenge, random_challenge);
    }

    fn run_verify_application_pin(pin: &str, expected_status: Status, card: &mut setup::Piv) {
        Self::run_bytes(
            &build_command(0x00, 0x20, 0x00, 0x80, &parse_hex(pin), 0),
            &MATCH_EMPTY,
            expected_status,
            card,
        );
    }

    fn run_verify_global_pin(pin: &str, expected_status: Status, card: &mut setup::Piv) {
        Self::run_bytes(
            &build_command(0x00, 0x20, 0x00, 0x00, &parse_hex(pin), 0),
            &MATCH_EMPTY,
            expected_status,
            card,
        );
    }

    fn run_select(card: &mut setup::Piv) {
        let matcher = OutputMatcher::Bytes(Cow::Borrowed(&hex!(
            "
            61 66 // Card application property template
                4f 06 000010000100 // Application identifier
                50 0c 4e6974726f6b657920504956 // Application label = b\"Nitrokey PIV\"

                // URL = b\"https://github.com/Nitrokey/piv-authenticator\"
                5f50 2d 68747470733a2f2f6769746875622e636f6d2f4e6974726f6b65792f7069762d61757468656e74696361746f72
                // Cryptographic Algorithm Identifier Template
                ac 15
                    80 01 03 // TDES - ECB
                    80 01 0c // AES256 - ECB
                    80 01 11 // P-256
                    80 01 e2 // Ed25519
                    80 01 e3 // X25519
                    80 01 07 // RSA 2048
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
    fn run_reset(expected_status: Status, card: &mut setup::Piv) {
        Self::run_bytes(&hex!("00 FB 00 00"), &MATCH_EMPTY, expected_status, card);
    }

    fn run_change_pin(old: &str, new: &str, status: Status, card: &mut setup::Piv) {
        let command = parse_hex(&format!("{old}{new}"));
        Self::run_bytes(
            &build_command(0, 0x24, 0x00, 0x80, &command, 0x00),
            &MATCH_EMPTY,
            status,
            card,
        );
    }
    fn run_change_puk(old: &str, new: &str, status: Status, card: &mut setup::Piv) {
        let command = parse_hex(&format!("{old}{new}"));
        Self::run_bytes(
            &build_command(0, 0x24, 0x00, 0x81, &command, 0x00),
            &MATCH_EMPTY,
            status,
            card,
        );
    }
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
enum UuidConfig {
    None,
    WithUuid(String),
    WithBoth(String),
}

impl Default for UuidConfig {
    fn default() -> Self {
        Self::WithBoth("00".repeat(16))
    }
}

#[test_log::test]
fn command_response() {
    let data = std::fs::read_to_string("tests/command_response.ron").unwrap();
    let tests: Vec<IoTest> = ron::from_str(&data).unwrap();
    for t in tests {
        println!("\n\n===========================================================",);
        println!("Running {}", t.name);
        if matches!(t.uuid_config, UuidConfig::None | UuidConfig::WithBoth(_)) {
            println!("Running {} without uuid", t.name);
            setup::piv(setup::WITHOUT_UUID, |card| {
                for io in &t.cmd_resp {
                    io.run(card);
                }
            });
        }
        match t.uuid_config {
            UuidConfig::WithUuid(uuid) | UuidConfig::WithBoth(uuid) => {
                println!("Running {} with uuid {uuid:?}", t.name);
                let uuid = (&*parse_hex(&uuid)).try_into().unwrap();

                setup::piv(piv_authenticator::Options::new().uuid(Some(uuid)), |card| {
                    for io in &t.cmd_resp {
                        io.run(card);
                    }
                });
            }
            _ => {}
        }
    }
}
