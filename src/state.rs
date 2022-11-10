// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use core::convert::{TryFrom, TryInto};

use heapless_bytes::Bytes;
use iso7816::Status;
use trussed::{
    api::reply::Metadata,
    config::MAX_MESSAGE_LENGTH,
    syscall, try_syscall,
    types::{KeyId, Location, Mechanism, PathBuf},
};

use crate::constants::*;
use crate::piv_types::Algorithms;

use crate::{Pin, Puk};

pub enum Key {
    Ed25519(KeyId),
    P256(KeyId),
    X25519(KeyId),
}
pub enum PinPolicy {
    Never,
    Once,
    Always,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
}

pub struct Slot {
    pub key: Option<KeyId>,
    pub pin_policy: PinPolicy,
    // touch_policy: TouchPolicy,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            key: None,
            pin_policy: PinPolicy::Once, /*touch_policy: TouchPolicy::Never*/
        }
    }
}

impl Slot {
    pub fn default(name: SlotName) -> Self {
        use SlotName::*;
        match name {
            // Management => Slot { pin_policy: PinPolicy::Never, ..Default::default() },
            Signature => Slot {
                pin_policy: PinPolicy::Always,
                ..Default::default()
            },
            Pinless => Slot {
                pin_policy: PinPolicy::Never,
                ..Default::default()
            },
            _ => Default::default(),
        }
    }
}

pub struct RetiredSlotIndex(u8);

impl core::convert::TryFrom<u8> for RetiredSlotIndex {
    type Error = u8;
    fn try_from(i: u8) -> core::result::Result<Self, Self::Error> {
        if (1..=20).contains(&i) {
            Ok(Self(i))
        } else {
            Err(i)
        }
    }
}
pub enum SlotName {
    Identity,
    Management, // Personalization? Administration?
    Signature,
    Decryption, // Management after all?
    Pinless,
    Retired(RetiredSlotIndex),
    Attestation,
}

impl SlotName {
    pub fn default_pin_policy(&self) -> PinPolicy {
        use PinPolicy::*;
        use SlotName::*;
        match *self {
            Signature => Always,
            Pinless | Management | Attestation => Never,
            _ => Once,
        }
    }

    pub fn default_slot(&self) -> Slot {
        Slot {
            key: None,
            pin_policy: self.default_pin_policy(),
        }
    }

    pub fn reference(&self) -> u8 {
        use SlotName::*;
        match *self {
            Identity => 0x9a,
            Management => 0x9b,
            Signature => 0x9c,
            Decryption => 0x9d,
            Pinless => 0x9e,
            Retired(RetiredSlotIndex(i)) => 0x81 + i,
            Attestation => 0xf9,
        }
    }
    pub fn tag(&self) -> u32 {
        use SlotName::*;
        match *self {
            Identity => 0x5fc105,
            Management => 0,
            Signature => 0x5fc10a,
            Decryption => 0x5fc10b,
            Pinless => 0x5fc101,
            Retired(RetiredSlotIndex(i)) => 0x5fc10c + i as u32,
            Attestation => 0x5fff01,
        }
    }
}

crate::container::enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
    pub enum ManagementAlgorithm: Algorithms {
        Tdes,
        Aes256
    }
}

impl ManagementAlgorithm {
    pub fn challenge_length(self) -> usize {
        match self {
            Self::Tdes => 8,
            Self::Aes256 => 16,
        }
    }

    pub fn mechanism(self) -> Mechanism {
        match self {
            Self::Tdes => Mechanism::Tdes,
            Self::Aes256 => Mechanism::Aes256Cbc,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ManagementKey {
    pub id: KeyId,
    pub alg: ManagementAlgorithm,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Keys {
    // 9a "PIV Authentication Key" (YK: PIV Authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_key: Option<KeyId>,
    // 9b "PIV Card Application Administration Key" (YK: PIV Management)
    pub management_key: ManagementKey,
    // 9c "Digital Signature Key" (YK: Digital Signature)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_key: Option<KeyId>,
    // 9d "Key Management Key" (YK: Key Management)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<KeyId>,
    // 9e "Card Authentication Key" (YK: Card Authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinless_authentication_key: Option<KeyId>,
    // 0x82..=0x95 (130-149)
    pub retired_keys: [Option<KeyId>; 20],
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct State {
    pub runtime: Runtime,
    pub persistent: Option<Persistent>,
}

impl State {
    pub fn load(&mut self, client: &mut impl trussed::Client) -> Result<LoadedState<'_>, Status> {
        if self.persistent.is_none() {
            self.persistent = Some(Persistent::load_or_initialize(client)?);
        }
        Ok(LoadedState {
            runtime: &mut self.runtime,
            persistent: self.persistent.as_mut().unwrap(),
        })
    }

    pub fn persistent(
        &mut self,
        client: &mut impl trussed::Client,
    ) -> Result<&mut Persistent, Status> {
        Ok(self.load(client)?.persistent)
    }

    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LoadedState<'t> {
    pub runtime: &'t mut Runtime,
    pub persistent: &'t mut Persistent,
}

#[derive(Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Persistent {
    pub keys: Keys,
    consecutive_pin_mismatches: u8,
    consecutive_puk_mismatches: u8,
    // the PIN can be 6-8 digits, padded with 0xFF if <8
    // we just store all of them for now.
    pin: Pin,
    // the PUK should be 8 digits, but it seems Yubico allows 6-8
    // like for PIN
    puk: Puk,
    // pin_hash: Option<[u8; 16]>,
    // Ideally, we'd dogfood a "Monotonic Counter" from `trussed`.
    timestamp: u32,
    // must be a valid RFC 4122 UUID 1, 2 or 4
    guid: [u8; 16],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Runtime {
    // aid: Option<
    // consecutive_pin_mismatches: u8,
    pub global_security_status: GlobalSecurityStatus,
    // pub currently_selected_application: SelectableAid,
    pub app_security_status: AppSecurityStatus,
    pub command_cache: Option<CommandCache>,
}

// pub trait Aid {
//     const AID: &'static [u8];
//     const RIGHT_TRUNCATED_LENGTH: usize;

//     fn len() -> usize {
//         Self::AID.len()
//     }

//     fn full() -> &'static [u8] {
//         Self::AID
//     }

//     fn right_truncated() -> &'static [u8] {
//         &Self::AID[..Self::RIGHT_TRUNCATED_LENGTH]
//     }

//     fn pix() -> &'static [u8] {
//         &Self::AID[5..]
//     }

//     fn rid() -> &'static [u8] {
//         &Self::AID[..5]
//     }
// }

// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
// pub enum SelectableAid {
//     Piv(PivAid),
//     YubicoOtp(YubicoOtpAid),
// }

// impl Default for SelectableAid {
//     fn default() -> Self {
//         Self::Piv(Default::default())
//     }
// }

// #[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
// pub struct PivAid {}

// impl Aid for PivAid {
//     const AID: &'static [u8] = &PIV_AID;
//     const RIGHT_TRUNCATED_LENGTH: usize = 9;
// }

// #[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
// pub struct YubicoOtpAid {}

// impl Aid for YubicoOtpAid {
//     const AID: &'static [u8] = &YUBICO_OTP_AID;
//     const RIGHT_TRUNCATED_LENGTH: usize = 8;
// }

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GlobalSecurityStatus {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecurityStatus {
    JustVerified,
    Verified,
    NotVerified,
}

impl Default for SecurityStatus {
    fn default() -> Self {
        Self::NotVerified
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppSecurityStatus {
    pub pin_verified: bool,
    pub puk_verified: bool,
    pub management_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandCache {
    GetData(GetData),
    AuthenticateChallenge(Bytes<16>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetData {}

impl Persistent {
    pub const PIN_RETRIES_DEFAULT: u8 = 3;
    // hmm...!
    pub const PUK_RETRIES_DEFAULT: u8 = 5;
    const FILENAME: &'static [u8] = b"persistent-state.cbor";
    const DEFAULT_PIN: &'static [u8] = b"123456\xff\xff";
    const DEFAULT_PUK: &'static [u8] = b"12345678";

    pub fn guid(&self) -> [u8; 16] {
        self.guid
    }

    pub fn remaining_pin_retries(&self) -> u8 {
        if self.consecutive_pin_mismatches >= Self::PIN_RETRIES_DEFAULT {
            0
        } else {
            Self::PIN_RETRIES_DEFAULT - self.consecutive_pin_mismatches
        }
    }

    pub fn remaining_puk_retries(&self) -> u8 {
        if self.consecutive_puk_mismatches >= Self::PUK_RETRIES_DEFAULT {
            0
        } else {
            Self::PUK_RETRIES_DEFAULT - self.consecutive_puk_mismatches
        }
    }

    // FIXME: revisit with trussed pin management
    pub fn verify_pin(&self, other_pin: &Pin) -> bool {
        // hprintln!("verifying pin {:?} against {:?}", other_pin, &self.pin).ok();
        self.pin == *other_pin
    }

    // FIXME: revisit with trussed pin management
    pub fn verify_puk(&self, other_puk: &Puk) -> bool {
        // hprintln!("verifying puk {:?} against {:?}", other_puk, &self.puk).ok();
        self.puk == *other_puk
    }

    pub fn set_pin(&mut self, new_pin: Pin, client: &mut impl trussed::Client) {
        self.pin = new_pin;
        self.save(client);
    }

    pub fn set_puk(&mut self, new_puk: Puk, client: &mut impl trussed::Client) {
        self.puk = new_puk;
        self.save(client);
    }

    pub fn reset_pin(&mut self, client: &mut impl trussed::Client) {
        self.set_pin(Pin::try_from(Self::DEFAULT_PIN).unwrap(), client);
        self.reset_consecutive_pin_mismatches(client);
    }

    pub fn reset_puk(&mut self, client: &mut impl trussed::Client) {
        self.set_puk(Puk::try_from(Self::DEFAULT_PUK).unwrap(), client);
        self.reset_consecutive_puk_mismatches(client);
    }

    pub fn increment_consecutive_pin_mismatches(
        &mut self,
        client: &mut impl trussed::Client,
    ) -> u8 {
        if self.consecutive_pin_mismatches >= Self::PIN_RETRIES_DEFAULT {
            return 0;
        }

        self.consecutive_pin_mismatches += 1;
        self.save(client);
        Self::PIN_RETRIES_DEFAULT - self.consecutive_pin_mismatches
    }

    pub fn increment_consecutive_puk_mismatches(
        &mut self,
        client: &mut impl trussed::Client,
    ) -> u8 {
        if self.consecutive_puk_mismatches >= Self::PUK_RETRIES_DEFAULT {
            return 0;
        }

        self.consecutive_puk_mismatches += 1;
        self.save(client);
        Self::PUK_RETRIES_DEFAULT - self.consecutive_puk_mismatches
    }

    pub fn reset_consecutive_pin_mismatches(&mut self, client: &mut impl trussed::Client) -> u8 {
        if self.consecutive_pin_mismatches != 0 {
            self.consecutive_pin_mismatches = 0;
            self.save(client);
        }

        Self::PIN_RETRIES_DEFAULT
    }

    pub fn reset_consecutive_puk_mismatches(&mut self, client: &mut impl trussed::Client) -> u8 {
        if self.consecutive_puk_mismatches != 0 {
            self.consecutive_puk_mismatches = 0;
            self.save(client);
        }

        Self::PUK_RETRIES_DEFAULT
    }

    pub fn reset_management_key(&mut self, client: &mut impl trussed::Client) {
        self.set_management_key(YUBICO_DEFAULT_MANAGEMENT_KEY, client);
    }

    pub fn set_management_key(
        &mut self,
        management_key: &[u8; 24],
        client: &mut impl trussed::Client,
    ) {
        // let new_management_key = syscall!(self.trussed.unsafe_inject_tdes_key(
        let new_management_key =
            syscall!(client
                .unsafe_inject_shared_key(management_key, trussed::types::Location::Internal,))
            .key;
        let old_management_key = self.keys.management_key.id;
        self.keys.management_key.id = new_management_key;
        self.save(client);
        syscall!(client.delete(old_management_key));
    }

    pub fn initialize(client: &mut impl trussed::Client) -> Self {
        info!("initializing PIV state");
        let management_key = ManagementKey {
            id: syscall!(client.unsafe_inject_shared_key(
                YUBICO_DEFAULT_MANAGEMENT_KEY,
                trussed::types::Location::Internal,
            ))
            .key,
            alg: YUBICO_DEFAULT_MANAGEMENT_KEY_ALG,
        };

        let mut guid: [u8; 16] = syscall!(client.random_bytes(16))
            .bytes
            .as_ref()
            .try_into()
            .unwrap();

        guid[6] = (guid[6] & 0xf) | 0x40;
        guid[8] = (guid[8] & 0x3f) | 0x80;

        let keys = Keys {
            authentication_key: None,
            management_key,
            signature_key: None,
            encryption_key: None,
            pinless_authentication_key: None,
            retired_keys: Default::default(),
        };

        let mut state = Self {
            keys,
            consecutive_pin_mismatches: 0,
            consecutive_puk_mismatches: 0,
            pin: Pin::try_from(Self::DEFAULT_PIN).unwrap(),
            puk: Puk::try_from(Self::DEFAULT_PUK).unwrap(),
            timestamp: 0,
            guid,
        };
        state.save(client);
        state
    }

    pub fn load_or_initialize(client: &mut impl trussed::Client) -> Result<Self, Status> {
        // todo: can't seem to combine load + initialize without code repetition
        let data = load_if_exists(client, Location::Internal, &PathBuf::from(Self::FILENAME))?;
        let Some(bytes) = data else {
            return Ok( Self::initialize(client));
        };

        let parsed = trussed::cbor_deserialize(&bytes).map_err(|_err| {
            error!("{_err:?}");
            Status::UnspecifiedPersistentExecutionError
        })?;
        Ok(parsed)
    }

    pub fn save(&mut self, client: &mut impl trussed::Client) {
        let data: trussed::types::Message = trussed::cbor_serialize_bytes(&self).unwrap();

        syscall!(client.write_file(
            Location::Internal,
            PathBuf::from(Self::FILENAME),
            data,
            None,
        ));
    }

    pub fn timestamp(&mut self, client: &mut impl trussed::Client) -> u32 {
        self.timestamp += 1;
        self.save(client);
        self.timestamp
    }
}

fn load_if_exists(
    client: &mut impl trussed::Client,
    location: Location,
    path: &PathBuf,
) -> Result<Option<Bytes<MAX_MESSAGE_LENGTH>>, Status> {
    match try_syscall!(client.read_file(location, path.clone())) {
        Ok(r) => Ok(Some(r.data)),
        Err(_) => match try_syscall!(client.entry_metadata(location, path.clone())) {
            Ok(Metadata { metadata: None }) => Ok(None),
            Ok(Metadata {
                metadata: Some(_metadata),
            }) => {
                error!("File {path} exists but couldn't be read: {_metadata:?}");
                Err(Status::UnspecifiedPersistentExecutionError)
            }
            Err(_err) => {
                error!("File {path} couldn't be read: {_err:?}");
                Err(Status::UnspecifiedPersistentExecutionError)
            }
        },
    }
}
