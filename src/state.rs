// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use core::convert::{TryFrom, TryInto};
use core::mem::replace;

use flexiber::EncodableHeapless;
use heapless::Vec;
use heapless_bytes::Bytes;
use iso7816::Status;
use trussed::{
    api::reply::Metadata,
    config::MAX_MESSAGE_LENGTH,
    syscall, try_syscall,
    types::{KeyId, KeySerialization, Location, Mechanism, PathBuf, StorageAttributes},
};

use crate::piv_types::CardHolderUniqueIdentifier;
use crate::{constants::*, piv_types::AsymmetricAlgorithms};
use crate::{
    container::{AsymmetricKeyReference, Container, ReadAccessRule, SecurityCondition},
    piv_types::Algorithms,
};

use crate::{Pin, Puk};

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

crate::container::enum_subset! {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub enum AdministrationAlgorithm: Algorithms {
        Tdes,
        Aes256
    }
}

impl AdministrationAlgorithm {
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

    pub fn key_len(self) -> usize {
        match self {
            Self::Tdes => 24,
            Self::Aes256 => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct KeyWithAlg<A> {
    pub id: KeyId,
    pub alg: A,
}

macro_rules! generate_into_key_with_alg {
    ($($name:ident),*) => {
        $(
            impl From<KeyWithAlg<$name>> for KeyWithAlg<Algorithms> {
                fn from(other: KeyWithAlg<$name>) -> Self {
                    KeyWithAlg {
                        id: other.id,
                        alg: other.alg.into()
                    }
                }
            }
        )*
    };
}

generate_into_key_with_alg!(AsymmetricAlgorithms, AdministrationAlgorithm);

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Keys {
    // 9a "PIV Authentication Key" (YK: PIV Authentication)
    pub authentication: KeyWithAlg<AsymmetricAlgorithms>,
    // 9b "PIV Card Application Administration Key" (YK: PIV Management)
    pub administration: KeyWithAlg<AdministrationAlgorithm>,
    pub is_admin_default: bool,
    // 9c "Digital Signature Key" (YK: Digital Signature)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<KeyWithAlg<AsymmetricAlgorithms>>,
    // 9d "Key Management Key" (YK: Key Management)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_management: Option<KeyWithAlg<AsymmetricAlgorithms>>,
    // 9e "Card Authentication Key" (YK: Card Authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_authentication: Option<KeyWithAlg<AsymmetricAlgorithms>>,
    // 0x82..=0x95 (130-149)
    pub retired_keys: [Option<KeyWithAlg<AsymmetricAlgorithms>>; 20],
    // pub secure_messaging
}

impl Keys {
    pub fn asymetric_for_reference(
        &self,
        key: AsymmetricKeyReference,
    ) -> Option<KeyWithAlg<AsymmetricAlgorithms>> {
        match key {
            AsymmetricKeyReference::PivAuthentication => Some(self.authentication),
            AsymmetricKeyReference::DigitalSignature => self.signature,
            AsymmetricKeyReference::KeyManagement => self.key_management,
            AsymmetricKeyReference::CardAuthentication => self.card_authentication,
            AsymmetricKeyReference::Retired01 => self.retired_keys[1],
            AsymmetricKeyReference::Retired02 => self.retired_keys[2],
            AsymmetricKeyReference::Retired03 => self.retired_keys[3],
            AsymmetricKeyReference::Retired04 => self.retired_keys[4],
            AsymmetricKeyReference::Retired05 => self.retired_keys[5],
            AsymmetricKeyReference::Retired06 => self.retired_keys[6],
            AsymmetricKeyReference::Retired07 => self.retired_keys[7],
            AsymmetricKeyReference::Retired08 => self.retired_keys[8],
            AsymmetricKeyReference::Retired09 => self.retired_keys[9],
            AsymmetricKeyReference::Retired10 => self.retired_keys[10],
            AsymmetricKeyReference::Retired11 => self.retired_keys[11],
            AsymmetricKeyReference::Retired12 => self.retired_keys[12],
            AsymmetricKeyReference::Retired13 => self.retired_keys[13],
            AsymmetricKeyReference::Retired14 => self.retired_keys[14],
            AsymmetricKeyReference::Retired15 => self.retired_keys[15],
            AsymmetricKeyReference::Retired16 => self.retired_keys[16],
            AsymmetricKeyReference::Retired17 => self.retired_keys[17],
            AsymmetricKeyReference::Retired18 => self.retired_keys[18],
            AsymmetricKeyReference::Retired19 => self.retired_keys[19],
            AsymmetricKeyReference::Retired20 => self.retired_keys[20],
        }
    }

    pub fn set_asymetric_for_reference(
        &mut self,
        key: AsymmetricKeyReference,
        new: KeyWithAlg<AsymmetricAlgorithms>,
    ) -> Option<KeyWithAlg<AsymmetricAlgorithms>> {
        match key {
            AsymmetricKeyReference::PivAuthentication => {
                Some(replace(&mut self.authentication, new))
            }
            AsymmetricKeyReference::DigitalSignature => self.signature.replace(new),
            AsymmetricKeyReference::KeyManagement => self.key_management.replace(new),
            AsymmetricKeyReference::CardAuthentication => self.card_authentication.replace(new),
            AsymmetricKeyReference::Retired01 => self.retired_keys[1].replace(new),
            AsymmetricKeyReference::Retired02 => self.retired_keys[2].replace(new),
            AsymmetricKeyReference::Retired03 => self.retired_keys[3].replace(new),
            AsymmetricKeyReference::Retired04 => self.retired_keys[4].replace(new),
            AsymmetricKeyReference::Retired05 => self.retired_keys[5].replace(new),
            AsymmetricKeyReference::Retired06 => self.retired_keys[6].replace(new),
            AsymmetricKeyReference::Retired07 => self.retired_keys[7].replace(new),
            AsymmetricKeyReference::Retired08 => self.retired_keys[8].replace(new),
            AsymmetricKeyReference::Retired09 => self.retired_keys[9].replace(new),
            AsymmetricKeyReference::Retired10 => self.retired_keys[10].replace(new),
            AsymmetricKeyReference::Retired11 => self.retired_keys[11].replace(new),
            AsymmetricKeyReference::Retired12 => self.retired_keys[12].replace(new),
            AsymmetricKeyReference::Retired13 => self.retired_keys[13].replace(new),
            AsymmetricKeyReference::Retired14 => self.retired_keys[14].replace(new),
            AsymmetricKeyReference::Retired15 => self.retired_keys[15].replace(new),
            AsymmetricKeyReference::Retired16 => self.retired_keys[16].replace(new),
            AsymmetricKeyReference::Retired17 => self.retired_keys[17].replace(new),
            AsymmetricKeyReference::Retired18 => self.retired_keys[18].replace(new),
            AsymmetricKeyReference::Retired19 => self.retired_keys[19].replace(new),
            AsymmetricKeyReference::Retired20 => self.retired_keys[20].replace(new),
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct State {
    pub volatile: Volatile,
    pub persistent: Option<Persistent>,
}

impl State {
    pub fn load(&mut self, client: &mut impl trussed::Client) -> Result<LoadedState<'_>, Status> {
        if self.persistent.is_none() {
            self.persistent = Some(Persistent::load_or_initialize(client)?);
        }
        Ok(LoadedState {
            volatile: &mut self.volatile,
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
    pub volatile: &'t mut Volatile,
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Volatile {
    // aid: Option<
    // consecutive_pin_mismatches: u8,
    pub global_security_status: GlobalSecurityStatus,
    // pub currently_selected_application: SelectableAid,
    pub app_security_status: AppSecurityStatus,
    pub command_cache: Option<CommandCache>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GlobalSecurityStatus {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecurityStatus {
    JustVerified,
    Verified,
    NotVerified,
}

impl Volatile {
    pub fn security_valid(&self, condition: SecurityCondition) -> bool {
        use SecurityCondition::*;
        match condition {
            Pin => self.app_security_status.pin_verified,
            Always => true,
        }
    }

    pub fn read_valid(&self, condition: ReadAccessRule) -> bool {
        use ReadAccessRule::*;
        match condition {
            Pin | PinOrOcc => self.app_security_status.pin_verified,
            Always => true,
        }
    }

    pub fn take_witness(&mut self) -> Option<Bytes<16>> {
        match self.command_cache.take() {
            Some(CommandCache::WitnessChallenge(b)) => return Some(b),
            old => self.command_cache = old,
        };
        None
    }

    pub fn take_challenge(&mut self) -> Option<Bytes<16>> {
        match self.command_cache.take() {
            Some(CommandCache::AuthenticateChallenge(b)) => return Some(b),
            old => self.command_cache = old,
        };
        None
    }
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
    pub administrator_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandCache {
    GetData(GetData),
    AuthenticateChallenge(Bytes<16>),
    WitnessChallenge(Bytes<16>),
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
    pub fn verify_pin(&mut self, other_pin: &Pin, client: &mut impl trussed::Client) -> bool {
        if self.remaining_pin_retries() == 0 {
            return false;
        }
        self.consecutive_pin_mismatches += 1;
        self.save(client);
        if self.pin == *other_pin {
            self.consecutive_pin_mismatches = 0;
            true
        } else {
            false
        }
    }

    // FIXME: revisit with trussed pin management
    pub fn verify_puk(&mut self, other_puk: &Puk, client: &mut impl trussed::Client) -> bool {
        if self.remaining_puk_retries() == 0 {
            return false;
        }
        self.consecutive_puk_mismatches += 1;
        self.save(client);
        if self.puk == *other_puk {
            self.consecutive_puk_mismatches = 0;
            true
        } else {
            false
        }
    }

    pub fn set_pin(&mut self, new_pin: Pin, client: &mut impl trussed::Client) {
        self.pin = new_pin;
        self.consecutive_pin_mismatches = 0;
        self.save(client);
    }

    pub fn set_puk(&mut self, new_puk: Puk, client: &mut impl trussed::Client) {
        self.puk = new_puk;
        self.consecutive_puk_mismatches = 0;
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

    pub fn reset_administration_key(&mut self, client: &mut impl trussed::Client) {
        self.set_administration_key(
            YUBICO_DEFAULT_MANAGEMENT_KEY,
            YUBICO_DEFAULT_MANAGEMENT_KEY_ALG,
            client,
        );
    }

    pub fn set_administration_key(
        &mut self,
        management_key: &[u8],
        alg: AdministrationAlgorithm,
        client: &mut impl trussed::Client,
    ) {
        // let new_management_key = syscall!(self.trussed.unsafe_inject_tdes_key(
        let id = syscall!(client.unsafe_inject_key(
            alg.mechanism(),
            management_key,
            trussed::types::Location::Internal,
            KeySerialization::Raw
        ))
        .key;
        let old_management_key = self.keys.administration.id;
        self.keys.administration = KeyWithAlg { id, alg };
        self.save(client);
        syscall!(client.delete(old_management_key));
    }

    fn set_asymmetric_key(
        &mut self,
        key: AsymmetricKeyReference,
        id: KeyId,
        alg: AsymmetricAlgorithms,
    ) -> Option<KeyWithAlg<AsymmetricAlgorithms>> {
        self.keys
            .set_asymetric_for_reference(key, KeyWithAlg { id, alg })
    }

    pub fn generate_asymmetric_key(
        &mut self,
        key: AsymmetricKeyReference,
        alg: AsymmetricAlgorithms,
        client: &mut impl trussed::Client,
    ) -> KeyId {
        let id = syscall!(client.generate_key(
            alg.key_mechanism(),
            StorageAttributes::default().set_persistence(Location::Internal)
        ))
        .key;
        let old = self.set_asymmetric_key(key, id, alg);
        self.save(client);
        if let Some(old) = old {
            syscall!(client.delete(old.id));
        }
        id
    }

    pub fn initialize(client: &mut impl trussed::Client) -> Self {
        info!("initializing PIV state");
        let administration = KeyWithAlg {
            id: syscall!(client.unsafe_inject_key(
                YUBICO_DEFAULT_MANAGEMENT_KEY_ALG.mechanism(),
                YUBICO_DEFAULT_MANAGEMENT_KEY,
                trussed::types::Location::Internal,
                KeySerialization::Raw
            ))
            .key,
            alg: YUBICO_DEFAULT_MANAGEMENT_KEY_ALG,
        };

        let authentication = KeyWithAlg {
            id: syscall!(client.generate_key(
                Mechanism::P256,
                StorageAttributes::new().set_persistence(Location::Internal)
            ))
            .key,
            alg: AsymmetricAlgorithms::P256,
        };

        let mut guid: [u8; 16] = syscall!(client.random_bytes(16))
            .bytes
            .as_ref()
            .try_into()
            .unwrap();

        guid[6] = (guid[6] & 0xf) | 0x40;
        guid[8] = (guid[8] & 0x3f) | 0x80;

        let guid_file: Vec<u8, 1024> = CardHolderUniqueIdentifier::default()
            .with_guid(guid)
            .to_heapless_vec()
            .unwrap();
        ContainerStorage(Container::CardHolderUniqueIdentifier)
            .save(
                client,
                &guid_file[2..], // Remove the unnecessary 53 tag
            )
            .ok();

        let keys = Keys {
            authentication,
            administration,
            is_admin_default: true,
            signature: None,
            key_management: None,
            card_authentication: None,
            retired_keys: Default::default(),
        };

        let mut state = Self {
            keys,
            consecutive_pin_mismatches: 0,
            consecutive_puk_mismatches: 0,
            pin: Pin::try_from(Self::DEFAULT_PIN).unwrap(),
            puk: Puk::try_from(Self::DEFAULT_PUK).unwrap(),
            timestamp: 0,
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

#[derive(Clone, Copy, Debug)]
pub struct ContainerStorage(pub Container);

impl ContainerStorage {
    fn path(self) -> PathBuf {
        PathBuf::from(match self.0 {
            Container::CardCapabilityContainer => "CardCapabilityContainer",
            Container::CardHolderUniqueIdentifier => "CardHolderUniqueIdentifier",
            Container::X509CertificateFor9A => "X509CertificateFor9A",
            Container::CardholderFingerprints => "CardholderFingerprints",
            Container::SecurityObject => "SecurityObject",
            Container::CardholderFacialImage => "CardholderFacialImage",
            Container::X509CertificateFor9E => "X509CertificateFor9E",
            Container::X509CertificateFor9C => "X509CertificateFor9C",
            Container::X509CertificateFor9D => "X509CertificateFor9D",
            Container::PrintedInformation => "PrintedInformation",
            Container::DiscoveryObject => "DiscoveryObject",
            Container::KeyHistoryObject => "KeyHistoryObject",
            Container::RetiredCert01 => "RetiredCert01",
            Container::RetiredCert02 => "RetiredCert02",
            Container::RetiredCert03 => "RetiredCert03",
            Container::RetiredCert04 => "RetiredCert04",
            Container::RetiredCert05 => "RetiredCert05",
            Container::RetiredCert06 => "RetiredCert06",
            Container::RetiredCert07 => "RetiredCert07",
            Container::RetiredCert08 => "RetiredCert08",
            Container::RetiredCert09 => "RetiredCert09",
            Container::RetiredCert10 => "RetiredCert10",
            Container::RetiredCert11 => "RetiredCert11",
            Container::RetiredCert12 => "RetiredCert12",
            Container::RetiredCert13 => "RetiredCert13",
            Container::RetiredCert14 => "RetiredCert14",
            Container::RetiredCert15 => "RetiredCert15",
            Container::RetiredCert16 => "RetiredCert16",
            Container::RetiredCert17 => "RetiredCert17",
            Container::RetiredCert18 => "RetiredCert18",
            Container::RetiredCert19 => "RetiredCert19",
            Container::RetiredCert20 => "RetiredCert20",
            Container::CardholderIrisImages => "CardholderIrisImages",
            Container::BiometricInformationTemplatesGroupTemplate => {
                "BiometricInformationTemplatesGroupTemplate"
            }
            Container::SecureMessagingCertificateSigner => "SecureMessagingCertificateSigner",
            Container::PairingCodeReferenceDataContainer => "PairingCodeReferenceDataContainer",
        })
    }

    fn default(self) -> Option<Vec<u8, MAX_MESSAGE_LENGTH>> {
        match self.0 {
            Container::CardHolderUniqueIdentifier => panic!("CHUID should alway be set"),
            Container::CardCapabilityContainer => Some(
                crate::piv_types::CardCapabilityContainer::default()
                    .to_heapless_vec()
                    .unwrap(),
            ),
            Container::DiscoveryObject => Some(Vec::from_slice(&DISCOVERY_OBJECT).unwrap()),
            _ => None,
        }
    }

    pub fn exists(self, client: &mut impl trussed::Client) -> Result<bool, Status> {
        match try_syscall!(client.entry_metadata(Location::Internal, self.path())) {
            Ok(Metadata { metadata: None }) => Ok(false),
            Ok(Metadata {
                metadata: Some(metadata),
            }) if metadata.is_file() => Ok(true),
            Ok(Metadata {
                metadata: Some(_metadata),
            }) => {
                error!(
                    "File {} exists but isn't a file: {_metadata:?}",
                    self.path()
                );
                Err(Status::UnspecifiedPersistentExecutionError)
            }
            Err(_err) => {
                error!("File {} couldn't be read: {_err:?}", self.path());
                Err(Status::UnspecifiedPersistentExecutionError)
            }
        }
    }

    pub fn load(
        self,
        client: &mut impl trussed::Client,
    ) -> Result<Option<Bytes<MAX_MESSAGE_LENGTH>>, Status> {
        load_if_exists(client, Location::Internal, &self.path())
            .map(|data| data.or_else(|| self.default().map(Bytes::from)))
    }

    pub fn save(self, client: &mut impl trussed::Client, bytes: &[u8]) -> Result<(), Status> {
        let msg = Bytes::from(heapless::Vec::try_from(bytes).map_err(|_| {
            error!("Buffer full");
            Status::IncorrectDataParameter
        })?);
        try_syscall!(client.write_file(Location::Internal, self.path(), msg, None)).map_err(
            |_err| {
                error!("Failed to store data: {_err:?}");
                Status::UnspecifiedNonpersistentExecutionError
            },
        )?;
        Ok(())
    }
}
