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
use trussed_chunked::utils;

use crate::piv_types::CardHolderUniqueIdentifier;
use crate::reply::Reply;
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
    pub fn load<T: crate::Client>(
        &mut self,
        client: &mut T,
        options: &crate::Options,
    ) -> Result<LoadedState<'_>, Status> {
        if self.persistent.is_none() {
            self.persistent = Some(Persistent::load_or_initialize(client, options)?);
        }
        Ok(LoadedState {
            volatile: &mut self.volatile,
            persistent: self.persistent.as_mut().unwrap(),
        })
    }

    pub fn persistent<T: crate::Client>(
        &mut self,
        client: &mut T,
        options: &crate::Options,
    ) -> Result<&mut Persistent, Status> {
        Ok(self.load(client, options)?.persistent)
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

/// exists only to please serde, which doesn't accept enum variants in `#[serde(default=…)]`
fn volatile() -> Location {
    Location::Volatile
}

enum PinType {
    Puk,
    UserPin,
}

impl From<PinType> for trussed_auth::PinId {
    fn from(value: PinType) -> Self {
        match value {
            PinType::UserPin => 0.into(),
            PinType::Puk => 1.into(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Persistent {
    pub keys: Keys,
    // Ideally, we'd dogfood a "Monotonic Counter" from `trussed`.
    timestamp: u32,
    #[serde(skip, default = "volatile")]
    storage: Location,
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

    pub fn take_single_challenge(&mut self) -> Option<Bytes<16>> {
        match self.command_cache.take() {
            Some(CommandCache::SingleAuthChallenge(b)) => return Some(b),
            old => self.command_cache = old,
        };
        None
    }

    pub fn take_mutual_challenge(&mut self) -> Option<Bytes<16>> {
        match self.command_cache.take() {
            Some(CommandCache::MutualAuthChallenge(b)) => return Some(b),
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
    SingleAuthChallenge(Bytes<16>),
    MutualAuthChallenge(Bytes<16>),
}

impl Persistent {
    pub const PIN_RETRIES_DEFAULT: u8 = 3;
    // hmm...!
    pub const PUK_RETRIES_DEFAULT: u8 = 5;
    const FILENAME: &'static [u8] = b"persistent-state.cbor";
    const DEFAULT_PIN: Pin = Pin(*b"123456\xff\xff");
    const DEFAULT_PUK: Puk = Puk(*b"12345678");

    pub fn remaining_pin_retries<T: crate::Client>(&self, client: &mut T) -> u8 {
        try_syscall!(client.pin_retries(PinType::UserPin))
            .map(|r| r.retries.unwrap_or_default())
            .unwrap_or(0)
    }

    pub fn remaining_puk_retries<T: crate::Client>(&self, client: &mut T) -> u8 {
        try_syscall!(client.pin_retries(PinType::Puk))
            .map(|r| r.retries.unwrap_or_default())
            .unwrap_or(0)
    }

    pub fn verify_pin<T: crate::Client>(&mut self, value: &Pin, client: &mut T) -> bool {
        let pin = Bytes::from_slice(&value.0).expect("Convertion of static array");
        try_syscall!(client.check_pin(PinType::UserPin, pin))
            .map(|r| r.success)
            .unwrap_or(false)
    }

    pub fn verify_puk<T: crate::Client>(&mut self, value: &Puk, client: &mut T) -> bool {
        let puk = Bytes::from_slice(&value.0).expect("Convertion of static array");
        try_syscall!(client.check_pin(PinType::Puk, puk))
            .map(|r| r.success)
            .unwrap_or(false)
    }

    pub fn change_pin<T: crate::Client>(
        &mut self,
        old_value: &Pin,
        new_value: &Pin,
        client: &mut T,
    ) -> bool {
        let old_pin = Bytes::from_slice(&old_value.0).expect("Convertion of static array");
        let new_pin = Bytes::from_slice(&new_value.0).expect("Convertion of static array");
        try_syscall!(client.change_pin(PinType::UserPin, old_pin, new_pin))
            .map(|r| r.success)
            .unwrap_or(false)
    }

    pub fn change_puk<T: crate::Client>(
        &mut self,
        old_value: &Puk,
        new_value: &Puk,
        client: &mut T,
    ) -> bool {
        let old_puk = Bytes::from_slice(&old_value.0).expect("Convertion of static array");
        let new_puk = Bytes::from_slice(&new_value.0).expect("Convertion of static array");
        try_syscall!(client.change_pin(PinType::Puk, old_puk, new_puk))
            .map(|r| r.success)
            .unwrap_or(false)
    }

    pub fn set_pin<T: crate::Client>(
        &mut self,
        new_pin: Pin,
        client: &mut T,
    ) -> Result<(), Status> {
        let new_pin = Bytes::from_slice(&new_pin.0).expect("Convertion of static array");
        try_syscall!(client.set_pin(
            PinType::UserPin,
            new_pin,
            Some(Self::PIN_RETRIES_DEFAULT),
            true
        ))
        .map_err(|_err| {
            error!("Failed to set pin");
            Status::UnspecifiedPersistentExecutionError
        })
        .map(drop)
    }

    pub fn set_puk<T: crate::Client>(
        &mut self,
        new_puk: Puk,
        client: &mut T,
    ) -> Result<(), Status> {
        let new_puk = Bytes::from_slice(&new_puk.0).expect("Convertion of static array");
        try_syscall!(client.set_pin(PinType::Puk, new_puk, Some(Self::PUK_RETRIES_DEFAULT), true))
            .map_err(|_err| {
                error!("Failed to set puk");
                Status::UnspecifiedPersistentExecutionError
            })
            .map(drop)
    }
    pub fn reset_pin<T: crate::Client>(
        &mut self,
        new_pin: Pin,
        client: &mut T,
    ) -> Result<(), Status> {
        self.set_pin(new_pin, client)
    }
    pub fn reset_puk<T: crate::Client>(
        &mut self,
        new_puk: Puk,
        client: &mut T,
    ) -> Result<(), Status> {
        self.set_puk(new_puk, client)
    }

    pub fn reset_administration_key(&mut self, client: &mut impl crate::Client) {
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
        client: &mut impl crate::Client,
    ) {
        // let new_management_key = syscall!(self.trussed.unsafe_inject_tdes_key(
        let id = syscall!(client.unsafe_inject_key(
            alg.mechanism(),
            management_key,
            self.storage,
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
        client: &mut impl crate::Client,
    ) -> KeyId {
        let id = syscall!(client.generate_key(
            alg.key_mechanism(),
            StorageAttributes::default().set_persistence(self.storage)
        ))
        .key;
        let old = self.set_asymmetric_key(key, id, alg);
        self.save(client);
        if let Some(old) = old {
            syscall!(client.delete(old.id));
        }
        id
    }

    pub fn initialize<T: crate::Client>(
        client: &mut T,
        options: &crate::Options,
    ) -> Result<Self, Status> {
        info!("initializing PIV state");
        let administration = KeyWithAlg {
            id: syscall!(client.unsafe_inject_key(
                YUBICO_DEFAULT_MANAGEMENT_KEY_ALG.mechanism(),
                YUBICO_DEFAULT_MANAGEMENT_KEY,
                options.storage,
                KeySerialization::Raw
            ))
            .key,
            alg: YUBICO_DEFAULT_MANAGEMENT_KEY_ALG,
        };

        let authentication = KeyWithAlg {
            id: syscall!(client.generate_key(
                Mechanism::P256,
                StorageAttributes::new().set_persistence(options.storage)
            ))
            .key,
            alg: AsymmetricAlgorithms::P256,
        };

        let guid = options.uuid.unwrap_or_else(|| {
            let mut guid: [u8; 16] = syscall!(client.random_bytes(16))
                .bytes
                .as_ref()
                .try_into()
                .unwrap();

            guid[6] = (guid[6] & 0xf) | 0x40;
            guid[8] = (guid[8] & 0x3f) | 0x80;
            guid
        });

        let guid_file: Vec<u8, 1024> = CardHolderUniqueIdentifier::default()
            .with_guid(guid)
            .to_heapless_vec()
            .unwrap();
        ContainerStorage(Container::CardHolderUniqueIdentifier)
            .save(
                client,
                &guid_file[2..], // Remove the unnecessary 53 tag
                options.storage,
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
            timestamp: 0,
            storage: options.storage,
        };
        state.save(client);
        state.reset_pin(Self::DEFAULT_PIN, client)?;
        state.reset_puk(Self::DEFAULT_PUK, client)?;
        Ok(state)
    }

    pub fn load_or_initialize<T: crate::Client>(
        client: &mut T,
        options: &crate::Options,
    ) -> Result<Self, Status> {
        // todo: can't seem to combine load + initialize without code repetition
        let data = load_if_exists(client, options.storage, &PathBuf::from(Self::FILENAME))?;
        let Some(bytes) = data else {
            return Self::initialize(client, options);
        };

        let mut parsed: Self = trussed::cbor_deserialize(&bytes).map_err(|_err| {
            error!("{_err:?}");
            Status::UnspecifiedPersistentExecutionError
        })?;
        parsed.storage = options.storage;
        Ok(parsed)
    }

    pub fn save(&mut self, client: &mut impl crate::Client) {
        let data: trussed::types::Message = trussed::cbor_serialize_bytes(&self).unwrap();

        syscall!(client.write_file(self.storage, PathBuf::from(Self::FILENAME), data, None,));
    }

    pub fn timestamp(&mut self, client: &mut impl crate::Client) -> u32 {
        self.timestamp += 1;
        self.save(client);
        self.timestamp
    }
}

fn load_if_exists(
    client: &mut impl crate::Client,
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

/// Returns false if the file does not exist
fn load_if_exists_streaming<const R: usize>(
    client: &mut impl crate::Client,
    location: Location,
    path: &PathBuf,
    mut buffer: Reply<'_, R>,
) -> Result<bool, Status> {
    let mut read_len = 0;
    let file_len;
    match try_syscall!(client.start_chunked_read(location, path.clone())) {
        Ok(r) => {
            read_len += r.data.len();
            file_len = r.len;
            buffer.append_len(file_len)?;
            buffer.expand(&r.data)?;
            if !r.data.is_full() {
                debug_assert_eq!(read_len, file_len);
                return Ok(true);
            }
        }
        Err(_err) => match try_syscall!(client.entry_metadata(location, path.clone())) {
            Ok(Metadata { metadata: None }) => return Ok(false),
            Ok(Metadata {
                metadata: Some(_metadata),
            }) => {
                error!("File {path} exists but couldn't be read: {_metadata:?}, {_err:?}");
                return Err(Status::UnspecifiedPersistentExecutionError);
            }
            Err(_err) => {
                error!("File {path} couldn't be read: {_err:?}");
                return Err(Status::UnspecifiedPersistentExecutionError);
            }
        },
    }

    loop {
        match try_syscall!(client.read_file_chunk()) {
            Ok(r) => {
                debug_assert_eq!(r.len, file_len);
                read_len += r.data.len();
                buffer.expand(&r.data)?;
                if !r.data.is_full() {
                    debug_assert_eq!(read_len, file_len);
                    break;
                }
            }
            Err(_err) => {
                error!("Failed to read chunk: {:?}", _err);
            }
        }
    }

    Ok(true)
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
            Container::CardCapabilityContainer => Some(Vec::from_slice(&CARD_CAP).unwrap()),
            Container::DiscoveryObject => Some(Vec::from_slice(&DISCOVERY_OBJECT).unwrap()),
            _ => None,
        }
    }

    pub fn exists(
        self,
        client: &mut impl crate::Client,
        storage: Location,
    ) -> Result<bool, Status> {
        match try_syscall!(client.entry_metadata(storage, self.path())) {
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

    // Write the length of the file and write
    pub fn load<const R: usize>(
        self,
        client: &mut impl crate::Client,
        storage: Location,
        mut reply: Reply<'_, R>,
    ) -> Result<bool, Status> {
        if load_if_exists_streaming(client, storage, &self.path(), reply.lend())? {
            return Ok(true);
        }

        if let Some(data) = self.default() {
            reply.append_len(data.len())?;
            reply.expand(&data)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn save(
        self,
        client: &mut impl crate::Client,
        bytes: &[u8],
        storage: Location,
    ) -> Result<(), Status> {
        utils::write_all(client, storage, self.path(), bytes, None, None).map_err(|_err| {
            error!("Failed to write data object: {:?}", _err);
            Status::UnspecifiedNonpersistentExecutionError
        })
    }
}
