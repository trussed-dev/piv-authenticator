use core::convert::{TryFrom, TryInto};
use core::mem;

use flexiber::EncodableHeapless;
use heapless::Vec;
use heapless_bytes::Bytes;
use iso7816::Status;
use littlefs2_core::{path, Path, PathBuf};
use trussed_chunked::utils;
use trussed_core::{
    api::reply::Metadata,
    config::MAX_MESSAGE_LENGTH,
    syscall, try_syscall,
    types::{KeyId, KeySerialization, Location, Mechanism, Message, StorageAttributes},
};

use crate::piv_types::CardHolderUniqueIdentifier;
use crate::reply::Reply;
use crate::{constants::*, piv_types::AsymmetricAlgorithms};
use crate::{
    container::{AsymmetricKeyReference, Container, ReadAccessRule, SecurityCondition},
    piv_types::Algorithms,
};

use crate::{Pin, Puk};

/// User pin key wrapped by the resetting code key
const PUK_USER_KEY_BACKUP: &Path = path!("puk-user-pin-key.bin");
/// User asymmetric key private part, wrapped by the PIN key
const USER_PRIVATE_KEY: &Path = path!("user-private-key.bin");
/// User asymmetric key publick part
const USER_PUBLIC_KEY: &Path = path!("user-public-key.bin");

/// Info parameter for the container storage
const HPKE_SEALKEY_CONTAINER_INFO: &[u8] = b"Container Storage";

/// Info parameter for the container storage
const HPKE_SEALKEY_REFERENCE_INFO: &[u8] = b"Key Storage";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyOrEncryptedWithAlg<A> {
    Plain(Option<KeyWithAlg<A>>),
    Encrypted(Option<A>),
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
    // // 9a "PIV Authentication Key" (YK: PIV Authentication)
    pub authentication_alg: AsymmetricAlgorithms,
    // 9b "PIV Card Application Administration Key" (YK: PIV Management)
    pub administration: KeyWithAlg<AdministrationAlgorithm>,
    pub is_admin_default: bool,
    // 9c "Digital Signature Key" (YK: Digital Signature)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<AsymmetricAlgorithms>,
    // 9d "Key Management Key" (YK: Key Management)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_management_alg: Option<AsymmetricAlgorithms>,
    // 9e "Card Authentication Key" (YK: Card Authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_authentication: Option<KeyWithAlg<AsymmetricAlgorithms>>,
    // 0x82..=0x95 (130-149)
    pub retired_keys: [Option<AsymmetricAlgorithms>; 20],
    // TODO secure_messaging
}

impl Keys {
    pub fn asymetric_for_reference(
        &self,
        key: AsymmetricKeyReference,
    ) -> KeyOrEncryptedWithAlg<AsymmetricAlgorithms> {
        use KeyOrEncryptedWithAlg::{Encrypted, Plain};
        match key {
            AsymmetricKeyReference::PivAuthentication => Encrypted(Some(self.authentication_alg)),
            AsymmetricKeyReference::DigitalSignature => Encrypted(self.signature_alg),
            AsymmetricKeyReference::KeyManagement => Encrypted(self.key_management_alg),
            AsymmetricKeyReference::CardAuthentication => Plain(self.card_authentication),
            AsymmetricKeyReference::Retired01 => Encrypted(self.retired_keys[0]),
            AsymmetricKeyReference::Retired02 => Encrypted(self.retired_keys[1]),
            AsymmetricKeyReference::Retired03 => Encrypted(self.retired_keys[2]),
            AsymmetricKeyReference::Retired04 => Encrypted(self.retired_keys[3]),
            AsymmetricKeyReference::Retired05 => Encrypted(self.retired_keys[4]),
            AsymmetricKeyReference::Retired06 => Encrypted(self.retired_keys[5]),
            AsymmetricKeyReference::Retired07 => Encrypted(self.retired_keys[6]),
            AsymmetricKeyReference::Retired08 => Encrypted(self.retired_keys[7]),
            AsymmetricKeyReference::Retired09 => Encrypted(self.retired_keys[8]),
            AsymmetricKeyReference::Retired10 => Encrypted(self.retired_keys[9]),
            AsymmetricKeyReference::Retired11 => Encrypted(self.retired_keys[10]),
            AsymmetricKeyReference::Retired12 => Encrypted(self.retired_keys[11]),
            AsymmetricKeyReference::Retired13 => Encrypted(self.retired_keys[12]),
            AsymmetricKeyReference::Retired14 => Encrypted(self.retired_keys[13]),
            AsymmetricKeyReference::Retired15 => Encrypted(self.retired_keys[14]),
            AsymmetricKeyReference::Retired16 => Encrypted(self.retired_keys[15]),
            AsymmetricKeyReference::Retired17 => Encrypted(self.retired_keys[16]),
            AsymmetricKeyReference::Retired18 => Encrypted(self.retired_keys[17]),
            AsymmetricKeyReference::Retired19 => Encrypted(self.retired_keys[18]),
            AsymmetricKeyReference::Retired20 => Encrypted(self.retired_keys[19]),
        }
    }

    pub fn set_asymetric_for_reference(
        &mut self,
        key: AsymmetricKeyReference,
        new: KeyWithAlg<AsymmetricAlgorithms>,
        storage: Location,
        client: &mut impl crate::Client,
    ) -> KeyOrEncryptedWithAlg<AsymmetricAlgorithms> {
        let mut user_public_key = None;
        let mut get_user_public_key = || {
            let user_public_key_data =
                syscall!(client.read_file(storage, PathBuf::from(USER_PUBLIC_KEY))).data;
            let key_id = syscall!(client.deserialize_key(
                Mechanism::X255,
                &user_public_key_data,
                KeySerialization::Raw,
                StorageAttributes::new().set_persistence(Location::Volatile)
            ))
            .key;
            assert!(user_public_key.is_none());
            user_public_key = Some(key_id);
            key_id
        };

        let old = match key {
            AsymmetricKeyReference::CardAuthentication => {
                KeyOrEncryptedWithAlg::Plain(self.card_authentication.replace(new))
            }
            _ => {
                let user_public_key = get_user_public_key();
                syscall!(client.hpke_seal_key_to_file(
                    PathBuf::from(key.name()),
                    storage,
                    user_public_key,
                    new.id,
                    Bytes::from_slice(key.name().as_str().as_bytes()).unwrap(),
                    Bytes::from_slice(HPKE_SEALKEY_REFERENCE_INFO).unwrap(),
                ));

                KeyOrEncryptedWithAlg::Encrypted(match key {
                    AsymmetricKeyReference::PivAuthentication => {
                        Some(mem::replace(&mut self.authentication_alg, new.alg))
                    }
                    AsymmetricKeyReference::KeyManagement => {
                        self.key_management_alg.replace(new.alg)
                    }

                    AsymmetricKeyReference::DigitalSignature => self.signature_alg.replace(new.alg),
                    AsymmetricKeyReference::Retired01 => self.retired_keys[0].replace(new.alg),
                    AsymmetricKeyReference::Retired02 => self.retired_keys[1].replace(new.alg),
                    AsymmetricKeyReference::Retired03 => self.retired_keys[2].replace(new.alg),
                    AsymmetricKeyReference::Retired04 => self.retired_keys[3].replace(new.alg),
                    AsymmetricKeyReference::Retired05 => self.retired_keys[4].replace(new.alg),
                    AsymmetricKeyReference::Retired06 => self.retired_keys[5].replace(new.alg),
                    AsymmetricKeyReference::Retired07 => self.retired_keys[6].replace(new.alg),
                    AsymmetricKeyReference::Retired08 => self.retired_keys[7].replace(new.alg),
                    AsymmetricKeyReference::Retired09 => self.retired_keys[8].replace(new.alg),
                    AsymmetricKeyReference::Retired10 => self.retired_keys[9].replace(new.alg),
                    AsymmetricKeyReference::Retired11 => self.retired_keys[10].replace(new.alg),
                    AsymmetricKeyReference::Retired12 => self.retired_keys[11].replace(new.alg),
                    AsymmetricKeyReference::Retired13 => self.retired_keys[12].replace(new.alg),
                    AsymmetricKeyReference::Retired14 => self.retired_keys[13].replace(new.alg),
                    AsymmetricKeyReference::Retired15 => self.retired_keys[14].replace(new.alg),
                    AsymmetricKeyReference::Retired16 => self.retired_keys[15].replace(new.alg),
                    AsymmetricKeyReference::Retired17 => self.retired_keys[16].replace(new.alg),
                    AsymmetricKeyReference::Retired18 => self.retired_keys[17].replace(new.alg),
                    AsymmetricKeyReference::Retired19 => self.retired_keys[18].replace(new.alg),
                    AsymmetricKeyReference::Retired20 => self.retired_keys[19].replace(new.alg),
                    AsymmetricKeyReference::CardAuthentication => unreachable!(),
                })
            }
        };

        if let Some(key_id) = user_public_key {
            syscall!(client.clear(key_id));
        }
        old
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

pub struct UseValidKey {
    pub key: KeyId,
    pub alg: AsymmetricAlgorithms,
    pub need_clear: bool,
}

impl UseValidKey {
    pub fn clear(mut self, client: &mut impl crate::Client) {
        if self.need_clear {
            syscall!(client.clear(self.key));
        }
        self.need_clear = false;
    }
}

impl Drop for UseValidKey {
    fn drop(&mut self) {
        assert!(!self.need_clear, "Memory leak of sensitive data")
    }
}

impl LoadedState<'_> {
    pub fn key_exists(
        &self,
        client: &mut impl crate::Client,
        options: &crate::Options,
        key: AsymmetricKeyReference,
    ) -> bool {
        syscall!(client.entry_metadata(options.storage, key.name().into()))
            .metadata
            .is_some()
    }

    pub fn use_valid_key(
        &mut self,
        key: AsymmetricKeyReference,
        client: &mut impl crate::Client,
        options: &crate::Options,
        just_verified: bool,
    ) -> Result<Option<UseValidKey>, Status> {
        let security_condition = key.use_security_condition();
        match security_condition {
            SecurityCondition::PinAlways if just_verified => {}
            SecurityCondition::Pin if self.volatile.app_security_status.pin_verified.is_some() => {}
            SecurityCondition::Always => {}
            _ => return Err(Status::SecurityStatusNotSatisfied),
        };

        let key_with_alg = self.persistent.keys.asymetric_for_reference(key);
        let alg = match key_with_alg {
            KeyOrEncryptedWithAlg::Plain(None) => return Ok(None),
            KeyOrEncryptedWithAlg::Plain(Some(KeyWithAlg { id, alg })) => {
                return Ok(Some(UseValidKey {
                    key: id,
                    alg,
                    need_clear: false,
                }))
            }
            KeyOrEncryptedWithAlg::Encrypted(None) => return Ok(None),
            KeyOrEncryptedWithAlg::Encrypted(Some(alg)) => alg,
        };

        let pin_key = self.volatile.app_security_status.pin_verified.unwrap();

        let unsealed_key = try_syscall!(client.hpke_open_key_from_file(
            pin_key,
            key.name().into(),
            options.storage,
            Location::Volatile,
            Bytes::from_slice(key.name().as_str().as_bytes()).unwrap(),
            Bytes::from_slice(HPKE_SEALKEY_REFERENCE_INFO).unwrap(),
        ))
        .map_err(|_err| {
            error!("Failed to unseal key: {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?
        .key;

        Ok(Some(UseValidKey {
            key: unsealed_key,
            alg,
            need_clear: true,
        }))
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadValid {
    /// Container can be read in plain text
    Plain,
    /// Container is stored encrypted but is also not found
    EncryptedNotFound,
    /// Container can be read with read_encrypted_chunk using the key
    ///
    /// The key is stored in volatile storage and must be deleted after use
    Encrypted(KeyId),
}

impl Volatile {
    pub fn verify_pin<T: crate::Client>(
        &mut self,
        value: &Pin,
        client: &mut T,
        options: &crate::Options,
    ) -> Option<KeyId> {
        self.clear_pin_verified(client);
        let pin = Bytes::from_slice(&value.0).expect("Convertion of static array");
        let pin_key = try_syscall!(client.get_pin_key(PinType::UserPin, pin))
            .ok()?
            .result?;
        let key = syscall!(client.unwrap_key_from_file(
            Mechanism::Chacha8Poly1305,
            pin_key,
            PathBuf::from(USER_PRIVATE_KEY),
            options.storage,
            Location::Volatile,
            USER_PRIVATE_KEY.as_str().as_bytes()
        ))
        .key
        .expect("Failed to unwrap private key");
        syscall!(client.delete(pin_key));
        self.app_security_status.pin_verified = Some(key);
        self.app_security_status.pin_just_verified = true;
        Some(key)
    }

    pub fn pin_verified(&self) -> bool {
        self.app_security_status.pin_verified.is_some()
    }

    pub fn clear_pin_verified(&mut self, client: &mut impl crate::Client) {
        if let Some(key) = self.app_security_status.pin_verified {
            syscall!(client.clear(key));
        }
        self.app_security_status.pin_verified = None;
        self.app_security_status.pin_just_verified = false;
    }

    pub fn security_valid(&self, condition: SecurityCondition, just_verified: bool) -> bool {
        use SecurityCondition::*;
        match condition {
            Pin => self.app_security_status.pin_verified.is_some(),
            PinAlways => just_verified,
            Always => true,
        }
    }

    pub fn read_valid_key(
        &mut self,
        container: Container,
        client: &mut impl crate::Client,
        options: &crate::Options,
    ) -> Result<ReadValid, Status> {
        let pin_key = match (
            container.contact_access_rule(),
            self.app_security_status.pin_verified,
        ) {
            (ReadAccessRule::Pin | ReadAccessRule::PinOrOcc, None) => {
                warn!("Unauthorized attempt to access: {:?}", container);
                return Err(Status::SecurityStatusNotSatisfied);
            }
            (ReadAccessRule::Always, _) => {
                return Ok(ReadValid::Plain);
            }
            (ReadAccessRule::Pin | ReadAccessRule::PinOrOcc, Some(key)) => key,
        };
        // Here we have the pin key, and we are in the complex case

        let data_encryption_sealed_key_path = ContainerStorage(container).path_key();

        let Ok(unsealed_key) = try_syscall!(client.hpke_open_key_from_file(
            pin_key,
            data_encryption_sealed_key_path,
            options.storage,
            Location::Volatile,
            Bytes::from_slice(ContainerStorage(container).path_key_str().as_bytes()).unwrap(),
            Bytes::from_slice(HPKE_SEALKEY_CONTAINER_INFO).unwrap(),
        )) else {
            return Ok(ReadValid::EncryptedNotFound);
        };

        Ok(ReadValid::Encrypted(unsealed_key.key))
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppSecurityStatus {
    /// Contains the decrypted asymetric key
    pin_verified: Option<KeyId>,
    pub pin_just_verified: bool,
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
    const FILENAME: &'static Path = path!("persistent-state.cbor");
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
        storage: Location,
        client: &mut impl crate::Client,
    ) -> KeyOrEncryptedWithAlg<AsymmetricAlgorithms> {
        self.keys
            .set_asymetric_for_reference(key, KeyWithAlg { id, alg }, storage, client)
    }

    pub fn generate_asymmetric_key(
        &mut self,
        key: AsymmetricKeyReference,
        alg: AsymmetricAlgorithms,
        client: &mut impl crate::Client,
        storage: Location,
    ) -> KeyId {
        let id = syscall!(client.generate_key(
            alg.key_mechanism(),
            StorageAttributes::default().set_persistence(key.storage(self.storage))
        ))
        .key;
        let old = self.set_asymmetric_key(key, id, alg, storage, client);
        self.save(client);
        use KeyOrEncryptedWithAlg::{Encrypted, Plain};
        match old {
            Plain(None) => {}
            Plain(Some(KeyWithAlg { id, alg: _ })) => {
                syscall!(client.delete(id));
            }
            Encrypted(_) => {
                // Old file was already overwritten
            }
        }
        id
    }

    pub fn replace_asymmetric_key(
        &mut self,
        key: AsymmetricKeyReference,
        alg: AsymmetricAlgorithms,
        id: KeyId,
        client: &mut impl crate::Client,
        storage: Location,
    ) {
        let old = self.set_asymmetric_key(key, id, alg, storage, client);
        self.save(client);
        use KeyOrEncryptedWithAlg::{Encrypted, Plain};
        match old {
            Plain(Some(old)) => {
                syscall!(client.delete(old.id));
            }
            Plain(None) => {}
            // The old file was simply overwritten
            Encrypted(_) => {}
        }
    }

    fn ensure_pins_not_init<T: crate::Client>(client: &mut T) -> Result<(), Status> {
        // If PINs are already there when initializing, it likely means that the state was corrupted rather than absent.
        // In that case, we wait for the user to explicitely factory-reset the device to avoid risking loosing data.
        // See https://github.com/Nitrokey/opcard-rs/issues/165
        if syscall!(client.has_pin(PinType::UserPin)).has_pin
            || syscall!(client.has_pin(PinType::Puk)).has_pin
        {
            debug!("Init pins after pins are already there");
            return Err(Status::UnspecifiedNonpersistentExecutionError);
        }
        Ok(())
    }

    fn init_pins<T: crate::Client>(client: &mut T, options: &crate::Options) -> Result<(), Status> {
        let default_pin =
            Bytes::from_slice(&Self::DEFAULT_PIN.0).expect("Convertion of static array");
        try_syscall!(client.set_pin(
            PinType::UserPin,
            default_pin.clone(),
            Some(Self::PIN_RETRIES_DEFAULT),
            true
        ))
        .map_err(|_err| {
            error!("Failed to set pin");
            Status::UnspecifiedPersistentExecutionError
        })?;
        let default_puk =
            Bytes::from_slice(&Self::DEFAULT_PUK.0).expect("Convertion of static array");
        try_syscall!(client.set_pin(
            PinType::Puk,
            default_puk.clone(),
            Some(Self::PIN_RETRIES_DEFAULT),
            true
        ))
        .map_err(|_err| {
            error!("Failed to set puk");
            Status::UnspecifiedPersistentExecutionError
        })?;

        let user_key = syscall!(client.get_pin_key(PinType::UserPin, default_pin))
            .result
            .expect("PIN was just set");
        let puk_key = syscall!(client.get_pin_key(PinType::Puk, default_puk))
            .result
            .expect("PUK was just set");

        let path = PathBuf::from(PUK_USER_KEY_BACKUP);
        syscall!(client.wrap_key_to_file(
            Mechanism::Chacha8Poly1305,
            puk_key,
            user_key,
            path,
            Location::External,
            PUK_USER_KEY_BACKUP.as_str().as_bytes()
        ));

        syscall!(client.delete(puk_key));

        let user_asymetric_key = syscall!(client.generate_key(
            Mechanism::X255,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .key;

        syscall!(client.wrap_key_to_file(
            Mechanism::Chacha8Poly1305,
            user_key,
            user_asymetric_key,
            PathBuf::from(USER_PRIVATE_KEY),
            options.storage,
            USER_PRIVATE_KEY.as_str().as_bytes()
        ));

        let user_asymetric_public_key = syscall!(client.derive_key(
            Mechanism::X255,
            user_asymetric_key,
            None,
            StorageAttributes::new().set_persistence(options.storage)
        ))
        .key;
        let key = syscall!(client.serialize_key(
            Mechanism::X255,
            user_asymetric_public_key,
            KeySerialization::Raw
        ))
        .serialized_key;
        syscall!(client.write_file(
            options.storage,
            PathBuf::from(USER_PUBLIC_KEY),
            Bytes::from_slice(&key).unwrap(),
            None
        ));

        syscall!(client.delete(user_key));
        syscall!(client.clear(user_asymetric_key));

        Ok(())
    }

    pub fn initialize<T: crate::Client>(
        client: &mut T,
        options: &crate::Options,
    ) -> Result<Self, Status> {
        Self::ensure_pins_not_init(client)?;

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

        let authentication_alg = AsymmetricAlgorithms::P256;
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
            authentication_alg,
            administration,
            is_admin_default: true,
            signature_alg: None,
            key_management_alg: None,
            card_authentication: None,
            retired_keys: Default::default(),
        };

        let mut state = Self {
            keys,
            timestamp: 0,
            storage: options.storage,
        };
        state.generate_asymmetric_key(
            AsymmetricKeyReference::CardAuthentication,
            authentication_alg,
            client,
            options.storage,
        );

        Self::init_pins(client, options)?;
        Ok(state)
    }

    pub fn load_or_initialize<T: crate::Client>(
        client: &mut T,
        options: &crate::Options,
    ) -> Result<Self, Status> {
        // todo: can't seem to combine load + initialize without code repetition
        let data = load_if_exists(client, options.storage, Self::FILENAME)?;
        let Some(bytes) = data else {
            return Self::initialize(client, options);
        };

        let mut parsed: Self = cbor_smol::cbor_deserialize(&bytes).map_err(|_err| {
            error!("{_err:?}");
            Status::UnspecifiedPersistentExecutionError
        })?;
        parsed.storage = options.storage;
        Ok(parsed)
    }

    pub fn save(&mut self, client: &mut impl crate::Client) {
        let mut data = Message::new();
        cbor_smol::cbor_serialize_to(&self, &mut data).unwrap();

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
    path: &Path,
) -> Result<Option<Bytes<MAX_MESSAGE_LENGTH>>, Status> {
    match try_syscall!(client.read_file(location, path.into())) {
        Ok(r) => Ok(Some(r.data)),
        Err(_) => match try_syscall!(client.entry_metadata(location, path.into())) {
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
    encryption: Option<KeyId>,
) -> Result<bool, Status> {
    let offset = buffer.len();
    match encryption {
        Some(key) => {
            try_syscall!(client.start_encrypted_chunked_read(location, path.clone(), key,))
                .map_err(|_err| {
                    error!("Encrypted {path} couldn't be read: {_err:?}");
                    Status::UnspecifiedPersistentExecutionError
                })?;
        }
        None => match try_syscall!(client.start_chunked_read(location, path.clone())) {
            Ok(r) => {
                buffer.expand(&r.data)?;
                if !r.data.is_full() {
                    buffer.prepend_len(offset)?;
                    return Ok(true);
                }
            }
            Err(_err) => match try_syscall!(client.entry_metadata(location, path.clone())) {
                Ok(Metadata { metadata: None }) => return Ok(false),
                Ok(Metadata {
                    metadata: Some(_metadata),
                }) => {
                    error!("File {path} exists but couldn't be read: {_metadata:?}");
                    return Err(Status::UnspecifiedPersistentExecutionError);
                }
                Err(_err) => {
                    error!("File {path} couldn't be read: {_err:?}");
                    return Err(Status::UnspecifiedPersistentExecutionError);
                }
            },
        },
    }

    loop {
        match try_syscall!(client.read_file_chunk()) {
            Ok(r) => {
                buffer.expand(&r.data)?;
                if !r.data.is_full() {
                    buffer.prepend_len(offset)?;
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
    fn path_key_str(self) -> &'static str {
        match self.0 {
            Container::CardCapabilityContainer => "CardCapabilityContainer.key",
            Container::CardHolderUniqueIdentifier => "CardHolderUniqueIdentifier.key",
            Container::X509CertificateFor9A => "X509CertificateFor9A.key",
            Container::CardholderFingerprints => "CardholderFingerprints.key",
            Container::SecurityObject => "SecurityObject.key",
            Container::CardholderFacialImage => "CardholderFacialImage.key",
            Container::X509CertificateFor9E => "X509CertificateFor9E.key",
            Container::X509CertificateFor9C => "X509CertificateFor9C.key",
            Container::X509CertificateFor9D => "X509CertificateFor9D.key",
            Container::PrintedInformation => "PrintedInformation.key",
            Container::DiscoveryObject => "DiscoveryObject.key",
            Container::KeyHistoryObject => "KeyHistoryObject.key",
            Container::RetiredCert01 => "RetiredCert01.key",
            Container::RetiredCert02 => "RetiredCert02.key",
            Container::RetiredCert03 => "RetiredCert03.key",
            Container::RetiredCert04 => "RetiredCert04.key",
            Container::RetiredCert05 => "RetiredCert05.key",
            Container::RetiredCert06 => "RetiredCert06.key",
            Container::RetiredCert07 => "RetiredCert07.key",
            Container::RetiredCert08 => "RetiredCert08.key",
            Container::RetiredCert09 => "RetiredCert09.key",
            Container::RetiredCert10 => "RetiredCert10.key",
            Container::RetiredCert11 => "RetiredCert11.key",
            Container::RetiredCert12 => "RetiredCert12.key",
            Container::RetiredCert13 => "RetiredCert13.key",
            Container::RetiredCert14 => "RetiredCert14.key",
            Container::RetiredCert15 => "RetiredCert15.key",
            Container::RetiredCert16 => "RetiredCert16.key",
            Container::RetiredCert17 => "RetiredCert17.key",
            Container::RetiredCert18 => "RetiredCert18.key",
            Container::RetiredCert19 => "RetiredCert19.key",
            Container::RetiredCert20 => "RetiredCert20.key",
            Container::CardholderIrisImages => "CardholderIrisImages.key",
            Container::BiometricInformationTemplatesGroupTemplate => {
                "BiometricInformationTemplatesGroupTemplate.key"
            }
            Container::SecureMessagingCertificateSigner => "SecureMessagingCertificateSigner.key",
            Container::PairingCodeReferenceDataContainer => "PairingCodeReferenceDataContainer.key",
        }
    }

    fn path_key(self) -> PathBuf {
        PathBuf::try_from(self.path_key_str()).unwrap()
    }

    fn path(self) -> PathBuf {
        PathBuf::try_from(self.path_key_str().strip_suffix(".key").unwrap()).unwrap()
    }

    fn default(self) -> Option<Vec<u8, MAX_MESSAGE_LENGTH>> {
        match self.0 {
            Container::CardHolderUniqueIdentifier => panic!("CHUID should alway be set"),
            Container::CardCapabilityContainer => Some(Vec::from_slice(&CARD_CAP).unwrap()),
            Container::DiscoveryObject => Some(Vec::from_slice(&DISCOVERY_OBJECT).unwrap()),
            Container::PrintedInformation => Some(Vec::from_slice(&PRINTED_INFORMATION).unwrap()),
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
        read_valid: ReadValid,
    ) -> Result<bool, Status> {
        let encryption = match read_valid {
            ReadValid::Plain => None,
            ReadValid::Encrypted(key) => Some(key),
            ReadValid::EncryptedNotFound => {
                if let Some(data) = self.default() {
                    reply.append_len(data.len())?;
                    reply.expand(&data)?;
                    return Ok(true);
                } else {
                    return Ok(false);
                }
            }
        };

        if load_if_exists_streaming(client, storage, &self.path(), reply.lend(), encryption)? {
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
        match self.0.contact_access_rule() {
            ReadAccessRule::Always => {
                utils::write_all(client, storage, self.path(), bytes, None, None).map_err(|_err| {
                    error!("Failed to write data object: {:?}", _err);
                    Status::UnspecifiedNonpersistentExecutionError
                })
            }
            ReadAccessRule::PinOrOcc | ReadAccessRule::Pin => {
                self.save_encrypted(client, bytes, storage)
            }
        }
    }

    fn save_encrypted(
        self,
        client: &mut impl crate::Client,
        bytes: &[u8],
        storage: Location,
    ) -> Result<(), Status> {
        let user_public_key_data =
            syscall!(client.read_file(storage, PathBuf::from(USER_PUBLIC_KEY))).data;
        let user_public_key = syscall!(client.deserialize_key(
            Mechanism::X255,
            &user_public_key_data,
            KeySerialization::Raw,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .key;
        let key_to_seal = syscall!(client.generate_secret_key(32, Location::Volatile)).key;
        syscall!(client.hpke_seal_key_to_file(
            self.path_key(),
            storage,
            user_public_key,
            key_to_seal,
            Bytes::from_slice(self.path_key_str().as_bytes()).unwrap(),
            Bytes::from_slice(HPKE_SEALKEY_CONTAINER_INFO).unwrap(),
        ));
        syscall!(client.delete(user_public_key));

        utils::write_all(
            client,
            storage,
            self.path(),
            bytes,
            None,
            Some(utils::EncryptionData {
                key: key_to_seal,
                // Nonce can be none since the key is only used to encrypt once
                nonce: None,
            }),
        )
        .map_err(|_err| {
            error!("Failed to write data object: {:?}", _err);
            Status::UnspecifiedNonpersistentExecutionError
        })?;

        syscall!(client.clear(key_to_seal));
        Ok(())
    }
}
