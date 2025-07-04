#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[cfg(feature = "delog")]
delog::generate_macros!();

pub mod commands;
use commands::containers::AsymmetricKeyReference;
pub use commands::{Command, YubicoPivExtension};
use commands::{GeneralAuthenticate, PutData, ResetRetryCounter};
pub mod constants;
pub mod container;
use container::{AuthenticateKeyReference, Container, GenerateKeyReference, KeyReference};
#[cfg(feature = "apdu-dispatch")]
mod dispatch;
pub mod piv_types;
mod reply;
pub mod state;
mod tlv;

pub use piv_types::{AsymmetricAlgorithms, Pin, Puk};
use trussed_chunked::ChunkedClient;
use trussed_hpke::HpkeClient;
use trussed_wrap_key_to_file::WrapKeyToFileClient;

#[cfg(feature = "virt")]
pub mod virt;
#[cfg(feature = "vpicc")]
pub mod vpicc;

use core::convert::TryInto;

use flexiber::EncodableHeapless;
use heapless_bytes::Bytes;
use iso7816::{Data, Status};
use trussed_auth::AuthClient;
use trussed_core::mechanisms::Tdes;
use trussed_core::types::{KeySerialization, Location, Mechanism, PathBuf, StorageAttributes};
use trussed_core::{syscall, try_syscall, CryptoClient, FilesystemClient};

use constants::*;

pub type Result<O = ()> = iso7816::Result<O>;
use reply::Reply;
use state::{AdministrationAlgorithm, CommandCache, KeyWithAlg, LoadedState, State, TouchPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    storage: Location,
    label: &'static [u8],
    url: &'static [u8],
    uuid: Option<[u8; 16]>,
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

impl Options {
    pub const fn new() -> Self {
        Self {
            storage: Location::External,
            label: NITROKEY_APPLICATION_LABEL,
            url: NITROKEY_APPLICATION_URL,
            uuid: None,
        }
    }

    pub const fn storage(self, storage: Location) -> Self {
        Self { storage, ..self }
    }
    pub const fn url(self, url: &'static [u8]) -> Self {
        Self { url, ..self }
    }
    pub const fn label(self, label: &'static [u8]) -> Self {
        Self { label, ..self }
    }
    pub const fn uuid(self, uuid: Option<[u8; 16]>) -> Self {
        Self { uuid, ..self }
    }
}

/// PIV authenticator Trussed app.
///
/// The `C` parameter is necessary, as PIV includes command sequences,
/// where we need to store the previous command, so we need to know how
/// much space to allocate.
pub struct Authenticator<T> {
    options: Options,
    state: State,
    trussed: T,
}

struct LoadedAuthenticator<'a, T> {
    options: &'a mut Options,
    state: LoadedState<'a>,
    trussed: &'a mut T,
}

impl<T> iso7816::App for Authenticator<T> {
    fn aid(&self) -> iso7816::Aid {
        crate::constants::PIV_AID
    }
}

impl<T> Authenticator<T>
where
    T: Client,
{
    pub fn new(trussed: T, options: Options) -> Self {
        // seems like RefCell is not the right thing, we want something like `Rc` instead,
        // which can be cloned and injected into other parts of the App that use Trussed.
        // let trussed = RefCell::new(trussed);
        Self {
            // state: state::State::new(trussed.clone()),
            state: Default::default(),
            options,
            trussed,
        }
    }

    fn load(&mut self) -> core::result::Result<LoadedAuthenticator<'_, T>, Status> {
        Ok(LoadedAuthenticator {
            state: self.state.load(&mut self.trussed, &self.options)?,
            trussed: &mut self.trussed,
            options: &mut self.options,
        })
    }

    // TODO: we'd like to listen on multiple AIDs.
    // The way apdu-dispatch currently works, this would deselect, resetting security indicators.
    pub fn deselect(&mut self) {}

    pub fn select<const R: usize>(&mut self, mut reply: Reply<'_, R>) -> Result {
        use piv_types::Algorithms::*;
        info!("selecting PIV maybe");

        let application_property_template = piv_types::ApplicationPropertyTemplate::default()
            .with_application_label(self.options.label)
            .with_application_url(self.options.url)
            .with_supported_cryptographic_algorithms(&[
                Tdes, Aes256, P256, Rsa2048, Rsa3072, Rsa4096, P384,
            ]);

        application_property_template
            .encode_to_heapless_vec(*reply)
            .unwrap();
        info!("returning {} bytes", reply.len());
        Ok(())
    }

    pub fn respond<const R: usize>(
        &mut self,
        command: iso7816::command::CommandView<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        let just_verified = self.state.volatile.app_security_status.pin_just_verified;
        self.state.volatile.app_security_status.pin_just_verified = false;

        // info!("PIV responding to {:02x?}", command);
        let parsed_command: Command = command.try_into()?;
        info!("parsed: {:02x?}", &parsed_command);
        let reply = Reply(reply);

        match parsed_command {
            Command::Verify(verify) => self.load()?.verify(verify),
            Command::ChangeReference(change_reference) => {
                self.load()?.change_reference(change_reference)
            }
            Command::GetData(container) => self.load()?.get_data(container, reply),
            Command::PutData(put_data) => self.load()?.put_data(put_data),
            Command::Select(_aid) => self.select(reply),
            Command::GeneralAuthenticate(authenticate) => self.load()?.general_authenticate(
                authenticate,
                command.data(),
                just_verified,
                reply,
            ),
            Command::GenerateAsymmetric(reference) => {
                self.load()?
                    .generate_asymmetric_keypair(reference, command.data(), reply)
            }
            Command::YkExtension(yk_command) => {
                self.yubico_piv_extension(command.data(), yk_command, reply)
            }
            Command::ResetRetryCounter(reset) => self.load()?.reset_retry_counter(reset),
        }
    }

    pub fn yubico_piv_extension<const R: usize>(
        &mut self,
        data: &[u8],
        instruction: YubicoPivExtension,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("yubico extension: {:?}", &instruction);
        match instruction {
            YubicoPivExtension::GetSerial => {
                // make up a 4-byte serial
                reply.extend_from_slice(&[0x00, 0x52, 0xf7, 0x43]).ok();
            }

            YubicoPivExtension::GetVersion => {
                // make up a version, be >= 5.0.0
                reply.extend_from_slice(&[0x06, 0x06, 0x06]).ok();
            }

            YubicoPivExtension::Attest(_slot) => return Err(Status::FunctionNotSupported),

            YubicoPivExtension::Reset => {
                let mut this;
                let trussed = match self.load() {
                    Err(_err) => &mut self.trussed,
                    Ok(loaded) => {
                        this = loaded;
                        if this.state.persistent.remaining_pin_retries(this.trussed) != 0 {
                            return Err(Status::ConditionsOfUseNotSatisfied);
                        }
                        &mut this.trussed
                    }
                };

                // TODO: find out what all needs resetting :)
                for location in [Location::Volatile, Location::External, Location::Internal] {
                    try_syscall!(trussed.delete_all(location)).ok();
                    try_syscall!(trussed.remove_dir_all(location, PathBuf::new())).ok();
                }
                try_syscall!(trussed.delete_all_pins()).ok();
                self.state.persistent = None;
            }

            YubicoPivExtension::SetManagementKey(touch_policy) => {
                self.load()?
                    .yubico_set_administration_key(data, touch_policy, reply)?;
            }

            YubicoPivExtension::GetMetadata(KeyReference::CardAuthentication) => {
                let this = self.load()?;
                if this.state.persistent.keys.card_authentication.is_some() {
                    reply.expand(&[0x02, 0x02, 0x01, 0x00])?;
                }
            }
            YubicoPivExtension::GetMetadata(_reference) => { /* TODO */ }
            YubicoPivExtension::ImportAsymmetricKey(algo, key) => {
                self.load()?.import_asymmetric_key(algo, key, data, reply)?;
            }
            _ => return Err(Status::FunctionNotSupported),
        }
        Ok(())
    }
}

impl<T: Client> LoadedAuthenticator<'_, T> {
    pub fn yubico_set_administration_key<const R: usize>(
        &mut self,
        data: &[u8],
        _touch_policy: TouchPolicy,
        _reply: Reply<'_, R>,
    ) -> Result {
        // cmd := apdu{
        //     instruction: insSetMGMKey,
        //     param1:      0xff,
        //     param2:      0xff,
        //     data: append([]byte{
        //         alg3DES, keyCardManagement, 24,
        //     }, key[:]...),
        // }

        // TODO _touch_policy

        if !self
            .state
            .volatile
            .app_security_status
            .administrator_verified
        {
            return Err(Status::SecurityStatusNotSatisfied);
        }

        // example:  03 9B 18
        //      B0 20 7A 20 DC 39 0B 1B A5 56 CC EB 8D CE 7A 8A C8 23 E6 F5 0D 89 17 AA
        if data.len() < 4 {
            warn!("Set management key with incorrect data");
            return Err(Status::IncorrectDataParameter);
        }

        let key_data = &data[3..];

        let Ok(alg) = AdministrationAlgorithm::try_from(data[0]) else {
            warn!("Set management key with incorrect alg: {:x}", data[0]);
            return Err(Status::IncorrectDataParameter);
        };

        if KeyReference::PivCardApplicationAdministration != data[1] {
            warn!(
                "Set management key with incorrect reference: {:x}, expected: {:x}",
                data[1],
                KeyReference::PivCardApplicationAdministration as u8
            );
            return Err(Status::IncorrectDataParameter);
        }

        if data[2] as usize != key_data.len() || alg.key_len() != key_data.len() {
            warn!("Set management key with incorrect data length: claimed: {}, required by algorithm: {}, real: {}", data[2], alg.key_len(), key_data.len());
            return Err(Status::IncorrectDataParameter);
        }

        self.state
            .persistent
            .set_administration_key(key_data, alg, self.trussed);
        Ok(())
    }

    // maybe reserve this for the case VerifyLogin::PivPin?
    pub fn login(&mut self, login: commands::VerifyLogin) -> Result {
        if let commands::VerifyLogin::PivPin(pin) = login {
            let pin_verified = self.state.volatile.verify_pin(&pin, self.trussed);
            if pin_verified.is_verified() {
                Ok(())
            } else {
                // should we logout here?
                self.state.volatile.app_security_status.pin_just_verified = false;
                let remaining = self.state.persistent.remaining_pin_retries(self.trussed);
                if remaining == 0 {
                    Err(Status::OperationBlocked)
                } else {
                    Err(Status::RemainingRetries(remaining))
                }
            }
        } else {
            Err(Status::FunctionNotSupported)
        }
    }

    pub fn verify(&mut self, command: commands::Verify) -> Result {
        use commands::Verify;
        match command {
            Verify::Login(login) => self.login(login),

            Verify::Logout(_) => {
                self.state.volatile.clear_pin_verified(self.trussed);
                Ok(())
            }

            Verify::Status(key_reference) => {
                if key_reference != commands::VerifyKeyReference::ApplicationPin {
                    return Err(Status::FunctionNotSupported);
                }
                if self.state.volatile.pin_verified() {
                    Ok(())
                } else {
                    let retries = self.state.persistent.remaining_pin_retries(self.trussed);
                    Err(Status::RemainingRetries(retries))
                }
            }
        }
    }

    pub fn change_reference(&mut self, command: commands::ChangeReference) -> Result {
        use commands::ChangeReference;
        match command {
            ChangeReference::ChangePin { old_pin, new_pin } => self.change_pin(old_pin, new_pin),
            ChangeReference::ChangePuk { old_puk, new_puk } => self.change_puk(old_puk, new_puk),
        }
    }

    pub fn change_pin(&mut self, old_pin: commands::Pin, new_pin: commands::Pin) -> Result {
        if !self
            .state
            .persistent
            .change_pin(&old_pin, &new_pin, self.trussed)
        {
            return Err(Status::VerificationFailed);
        }
        assert!(self
            .state
            .volatile
            .verify_pin(&new_pin, self.trussed)
            .is_verified());
        Ok(())
    }

    pub fn change_puk(&mut self, old_puk: commands::Puk, new_puk: commands::Puk) -> Result {
        if !self
            .state
            .persistent
            .change_puk(&old_puk, &new_puk, self.trussed)
        {
            return Err(Status::VerificationFailed);
        }
        Ok(())
    }

    // SP 800-73-4, Part 2, Section 3.2.4
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=92
    //
    // General use:
    // - PIV authn keys (9A, 9B, 9E):
    //   - card/app to client (INTERNAL)
    //   - entity to card (EXTERNAL)
    //   - mutual card/external (MUTUAL)
    // - Signature key (9C): => Appendix A.4
    //   - signing data hashed off card
    // - Management key (9D, retired 82-95): => Appendix A.5
    //   - key establishment schems in SP 800-78 (ECDH)
    // - PIV secure messaging key (04, alg 27, 2E)
    //
    // Data field tags:
    // - 80 witness
    // - 81 challenge
    // - 82 response
    // - 83 exponentiation
    //
    // Request for requests:
    // - '80 00' returns '80 TL <encrypted random>'
    // - '81 00' returns '81 TL <random>'
    //
    // Errors:
    // - 9000, 61XX for success
    // - 6982 security status
    // - 6A80, 6A86 for data, P1/P2 issue
    pub fn general_authenticate<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        data: &[u8],
        just_verified: bool,
        mut reply: Reply<'_, R>,
    ) -> Result {
        // For "SSH", we need implement A.4.2 in SP-800-73-4 Part 2, ECDSA signatures
        //
        // ins = 87 = general authenticate
        // p1 = 11 = alg P256
        // p2 = 9a = keyref "PIV authentication"
        // 00 87 11 9A 26
        //     # 7c = specified template
        //     7C 24
        //         # 82 = response, 00 = "request for request"
        //         82 00
        //         # 81 = challenge
        //         81 20
        //             # 32B nonce
        //             95 AE 21 F9 5E 00 01 E6 23 27 F4 FD A5 05 F1 F5 B7 95 0F 11 75 BC 4D A2 06 B1 00 6B DA 90 C3 3A
        //
        // expected response: "7C L1 82 L2 SEQ(INT r, INT s)"

        // refine as we gain more capability

        if !self
            .state
            .volatile
            .security_valid(auth.key_reference.use_security_condition(), just_verified)
        {
            warn!(
                "Security condition not satisfied for key {:?}",
                auth.key_reference
            );
            return Err(Status::SecurityStatusNotSatisfied);
        }

        ///  struct
        struct Auth<'i> {
            witness: Option<&'i [u8]>,
            challenge: Option<&'i [u8]>,
            response: Option<&'i [u8]>,
            exponentiation: Option<&'i [u8]>,
        }

        let input = tlv::get_do(&[0x007C], data).ok_or_else(|| {
            warn!("No 0x7C do in GENERAL AUTHENTICATE");
            Status::IncorrectDataParameter
        })?;

        let parsed = Auth {
            witness: tlv::get_do(&[0x80], input),
            challenge: tlv::get_do(&[0x81], input),
            response: tlv::get_do(&[0x82], input),
            exponentiation: tlv::get_do(&[0x85], input),
        };

        debug!(
            "witness: {}, challenge: {}, response: {}, exponentiation: {}",
            &parsed.witness.is_some(),
            &parsed.challenge.is_some(),
            &parsed.response.is_some(),
            &parsed.exponentiation.is_some(),
        );

        match parsed {
            Auth {
                witness: None,
                challenge: Some(c),
                response: Some([]),
                exponentiation: None,
            } => self.sign(auth, c, just_verified, reply.lend())?,
            Auth {
                witness: None,
                challenge: None,
                response: Some([]),
                exponentiation: Some(p),
            } => self.key_agreement(auth, p, reply.lend(), just_verified)?,
            Auth {
                witness: None,
                challenge: Some([]),
                response: None,
                exponentiation: None,
            } => self.single_auth_1(auth, reply.lend())?,
            Auth {
                witness: None,
                challenge: None,
                response: Some(c),
                exponentiation: None,
            } => self.single_auth_2(auth, c)?,
            Auth {
                witness: Some([]),
                challenge: None,
                response: None,
                exponentiation: None,
            } => self.mutual_auth_1(auth, reply.lend())?,
            Auth {
                witness: Some(r),
                challenge: Some(c),
                response: None,
                exponentiation: None,
            } => self.mutual_auth_2(auth, r, c, reply.lend())?,
            Auth {
                witness: _witness,
                challenge: _challenge,
                response: _response,
                exponentiation: _exponentiation,
            } => {
                warn!(
                    "General authenticate with unexpected data: witness: {:?}, challenge: {:?}, response: {:?}, exponentiation: {:?}",
                    _witness.map(|s|s.len()),
                    _challenge.map(|s|s.len()),
                    _response.map(|s|s.len()),
                    _exponentiation.map(|s|s.len()),
                );
                return Err(Status::IncorrectDataParameter);
            }
        }
        Ok(())
    }

    /// Validate the auth parameters for managememt authentication operations
    fn validate_auth_management(
        &self,
        auth: GeneralAuthenticate,
    ) -> Result<KeyWithAlg<AdministrationAlgorithm>> {
        if auth.key_reference != AuthenticateKeyReference::PivCardApplicationAdministration {
            warn!("Attempt to authenticate with an invalid key");
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        if auth.algorithm != self.state.persistent.keys.administration.alg {
            warn!("Attempt to authenticate with an invalid algo");
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        Ok(self.state.persistent.keys.administration)
    }

    fn single_auth_1<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("Single auth 1");
        let key = self.validate_auth_management(auth)?;
        let plaintext = syscall!(self.trussed.random_bytes(key.alg.challenge_length())).bytes;
        let ciphertext =
            syscall!(self
                .trussed
                .encrypt(key.alg.mechanism(), key.id, &plaintext, &[], None))
            .ciphertext;
        self.state.volatile.command_cache = Some(CommandCache::SingleAuthChallengeReference(
            Bytes::from_slice(&ciphertext).unwrap(),
        ));

        reply.expand(&[0x7C])?;
        let offset = reply.len();
        {
            reply.expand(&[0x81])?;
            reply.append_len(plaintext.len())?;
            reply.expand(&plaintext)?;
        }
        reply.prepend_len(offset)?;
        Ok(())
    }

    fn single_auth_2(&mut self, auth: GeneralAuthenticate, response: &[u8]) -> Result {
        info!("Single auth 2");
        use subtle::ConstantTimeEq;

        let key = self.validate_auth_management(auth)?;
        if response.len() != key.alg.challenge_length() {
            warn!("Incorrect challenge length");
            return Err(Status::IncorrectDataParameter);
        }

        let Some(challenge_reference) = self.state.volatile.take_single_challenge_reference()
        else {
            warn!("Missing cached challenge for auth");
            return Err(Status::ConditionsOfUseNotSatisfied);
        };

        let is_eq: bool = response.ct_eq(&challenge_reference).into();
        if !is_eq {
            warn!("Failed admin authentication. Challenge did not match");
            return Err(Status::IncorrectDataParameter);
        }

        self.state
            .volatile
            .app_security_status
            .administrator_verified = true;
        Ok(())
    }

    fn mutual_auth_1<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("Mutual auth 1");
        let key = self.validate_auth_management(auth)?;
        let plaintext = syscall!(self.trussed.random_bytes(key.alg.challenge_length())).bytes;

        let ciphertext =
            syscall!(self
                .trussed
                .encrypt(key.alg.mechanism(), key.id, &plaintext, &[], None))
            .ciphertext;

        self.state.volatile.command_cache = Some(CommandCache::MutualAuthWitnessReference(
            Bytes::from_slice(&plaintext).unwrap(),
        ));

        reply.expand(&[0x7C])?;
        let offset = reply.len();
        {
            reply.expand(&[0x80])?;
            reply.append_len(ciphertext.len())?;
            reply.expand(&ciphertext)?;
        }
        reply.prepend_len(offset)?;
        Ok(())
    }

    fn mutual_auth_2<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        response: &[u8],
        challenge: &[u8],
        mut reply: Reply<'_, R>,
    ) -> Result {
        use subtle::ConstantTimeEq;

        info!("Mutual auth 2");
        let key = self.validate_auth_management(auth)?;
        if challenge.len() != key.alg.challenge_length() {
            warn!("Incorrect challenge length");
            return Err(Status::IncorrectDataParameter);
        }
        if response.len() != key.alg.challenge_length() {
            warn!("Incorrect response length");
            return Err(Status::IncorrectDataParameter);
        }

        let Some(witness_reference) = self.state.volatile.take_mutual_witness_reference() else {
            warn!("Missing cached challenge for auth");
            return Err(Status::ConditionsOfUseNotSatisfied);
        };

        let is_eq: bool = response.ct_eq(&witness_reference).into();
        if !is_eq {
            warn!("Failed admin authentication. Challenge did not match");
            return Err(Status::IncorrectDataParameter);
        }

        let challenge_response =
            syscall!(self
                .trussed
                .encrypt(key.alg.mechanism(), key.id, challenge, &[], None))
            .ciphertext;

        reply.expand(&[0x7C])?;
        let offset = reply.len();
        {
            reply.expand(&[0x82])?;
            reply.append_len(challenge_response.len())?;
            reply.expand(&challenge_response)?;
        }
        reply.prepend_len(offset)?;

        self.state
            .volatile
            .app_security_status
            .administrator_verified = true;
        Ok(())
    }

    // Sign a message. For RSA, since the key is exposed as a raw key, so it can also be used for decryption
    fn sign<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        message: &[u8],
        just_verified: bool,
        mut reply: Reply<'_, R>,
    ) -> Result {
        debug!("Request for sign, data length: {}, data:", message.len());
        // error!("{}", delog::hexstr!(message));

        let Ok(key_ref) = auth.key_reference.try_into() else {
            warn!("Attempt to sign with an incorrect key");
            return Err(Status::IncorrectP1OrP2Parameter);
        };

        self.state.with_valid_key(
            key_ref,
            self.trussed,
            self.options,
            just_verified,
            |key, trussed| {
                let Some(key) = key? else {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                };
                if key.alg.sign_len() != message.len() {
                    return Err(Status::IncorrectDataParameter);
                }
                let response = syscall!(trussed.sign(
                    key.alg.sign_mechanism(),
                    key.key,
                    message,
                    key.alg.sign_serialization(),
                ))
                .signature;

                reply.expand(&[0x7C])?;
                let offset = reply.len();
                {
                    reply.expand(&[0x82])?;
                    reply.append_len(response.len())?;
                    reply.expand(&response)?;
                }
                debug!("Signed data len: {}, Data:", response.len());
                // error!("{}", delog::hexstr!(&response));

                reply.prepend_len(offset)?;
                Ok(())
            },
        )
    }

    fn key_agreement<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        data: &[u8],
        mut reply: Reply<'_, R>,
        just_verified: bool,
    ) -> Result {
        info!("Request for exponentiation");
        let key_reference = auth.key_reference.try_into().map_err(|_| {
            warn!(
                "Attempt to use non asymetric key for exponentiation: {:?}",
                auth.key_reference
            );
            Status::IncorrectP1OrP2Parameter
        })?;

        self.state.with_valid_key(
            key_reference,
            self.trussed,
            self.options,
            just_verified,
            |key, trussed| {
                let Some(key) = key? else {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                };

                if key.alg != auth.algorithm {
                    warn!("Attempt to exponentiate with incorrect algorithm");
                    return Err(Status::IncorrectP1OrP2Parameter);
                }

                let Some(mechanism) = key.alg.ecdh_mechanism() else {
                    warn!("Attempt to exponentiate with non ECDH algorithm");
                    return Err(Status::ConditionsOfUseNotSatisfied);
                };

                if data.first() != Some(&0x04) {
                    warn!("Bad data forat for ECDH");
                    return Err(Status::IncorrectDataParameter);
                }

                let public_key = match try_syscall!(trussed.deserialize_key(
                    mechanism,
                    &data[1..],
                    KeySerialization::Raw,
                    StorageAttributes::default().set_persistence(Location::Volatile)
                )) {
                    Ok(key) => key.key,
                    Err(_err) => {
                        warn!("Failed to load public key: {:?}", _err);
                        return Err(Status::IncorrectDataParameter);
                    }
                };
                let shared_secret = syscall!(trussed.agree(
                    mechanism,
                    key.key,
                    public_key,
                    StorageAttributes::default()
                        .set_persistence(Location::Volatile)
                        .set_serializable(true)
                ))
                .shared_secret;

                let serialized_secret = syscall!(trussed.serialize_key(
                    Mechanism::SharedSecret,
                    shared_secret,
                    KeySerialization::Raw
                ))
                .serialized_key;
                syscall!(trussed.delete(public_key));
                syscall!(trussed.delete(shared_secret));

                reply.expand(&[0x7C])?;
                let offset = reply.len();
                {
                    reply.expand(&[0x82])?;
                    reply.append_len(serialized_secret.len())?;
                    reply.expand(&serialized_secret)?;
                }
                reply.prepend_len(offset)?;
                Ok(())
            },
        )
    }

    pub fn generate_asymmetric_keypair<const R: usize>(
        &mut self,
        reference: GenerateKeyReference,
        data: &[u8],
        mut reply: Reply<'_, R>,
    ) -> Result {
        if !self
            .state
            .volatile
            .app_security_status
            .administrator_verified
        {
            return Err(Status::SecurityStatusNotSatisfied);
        }

        // example: 00 47 00 9A 0B
        //   AC 09
        //      # P256
        //      80 01 11
        //      # 0xAA = Yubico extension (of course...), PinPolicy, 0x2 =
        //      AA 01 02
        //      # 0xAB = Yubico extension (of course...), TouchPolicy, 0x2 =
        //      AB 01 02
        //
        // var touchPolicyMap = map[TouchPolicy]byte{
        //     TouchPolicyNever:  0x01,
        //     TouchPolicyAlways: 0x02,
        //     TouchPolicyCached: 0x03,
        // }

        // var pinPolicyMap = map[PINPolicy]byte{
        //     PINPolicyNever:  0x01,
        //     PINPolicyOnce:   0x02,
        //     PINPolicyAlways: 0x03,
        // }

        let Some([mechanism]) = tlv::get_do(&[0xAC, 0x80], data) else {
            warn!("Generate assymetric key pair without mechanism");
            return Err(Status::IncorrectDataParameter);
        };

        let parsed_mechanism: AsymmetricAlgorithms = (*mechanism).try_into().map_err(|_| {
            warn!("Unknown mechanism: {mechanism:x}");
            Status::IncorrectDataParameter
        })?;

        let secret_key = self.state.persistent.generate_asymmetric_key(
            reference,
            parsed_mechanism,
            self.trussed,
            self.options.storage,
        );

        let public_key = syscall!(self.trussed.derive_key(
            parsed_mechanism.key_mechanism(),
            secret_key,
            None,
            StorageAttributes::default().set_persistence(Location::Volatile)
        ))
        .key;

        match parsed_mechanism {
            AsymmetricAlgorithms::P256 => {
                let serialized_key = syscall!(self.trussed.serialize_key(
                    parsed_mechanism.key_mechanism(),
                    public_key,
                    KeySerialization::Raw
                ))
                .serialized_key;
                reply.expand(&[0x7F, 0x49])?;
                let offset = reply.len();
                reply.expand(&[0x86])?;
                reply.append_len(serialized_key.len() + 1)?;
                reply.expand(&[0x04])?;
                reply.expand(&serialized_key)?;
                reply.prepend_len(offset)?;
            }
            AsymmetricAlgorithms::P384 => {
                let serialized_key = syscall!(self.trussed.serialize_key(
                    parsed_mechanism.key_mechanism(),
                    public_key,
                    KeySerialization::Raw
                ))
                .serialized_key;
                reply.expand(&[0x7F, 0x49])?;
                let offset = reply.len();
                reply.expand(&[0x86])?;
                reply.append_len(serialized_key.len() + 1)?;
                reply.expand(&[0x04])?;
                reply.expand(&serialized_key)?;
                reply.prepend_len(offset)?;
            }
            #[cfg(feature = "rsa")]
            AsymmetricAlgorithms::Rsa2048
            | AsymmetricAlgorithms::Rsa3072
            | AsymmetricAlgorithms::Rsa4096 => {
                use trussed_rsa_alloc::RsaPublicParts;
                reply.expand(&[0x7F, 0x49])?;
                let offset = reply.len();
                let tmp = syscall!(self.trussed.serialize_key(
                    parsed_mechanism.key_mechanism(),
                    public_key,
                    KeySerialization::RsaParts
                ))
                .serialized_key;
                let serialized = RsaPublicParts::deserialize(&tmp).map_err(|_err| {
                    error!("Failed to parse RSA parts: {:?}", _err);
                    Status::UnspecifiedNonpersistentExecutionError
                })?;
                reply.expand(&[0x81])?;
                reply.append_len(serialized.n.len())?;
                reply.expand(serialized.n)?;

                reply.expand(&[0x82])?;
                reply.append_len(serialized.e.len())?;
                reply.expand(serialized.e)?;

                reply.prepend_len(offset)?;
            }
        };
        syscall!(self.trussed.delete(public_key));
        if reference.is_encrypted() {
            syscall!(self.trussed.clear(secret_key));
        }

        Ok(())
    }

    fn get_data<const R: usize>(
        &mut self,
        container: Container,
        mut reply: Reply<'_, R>,
    ) -> Result {
        let read_valid =
            self.state
                .volatile
                .read_valid_key(container, self.trussed, self.options)?;

        use state::ContainerStorage;
        let tag = match container {
            Container::DiscoveryObject => [0x7E].as_slice(),
            Container::BiometricInformationTemplatesGroupTemplate => &[0x7F, 0x61],
            _ => &[0x53],
        };
        reply.expand(tag)?;
        match container {
            Container::KeyHistoryObject => {
                let offset = reply.len();
                self.get_key_history_object(reply.lend())?;
                reply.prepend_len(offset)?;
            }
            _ => {
                error!("Getting {container:?}");
                let res = ContainerStorage(container).load(
                    self.trussed,
                    self.options.storage,
                    reply.lend(),
                    read_valid,
                );

                if !res? {
                    return Err(Status::NotFound);
                }
            }
        }

        Ok(())
    }

    fn put_data(&mut self, put_data: PutData<'_>) -> Result {
        if !self
            .state
            .volatile
            .app_security_status
            .administrator_verified
        {
            warn!("Unauthorized attempt at PUT DATA: {:?}", put_data);
            return Err(Status::SecurityStatusNotSatisfied);
        }

        let (container, data) = match put_data {
            PutData::Any(container, data) => (container, data),
            PutData::BitGroupTemplate(data) => {
                (Container::BiometricInformationTemplatesGroupTemplate, data)
            }
            PutData::DiscoveryObject(data) => (Container::DiscoveryObject, data),
        };

        use state::ContainerStorage;
        ContainerStorage(container).save(self.trussed, data, self.options.storage)
    }

    fn reset_retry_counter(&mut self, data: ResetRetryCounter) -> Result {
        let res = self.state.persistent.reset_retry_counter(
            &Puk(data.puk),
            &Pin(data.pin),
            self.trussed,
        )?;
        if !res {
            return Err(Status::RemainingRetries(
                self.state.persistent.remaining_puk_retries(self.trussed),
            ));
        }
        Ok(())
    }

    fn get_key_history_object<const R: usize>(&mut self, mut reply: Reply<'_, R>) -> Result {
        use state::ContainerStorage;

        let mut num_certs = 0;
        for c in RETIRED_CERTS {
            if ContainerStorage(c).exists(self.trussed, self.options.storage)? {
                num_certs += 1;
            }
        }

        reply.expand(&[0xC1, 0x01])?;
        reply.expand(&[num_certs])?;
        reply.expand(&[0xC2, 0x01])?;
        reply.expand(&[0])?;
        reply.expand(&[0xFE, 0x00])?;
        Ok(())
    }

    fn import_asymmetric_key<const R: usize>(
        &mut self,
        algo: AsymmetricAlgorithms,
        key: AsymmetricKeyReference,
        #[cfg_attr(not(feature = "rsa"), allow(unused))] data: &[u8],
        mut _reply: Reply<'_, R>,
    ) -> Result {
        if !self
            .state
            .volatile
            .app_security_status
            .administrator_verified
        {
            return Err(Status::SecurityStatusNotSatisfied);
        }

        match (algo, key) {
            // TODO: document Here we do not exactly follow the Yubico extensions to fit better with our RSA backend requirements
            #[cfg(feature = "rsa")]
            (
                AsymmetricAlgorithms::Rsa2048
                | AsymmetricAlgorithms::Rsa3072
                | AsymmetricAlgorithms::Rsa4096,
                AsymmetricKeyReference::PivAuthentication,
            ) => {
                use trussed_rsa_alloc::RsaImportFormat;
                let p = tlv::get_do(&[0x01], data).ok_or(Status::IncorrectDataParameter)?;
                let q = tlv::get_do(&[0x02], data).ok_or(Status::IncorrectDataParameter)?;
                let e = tlv::get_do(&[0x03], data).ok_or(Status::IncorrectDataParameter)?;
                let id = syscall!(self.trussed.unsafe_inject_key(
                    algo.key_mechanism(),
                    &RsaImportFormat { e, p, q }.serialize().map_err(|_err| {
                        error!("Failed rsa import serialization: {_err:?}");
                        Status::UnspecifiedNonpersistentExecutionError
                    })?,
                    AsymmetricKeyReference::PivAuthentication.storage(self.options.storage),
                    KeySerialization::RsaParts
                ))
                .key;
                self.state.persistent.replace_asymmetric_key(
                    key,
                    algo,
                    id,
                    self.trussed,
                    self.options.storage,
                );
                Ok(())
            }
            _ => Err(Status::FunctionNotSupported),
        }
    }
}

/// Super trait with all trussed extensions required by opcard
pub trait Client:
    CryptoClient
    + FilesystemClient
    + AuthClient
    + ChunkedClient
    + Tdes
    + WrapKeyToFileClient
    + HpkeClient
{
}
impl<
        C: CryptoClient
            + FilesystemClient
            + AuthClient
            + ChunkedClient
            + Tdes
            + WrapKeyToFileClient
            + HpkeClient,
    > Client for C
{
}
