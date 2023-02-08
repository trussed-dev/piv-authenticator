// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[cfg(feature = "delog")]
delog::generate_macros!();

pub mod commands;
use commands::piv_types::{Algorithms, RsaAlgorithms};
pub use commands::{Command, YubicoPivExtension};
use commands::{GeneralAuthenticate, PutData, ResetRetryCounter};
pub mod constants;
pub mod container;
use container::{
    AttestKeyReference, AuthenticateKeyReference, Container, GenerateKeyReference, KeyReference,
};
pub mod derp;
#[cfg(feature = "apdu-dispatch")]
mod dispatch;
pub mod piv_types;
mod reply;
pub mod state;
mod tlv;

pub use piv_types::{AsymmetricAlgorithms, Pin, Puk};

#[cfg(feature = "virtual")]
pub mod vpicc;

use core::convert::TryInto;

use flexiber::EncodableHeapless;
use heapless_bytes::Bytes;
use iso7816::{Data, Status};
use trussed::types::{KeySerialization, Location, StorageAttributes};
use trussed::{client, syscall, try_syscall};

use constants::*;

pub type Result = iso7816::Result<()>;
use reply::Reply;
use state::{AdministrationAlgorithm, CommandCache, KeyWithAlg, LoadedState, State, TouchPolicy};

use crate::container::AsymmetricKeyReference;

/// PIV authenticator Trussed app.
///
/// The `C` parameter is necessary, as PIV includes command sequences,
/// where we need to store the previous command, so we need to know how
/// much space to allocate.
pub struct Authenticator<T> {
    state: State,
    trussed: T,
}

struct LoadedAuthenticator<'a, T> {
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
    T: client::Client + client::Ed255 + client::Tdes,
{
    pub fn new(trussed: T) -> Self {
        // seems like RefCell is not the right thing, we want something like `Rc` instead,
        // which can be cloned and injected into other parts of the App that use Trussed.
        // let trussed = RefCell::new(trussed);
        Self {
            // state: state::State::new(trussed.clone()),
            state: Default::default(),
            trussed,
        }
    }

    fn load(&mut self) -> core::result::Result<LoadedAuthenticator<'_, T>, Status> {
        Ok(LoadedAuthenticator {
            state: self.state.load(&mut self.trussed)?,
            trussed: &mut self.trussed,
        })
    }

    // TODO: we'd like to listen on multiple AIDs.
    // The way apdu-dispatch currently works, this would deselect, resetting security indicators.
    pub fn deselect(&mut self) {}

    pub fn select<const R: usize>(&mut self, mut reply: Reply<'_, R>) -> Result {
        use piv_types::Algorithms::*;
        info!("selecting PIV maybe");

        let application_property_template = piv_types::ApplicationPropertyTemplate::default()
            .with_application_label(APPLICATION_LABEL)
            .with_application_url(APPLICATION_URL)
            .with_supported_cryptographic_algorithms(&[
                Tdes, Aes256, P256, Ed25519, X25519, Rsa2048,
            ]);

        application_property_template
            .encode_to_heapless_vec(*reply)
            .unwrap();
        info!("returning: {:02X?}", reply);
        Ok(())
    }

    pub fn respond<const R: usize, const C: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        info!("PIV responding to {:02x?}", command);
        let parsed_command: Command = command.try_into()?;
        info!("parsed: {:?}", &parsed_command);
        let reply = Reply(reply);

        match parsed_command {
            Command::Verify(verify) => self.load()?.verify(verify),
            Command::ChangeReference(change_reference) => {
                self.load()?.change_reference(change_reference)
            }
            Command::GetData(container) => self.load()?.get_data(container, reply),
            Command::PutData(put_data) => self.load()?.put_data(put_data),
            Command::Select(_aid) => self.select(reply),
            Command::GeneralAuthenticate(authenticate) => {
                self.load()?
                    .general_authenticate(authenticate, command.data(), reply)
            }
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

            YubicoPivExtension::Attest(slot) => {
                match slot {
                    AttestKeyReference::PivAuthentication => reply
                        .extend_from_slice(YUBICO_ATTESTATION_CERTIFICATE_FOR_9A)
                        .ok(),
                };
            }

            YubicoPivExtension::Reset => {
                let persistent_state = self.state.persistent(&mut self.trussed)?;

                // TODO: find out what all needs resetting :)
                persistent_state.reset_pin(&mut self.trussed);
                persistent_state.reset_puk(&mut self.trussed);
                persistent_state.reset_administration_key(&mut self.trussed);
                self.state.volatile.app_security_status.pin_verified = false;
                self.state.volatile.app_security_status.puk_verified = false;
                self.state
                    .volatile
                    .app_security_status
                    .administrator_verified = false;

                try_syscall!(self.trussed.remove_file(
                    trussed::types::Location::Internal,
                    trussed::types::PathBuf::from(b"printed-information"),
                ))
                .ok();

                try_syscall!(self.trussed.remove_file(
                    trussed::types::Location::Internal,
                    trussed::types::PathBuf::from(b"authentication-key.x5c"),
                ))
                .ok();
            }

            YubicoPivExtension::SetManagementKey(touch_policy) => {
                self.load()?
                    .yubico_set_administration_key(data, touch_policy, reply)?;
            }

            YubicoPivExtension::GetMetadata(_reference) => { /* TODO */ }
            _ => return Err(Status::FunctionNotSupported),
        }
        Ok(())
    }
}

impl<'a, T: trussed::Client + trussed::client::Ed255> LoadedAuthenticator<'a, T> {
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
            // the actual PIN verification
            if self.state.persistent.remaining_pin_retries() == 0 {
                return Err(Status::OperationBlocked);
            }

            if self.state.persistent.verify_pin(&pin, self.trussed) {
                self.state
                    .persistent
                    .reset_consecutive_pin_mismatches(self.trussed);
                self.state.volatile.app_security_status.pin_verified = true;
                Ok(())
            } else {
                let remaining = self
                    .state
                    .persistent
                    .increment_consecutive_pin_mismatches(self.trussed);
                // should we logout here?
                self.state.volatile.app_security_status.pin_verified = false;
                Err(Status::RemainingRetries(remaining))
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
                self.state.volatile.app_security_status.pin_verified = false;
                Ok(())
            }

            Verify::Status(key_reference) => {
                if key_reference != commands::VerifyKeyReference::ApplicationPin {
                    return Err(Status::FunctionNotSupported);
                }
                if self.state.volatile.app_security_status.pin_verified {
                    Ok(())
                } else {
                    let retries = self.state.persistent.remaining_pin_retries();
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
        if self.state.persistent.remaining_pin_retries() == 0 {
            return Err(Status::OperationBlocked);
        }

        if !self.state.persistent.verify_pin(&old_pin, self.trussed) {
            let remaining = self
                .state
                .persistent
                .increment_consecutive_pin_mismatches(self.trussed);
            self.state.volatile.app_security_status.pin_verified = false;
            return Err(Status::RemainingRetries(remaining));
        }

        self.state
            .persistent
            .reset_consecutive_pin_mismatches(self.trussed);
        self.state.persistent.set_pin(new_pin, self.trussed);
        self.state.volatile.app_security_status.pin_verified = true;
        Ok(())
    }

    pub fn change_puk(&mut self, old_puk: commands::Puk, new_puk: commands::Puk) -> Result {
        if self.state.persistent.remaining_puk_retries() == 0 {
            return Err(Status::OperationBlocked);
        }

        if !self.state.persistent.verify_puk(&old_puk, self.trussed) {
            let remaining = self
                .state
                .persistent
                .increment_consecutive_puk_mismatches(self.trussed);
            self.state.volatile.app_security_status.puk_verified = false;
            return Err(Status::RemainingRetries(remaining));
        }

        self.state
            .persistent
            .reset_consecutive_puk_mismatches(self.trussed);
        self.state.persistent.set_puk(new_puk, self.trussed);
        self.state.volatile.app_security_status.puk_verified = true;
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
            .security_valid(auth.key_reference.use_security_condition())
        {
            warn!(
                "Security condition not satisfied for key {:?}",
                auth.key_reference
            );
            return Err(Status::SecurityStatusNotSatisfied);
        }

        reply.expand(&[0x7C])?;
        let offset = reply.len();
        let input = derp::Input::from(data);
        input.read_all(Status::IncorrectDataParameter, |input| {
            derp::nested(
                input,
                Status::IncorrectDataParameter,
                Status::IncorrectDataParameter,
                0x7C,
                |input| {
                    while !input.at_end() {
                        let (tag, data) = match derp::read_tag_and_get_value(input) {
                            Ok((tag, data)) => (tag, data),
                            Err(_err) => {
                                warn!("Failed to parse data: {:?}", _err);
                                return Err(Status::IncorrectDataParameter);
                            }
                        };

                        // part 2 table 7
                        match tag {
                            0x80 => self.witness(auth, data, reply.lend())?,
                            0x81 => self.challenge(auth, data, reply.lend())?,
                            0x82 => self.response(auth, data, reply.lend())?,
                            0x85 => self.exponentiation(auth, data, reply.lend())?,
                            _ => return Err(Status::IncorrectDataParameter),
                        }
                    }
                    Ok(())
                },
            )
        })?;
        reply.prepend_len(offset)
    }

    pub fn response<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        data: derp::Input<'_>,
        reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for response");

        if data.is_empty() {
            info!("Empty data");
            return Ok(());
        }
        if auth.key_reference != KeyReference::PivCardApplicationAdministration {
            warn!("Response with bad key ref: {:?}", auth);
            return Err(Status::IncorrectP1OrP2Parameter);
        }

        match self.state.volatile.command_cache.take() {
            Some(CommandCache::AuthenticateChallenge(original)) => {
                info!("Got response for challenge");
                self.admin_challenge_validate(auth.algorithm, data, original, reply)
            }
            Some(CommandCache::WitnessChallenge(original)) => {
                info!("Got response for challenge");
                self.admin_witness_validate(auth.algorithm, data, original, reply)
            }
            _ => {
                warn!("Response without a challenge or a witness");
                Err(Status::ConditionsOfUseNotSatisfied)
            }
        }
    }

    pub fn exponentiation<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        data: derp::Input<'_>,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for exponentiation");
        let key_reference = auth.key_reference.try_into().map_err(|_| {
            warn!(
                "Attempt to use non asymetric key for exponentiation: {:?}",
                auth.key_reference
            );
            Status::IncorrectP1OrP2Parameter
        })?;
        let Some(KeyWithAlg { alg, id }) = self.state.persistent.keys.asymetric_for_reference(key_reference) else {
            warn!("Attempt to use unset key");
            return Err(Status::ConditionsOfUseNotSatisfied);
        };

        if alg != auth.algorithm {
            warn!("Attempt to exponentiate with incorrect algorithm");
            return Err(Status::IncorrectP1OrP2Parameter);
        }

        let Some(mechanism) = alg.ecdh_mechanism() else {
            warn!("Attempt to exponentiate with non ECDH algorithm");
            return Err(Status::ConditionsOfUseNotSatisfied);
        };

        let data = data.as_slice_less_safe();
        if data.first() != Some(&0x04) {
            warn!("Bad data format for ECDH");
            return Err(Status::IncorrectDataParameter);
        }

        let public_key = try_syscall!(self.trussed.deserialize_key(
            mechanism,
            &data[1..],
            KeySerialization::Raw,
            StorageAttributes::default().set_persistence(Location::Volatile)
        ))
        .map_err(|_err| {
            warn!("Failed to load public key: {:?}", _err);
            Status::IncorrectDataParameter
        })?
        .key;
        let shared_secret = syscall!(self.trussed.agree(
            mechanism,
            id,
            public_key,
            StorageAttributes::default()
                .set_persistence(Location::Volatile)
                .set_serializable(true)
        ))
        .shared_secret;

        let serialized_secret = syscall!(self.trussed.serialize_key(
            trussed::types::Mechanism::SharedSecret,
            shared_secret,
            KeySerialization::Raw
        ))
        .serialized_key;
        syscall!(self.trussed.delete(public_key));
        syscall!(self.trussed.delete(shared_secret));

        reply.expand(&[0x82])?;
        reply.append_len(serialized_secret.len())?;
        reply.expand(&serialized_secret)
    }

    pub fn challenge<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        data: derp::Input<'_>,
        reply: Reply<'_, R>,
    ) -> Result {
        if data.is_empty() {
            self.request_for_challenge(auth, reply)
        } else {
            use AuthenticateKeyReference::*;
            match auth.key_reference {
                PivCardApplicationAdministration => {
                    self.admin_challenge(auth.algorithm, data, reply)
                }
                SecureMessaging => Err(Status::FunctionNotSupported),
                PivAuthentication | CardAuthentication | DigitalSignature => self.sign_challenge(
                    auth.algorithm,
                    auth.key_reference.try_into().map_err(|_| {
                        if cfg!(debug_assertions) {
                            // To find errors more easily in tests and fuzzing but not crash in production
                            panic!("Failed to convert key reference: {:?}", auth.key_reference);
                        } else {
                            error!("Failed to convert key reference: {:?}", auth.key_reference);
                            Status::UnspecifiedPersistentExecutionError
                        }
                    })?,
                    data,
                    reply,
                ),
                KeyManagement | Retired01 | Retired02 | Retired03 | Retired04 | Retired05
                | Retired06 | Retired07 | Retired08 | Retired09 | Retired10 | Retired11
                | Retired12 | Retired13 | Retired14 | Retired15 | Retired16 | Retired17
                | Retired18 | Retired19 | Retired20 => self.agreement_challenge(
                    auth.algorithm,
                    auth.key_reference.try_into().map_err(|_| {
                        if cfg!(debug_assertions) {
                            // To find errors more easily in tests and fuzzing but not crash in production
                            panic!("Failed to convert key reference: {:?}", auth.key_reference);
                        } else {
                            error!("Failed to convert key reference: {:?}", auth.key_reference);
                            Status::UnspecifiedPersistentExecutionError
                        }
                    })?,
                    data,
                    reply,
                ),
            }
        }
    }

    pub fn agreement_challenge<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        key_ref: AsymmetricKeyReference,
        data: derp::Input<'_>,
        mut reply: Reply<'_, R>,
    ) -> Result {
        let Some(KeyWithAlg { alg, id }) = self.state.persistent.keys.asymetric_for_reference(key_ref) else {
            warn!("Attempt to use unset key");
            return Err(Status::ConditionsOfUseNotSatisfied);
        };

        if alg != requested_alg {
            warn!("Bad algorithm: {:?}", requested_alg);
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        let rsa_alg: RsaAlgorithms = alg.try_into().map_err(|_| {
            warn!("Tried to perform agreement on a challenge with a non-rsa algorithm");
            Status::ConditionsOfUseNotSatisfied
        })?;

        let response = try_syscall!(self.trussed.decrypt(
            rsa_alg.mechanism(),
            id,
            data.as_slice_less_safe(),
            &[],
            &[],
            &[]
        ))
        .map_err(|_err| {
            warn!("Failed to decrypt challenge: {:?}", _err);
            Status::IncorrectDataParameter
        })?
        .plaintext
        .ok_or_else(|| {
            warn!("Failed to decrypt challenge, no plaintext");
            Status::IncorrectDataParameter
        })?;
        reply.expand(&[0x82])?;
        reply.append_len(response.len())?;
        reply.expand(&response)?;
        Ok(())
    }

    pub fn sign_challenge<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        key_ref: AsymmetricKeyReference,
        data: derp::Input<'_>,
        mut reply: Reply<'_, R>,
    ) -> Result {
        let Some(KeyWithAlg { alg, id }) = self.state.persistent.keys.asymetric_for_reference(key_ref) else {
            warn!("Attempt to use unset key");
            return Err(Status::ConditionsOfUseNotSatisfied);
        };

        if alg != requested_alg {
            warn!("Bad algorithm: {:?}", requested_alg);
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        if !self.state.volatile.app_security_status.pin_verified {
            warn!("Authenticate challenge without pin validated");
            return Err(Status::SecurityStatusNotSatisfied);
        }

        // Trussed doesn't support signing pre-padded with RSA, so we remove it.
        // PKCS#1v1.5 padding is 00 01 FF…FF 00
        let data = data.as_slice_less_safe();
        if data.len() < 3 {
            warn!("Attempt to sign too little data");
            return Err(Status::IncorrectDataParameter);
        }
        if data[0] != 0 || data[1] != 1 {
            warn!("Attempt to sign with bad padding");
            return Err(Status::IncorrectDataParameter);
        }
        let mut data = &data[2..];
        loop {
            let Some(b) = data.first() else {
                warn!("Sign is only padding");
                return Err(Status::IncorrectDataParameter);
            };
            data = &data[1..];
            if *b == 0xFF {
                continue;
            }
            if *b == 0 {
                break;
            }
            warn!("Invalid padding value");
            return Err(Status::IncorrectDataParameter);
        }

        let response = syscall!(self.trussed.sign(
            alg.sign_mechanism(),
            id,
            data,
            trussed::types::SignatureSerialization::Raw,
        ))
        .signature;
        reply.expand(&[0x82])?;
        reply.append_len(response.len())?;
        reply.expand(&response)?;
        Ok(())
    }

    pub fn admin_challenge<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        data: derp::Input<'_>,
        reply: Reply<'_, R>,
    ) -> Result {
        info!("Response for challenge ");
        match self.state.volatile.take_challenge() {
            Some(original) => self.admin_challenge_validate(requested_alg, data, original, reply),
            None => self.admin_challenge_respond(requested_alg, data, reply),
        }
    }

    pub fn admin_challenge_respond<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        data: derp::Input<'_>,
        mut reply: Reply<'_, R>,
    ) -> Result {
        let admin = &self.state.persistent.keys.administration;
        if admin.alg != requested_alg {
            warn!("Bad algorithm: {:?}", requested_alg);
            return Err(Status::IncorrectP1OrP2Parameter);
        }

        if data.len() != admin.alg.challenge_length() {
            warn!("Bad challenge length");
            return Err(Status::IncorrectDataParameter);
        }

        let response = syscall!(self.trussed.encrypt(
            admin.alg.mechanism(),
            admin.id,
            data.as_slice_less_safe(),
            &[],
            None
        ))
        .ciphertext;

        info!(
            "Challenge: {:02x?}, response: {:02x?}",
            data.as_slice_less_safe(),
            &*response
        );

        reply.expand(&[0x82])?;
        reply.append_len(response.len())?;
        reply.expand(&response)
    }

    pub fn admin_challenge_validate<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        data: derp::Input<'_>,
        original: Bytes<16>,
        _reply: Reply<'_, R>,
    ) -> Result {
        if self.state.persistent.keys.administration.alg != requested_alg {
            warn!(
                "Incorrect challenge validation algorithm. Expected: {:?}, got {:?}",
                self.state.persistent.keys.administration.alg, requested_alg
            );
        }
        use subtle::ConstantTimeEq;
        if data.as_slice_less_safe().ct_eq(&original).into() {
            info!("Correct challenge validation");
            self.state
                .volatile
                .app_security_status
                .administrator_verified = true;
            Ok(())
        } else {
            warn!("Incorrect challenge validation");
            Err(Status::UnspecifiedCheckingError)
        }
    }

    pub fn request_for_challenge<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for challenge ");

        let alg = self.state.persistent.keys.administration.alg;
        if alg != auth.algorithm {
            warn!("Bad algorithm: {:?}", auth.algorithm);
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        let challenge = syscall!(self.trussed.random_bytes(alg.challenge_length())).bytes;
        let ciphertext = syscall!(self.trussed.encrypt(
            alg.mechanism(),
            self.state.persistent.keys.administration.id,
            &challenge,
            &[],
            None
        ))
        .ciphertext;
        self.state.volatile.command_cache = Some(CommandCache::AuthenticateChallenge(
            Bytes::from_slice(&ciphertext).unwrap(),
        ));

        reply.expand(&[0x81])?;
        reply.append_len(challenge.len())?;
        reply.expand(&challenge)
    }
    pub fn witness<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        data: derp::Input<'_>,
        reply: Reply<'_, R>,
    ) -> Result {
        if data.is_empty() {
            self.request_for_witness(auth, reply)
        } else {
            use AuthenticateKeyReference::*;
            match auth.key_reference {
                PivCardApplicationAdministration => self.admin_witness(auth.algorithm, data, reply),
                _ => Err(Status::FunctionNotSupported),
            }
        }
    }

    pub fn request_for_witness<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for witness");

        let alg = self.state.persistent.keys.administration.alg;
        if alg != auth.algorithm {
            warn!("Bad algorithm: {:?}", auth.algorithm);
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        let data = syscall!(self.trussed.random_bytes(alg.challenge_length())).bytes;
        self.state.volatile.command_cache = Some(CommandCache::WitnessChallenge(
            Bytes::from_slice(&data).unwrap(),
        ));
        info!("{:02x?}", &*data);

        let challenge = syscall!(self.trussed.encrypt(
            alg.mechanism(),
            self.state.persistent.keys.administration.id,
            &data,
            &[],
            None
        ))
        .ciphertext;

        reply.expand(&[0x80])?;
        reply.append_len(challenge.len())?;
        reply.expand(&challenge)
    }

    pub fn admin_witness<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        data: derp::Input<'_>,
        reply: Reply<'_, R>,
    ) -> Result {
        info!("Admin witness");
        match self.state.volatile.take_witness() {
            Some(original) => self.admin_witness_validate(requested_alg, data, original, reply),
            None => self.admin_witness_respond(requested_alg, data, reply),
        }
    }

    pub fn admin_witness_respond<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        data: derp::Input<'_>,
        mut reply: Reply<'_, R>,
    ) -> Result {
        let admin = &self.state.persistent.keys.administration;
        if admin.alg != requested_alg {
            warn!("Bad algorithm: {:?}", requested_alg);
            return Err(Status::IncorrectP1OrP2Parameter);
        }

        if data.len() != admin.alg.challenge_length() {
            warn!(
                "Bad challenge length. Got {}, expected {} for algorithm: {:?}",
                data.len(),
                admin.alg.challenge_length(),
                admin.alg
            );
            return Err(Status::IncorrectDataParameter);
        }
        let response = syscall!(self.trussed.decrypt(
            admin.alg.mechanism(),
            admin.id,
            data.as_slice_less_safe(),
            &[],
            &[],
            &[]
        ))
        .plaintext;

        let Some(response) = response else {
            warn!("Failed to decrypt witness");
            return Err(Status::IncorrectDataParameter);
        };

        reply.expand(&[0x82])?;
        reply.append_len(response.len())?;
        reply.expand(&response)
    }

    pub fn admin_witness_validate<const R: usize>(
        &mut self,
        requested_alg: Algorithms,
        data: derp::Input<'_>,
        original: Bytes<16>,
        _reply: Reply<'_, R>,
    ) -> Result {
        use subtle::ConstantTimeEq;
        if self.state.persistent.keys.administration.alg != requested_alg {
            warn!(
                "Incorrect witness validation algorithm. Expected: {:?}, got {:?}",
                self.state.persistent.keys.administration.alg, requested_alg
            );
        }
        if data.as_slice_less_safe().ct_eq(&original).into() {
            info!("Correct witness validation");
            self.state
                .volatile
                .app_security_status
                .administrator_verified = true;
            Ok(())
        } else {
            warn!("Incorrect witness validation");
            Err(Status::UnspecifiedCheckingError)
        }
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

        // TODO: iterate on this, don't expect tags..
        let input = derp::Input::from(data);
        // let (mechanism, parameter) = input.read_all(derp::Error::Read, |input| {
        let mechanism_data = input.read_all(Status::IncorrectDataParameter, |input| {
            derp::nested(
                input,
                Status::IncorrectDataParameter,
                Status::IncorrectDataParameter,
                0xac,
                |input| {
                    derp::expect_tag_and_get_value(input, 0x80)
                        .map(|input| input.as_slice_less_safe())
                        .map_err(|_e| {
                            warn!("error parsing GenerateAsymmetricKeypair: {:?}", &_e);
                            Status::IncorrectDataParameter
                        })
                },
            )
        })?;

        let [mechanism] = mechanism_data else {
            warn!("Mechanism of len not 1: {mechanism_data:02x?}");
            return Err(Status::IncorrectDataParameter);
        };

        let parsed_mechanism: AsymmetricAlgorithms = (*mechanism).try_into().map_err(|_| {
            warn!("Unknown mechanism: {mechanism:x}");
            Status::IncorrectDataParameter
        })?;

        let secret_key = self.state.persistent.generate_asymmetric_key(
            reference.into(),
            parsed_mechanism,
            self.trussed,
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
                    trussed::types::KeySerialization::Raw
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
            AsymmetricAlgorithms::Rsa2048 | AsymmetricAlgorithms::Rsa4096 => {
                reply.expand(&[0x7F, 0x49])?;
                let offset = reply.len();
                let serialized_n = syscall!(self.trussed.serialize_key(
                    parsed_mechanism.key_mechanism(),
                    public_key,
                    trussed::types::KeySerialization::RsaN
                ))
                .serialized_key;
                reply.expand(&[0x81])?;
                reply.append_len(serialized_n.len())?;
                reply.expand(&serialized_n)?;

                let serialized_e = syscall!(self.trussed.serialize_key(
                    parsed_mechanism.key_mechanism(),
                    public_key,
                    trussed::types::KeySerialization::RsaE
                ))
                .serialized_key;
                reply.expand(&[0x82])?;
                reply.append_len(serialized_e.len())?;
                reply.expand(&serialized_e)?;

                reply.prepend_len(offset)?;
            }
        };
        syscall!(self.trussed.delete(public_key));

        Ok(())
    }

    fn get_data<const R: usize>(
        &mut self,
        container: Container,
        mut reply: Reply<'_, R>,
    ) -> Result {
        if !self
            .state
            .volatile
            .read_valid(container.contact_access_rule())
        {
            warn!("Unauthorized attempt to access: {:?}", container);
            return Err(Status::SecurityStatusNotSatisfied);
        }

        use state::ContainerStorage;
        let tag = match container {
            Container::DiscoveryObject => [0x7E].as_slice(),
            Container::BiometricInformationTemplatesGroupTemplate => &[0x7F, 0x61],
            _ => &[0x53],
        };
        reply.expand(tag)?;
        let offset = reply.len();
        match container {
            Container::KeyHistoryObject => self.get_key_history_object(reply.lend())?,
            _ => match ContainerStorage(container).load(self.trussed)? {
                Some(data) => reply.expand(&data)?,
                None => return Err(Status::NotFound),
            },
        }
        reply.prepend_len(offset)?;

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
        ContainerStorage(container).save(self.trussed, data)
    }

    fn reset_retry_counter(&mut self, data: ResetRetryCounter) -> Result {
        if !self
            .state
            .persistent
            .verify_puk(&Puk(data.puk), self.trussed)
        {
            return Err(Status::VerificationFailed);
        }
        self.state.persistent.set_pin(Pin(data.pin), self.trussed);

        Ok(())
    }

    fn get_key_history_object<const R: usize>(&mut self, mut reply: Reply<'_, R>) -> Result {
        let num_keys = self
            .state
            .persistent
            .keys
            .retired_keys
            .iter()
            .filter(|k| k.is_some())
            .count() as u8;
        let mut num_certs = 0u8;

        use state::ContainerStorage;

        for c in RETIRED_CERTS {
            if ContainerStorage(c).exists(self.trussed)? {
                num_certs += 1;
            }
        }

        reply.expand(&[0xC1, 0x01])?;
        reply.expand(&[num_certs])?;
        reply.expand(&[0xC2, 0x01])?;
        reply.expand(&[num_keys.saturating_sub(num_certs)])?;
        reply.expand(&[0xFE, 0x00])?;
        Ok(())
    }
}
