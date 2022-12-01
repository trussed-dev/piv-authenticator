// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[cfg(feature = "delog")]
delog::generate_macros!();

pub mod commands;
use commands::containers::KeyReference;
use commands::{AsymmetricKeyReference, GeneralAuthenticate};
pub use commands::{Command, YubicoPivExtension};
pub mod constants;
pub mod container;
use container::AttestKeyReference;
pub mod derp;
#[cfg(feature = "apdu-dispatch")]
mod dispatch;
pub mod piv_types;
mod reply;
pub mod state;

pub use piv_types::{AsymmetricAlgorithms, Pin, Puk};

#[cfg(feature = "virtual")]
pub mod vpicc;

use core::convert::TryInto;

use flexiber::EncodableHeapless;
use heapless_bytes::Bytes;
use iso7816::{Data, Status};
use trussed::types::{Location, StorageAttributes};
use trussed::{client, syscall, try_syscall};

use constants::*;

pub type Result = iso7816::Result<()>;
use reply::Reply;
use state::{AdministrationAlgorithm, CommandCache, LoadedState, State, TouchPolicy};

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
            .with_supported_cryptographic_algorithms(&[Tdes, Aes256, P256, Ed25519, X25519]);

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
            Command::GetData(container) => self.get_data(container, reply),
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
            _ => todo!(),
        }
    }

    fn get_data<const R: usize>(
        &mut self,
        container: container::Container,
        mut reply: Reply<'_, R>,
    ) -> Result {
        // TODO: check security status, else return Status::SecurityStatusNotSatisfied

        // Table 3, Part 1, SP 800-73-4
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=30
        use crate::container::Container;
        match container {
            Container::DiscoveryObject => {
                // Err(Status::InstructionNotSupportedOrInvalid)
                reply.extend_from_slice(DISCOVERY_OBJECT).ok();
                // todo!("discovery object"),
            }

            Container::BiometricInformationTemplatesGroupTemplate => {
                return Err(Status::InstructionNotSupportedOrInvalid);
                // todo!("biometric information template"),
            }

            // '5FC1 07' (351B)
            Container::CardCapabilityContainer => {
                piv_types::CardCapabilityContainer::default()
                    .encode_to_heapless_vec(*reply)
                    .unwrap();
                info!("returning CCC {:02X?}", reply);
            }

            // '5FC1 02' (351B)
            Container::CardHolderUniqueIdentifier => {
                let guid = self.state.persistent(&mut self.trussed)?.guid();
                piv_types::CardHolderUniqueIdentifier::default()
                    .with_guid(guid)
                    .encode_to_heapless_vec(*reply)
                    .unwrap();
                info!("returning CHUID {:02X?}", reply);
            }

            // // '5FC1 05' (351B)
            // Container::X509CertificateForPivAuthentication => {
            //     // return Err(Status::NotFound);

            //     // info!("loading 9a cert");
            //     // it seems like fetching this certificate is the way Filo's agent decides
            //     // whether the key is "already setup":
            //     // https://github.com/FiloSottile/yubikey-agent/blob/8781bc0082db5d35712a2244e3ab3086f415dd59/setup.go#L69-L70
            //     let data = try_syscall!(self.trussed.read_file(
            //         trussed::types::Location::Internal,
            //         trussed::types::PathBuf::from(b"authentication-key.x5c"),
            //     )).map_err(|_| {
            //         // info!("error loading: {:?}", &e);
            //         Status::NotFound
            //     } )?.data;

            //     // todo: cleanup
            //     let tag = flexiber::Tag::application(0x13); // 0x53
            //     flexiber::TaggedSlice::from(tag, &data)
            //         .unwrap()
            //         .encode_to_heapless_vec(reply)
            //         .unwrap();
            // }

            // // '5F FF01' (754B)
            // YubicoObjects::AttestationCertificate => {
            //     let data = Data<R>::from_slice(YUBICO_ATTESTATION_CERTIFICATE).unwrap();
            //     reply.extend_from_slice(&data).ok();
            // }
            _ => {
                warn!("Unimplemented GET DATA object: {container:?}");
                return Err(Status::FunctionNotSupported);
            }
        }
        Ok(())
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
                self.state.runtime.app_security_status.pin_verified = false;
                self.state.runtime.app_security_status.puk_verified = false;
                self.state
                    .runtime
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
            .runtime
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

            if self.state.persistent.verify_pin(&pin) {
                self.state
                    .persistent
                    .reset_consecutive_pin_mismatches(self.trussed);
                self.state.runtime.app_security_status.pin_verified = true;
                Ok(())
            } else {
                let remaining = self
                    .state
                    .persistent
                    .increment_consecutive_pin_mismatches(self.trussed);
                // should we logout here?
                self.state.runtime.app_security_status.pin_verified = false;
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
                self.state.runtime.app_security_status.pin_verified = false;
                Ok(())
            }

            Verify::Status(key_reference) => {
                if key_reference != commands::VerifyKeyReference::ApplicationPin {
                    return Err(Status::FunctionNotSupported);
                }
                if self.state.runtime.app_security_status.pin_verified {
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

        if !self.state.persistent.verify_pin(&old_pin) {
            let remaining = self
                .state
                .persistent
                .increment_consecutive_pin_mismatches(self.trussed);
            self.state.runtime.app_security_status.pin_verified = false;
            return Err(Status::RemainingRetries(remaining));
        }

        self.state
            .persistent
            .reset_consecutive_pin_mismatches(self.trussed);
        self.state.persistent.set_pin(new_pin, self.trussed);
        self.state.runtime.app_security_status.pin_verified = true;
        Ok(())
    }

    pub fn change_puk(&mut self, old_puk: commands::Puk, new_puk: commands::Puk) -> Result {
        if self.state.persistent.remaining_puk_retries() == 0 {
            return Err(Status::OperationBlocked);
        }

        if !self.state.persistent.verify_puk(&old_puk) {
            let remaining = self
                .state
                .persistent
                .increment_consecutive_puk_mismatches(self.trussed);
            self.state.runtime.app_security_status.puk_verified = false;
            return Err(Status::RemainingRetries(remaining));
        }

        self.state
            .persistent
            .reset_consecutive_puk_mismatches(self.trussed);
        self.state.persistent.set_puk(new_puk, self.trussed);
        self.state.runtime.app_security_status.puk_verified = true;
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
                            0x83 => self.exponentiation(auth, data, reply.lend())?,
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
        _reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for response");

        if data.is_empty() {
            // Not sure if this is correct
            return Ok(());
        }

        let alg = self.state.persistent.keys.administration.alg;
        if data.len() != alg.challenge_length() {
            warn!("Bad response length");
            return Err(Status::IncorrectDataParameter);
        }
        if alg != auth.algorithm {
            warn!("Bad algorithm");
            return Err(Status::IncorrectP1OrP2Parameter);
        }

        let Some(CommandCache::AuthenticateChallenge(plaintext)) = self.state.runtime.command_cache.take() else {
            warn!("Request for response without cached challenge");
            return Err(Status::ConditionsOfUseNotSatisfied);
        };
        let ciphertext = syscall!(self.trussed.encrypt(
            alg.mechanism(),
            self.state.persistent.keys.administration.id,
            &plaintext,
            &[],
            None
        ))
        .ciphertext;

        use subtle::ConstantTimeEq;
        if data.as_slice_less_safe().ct_eq(&ciphertext).into() {
            self.state
                .runtime
                .app_security_status
                .administrator_verified = true;
            Ok(())
        } else {
            Err(Status::SecurityStatusNotSatisfied)
        }
    }

    pub fn exponentiation<const R: usize>(
        &mut self,
        _auth: GeneralAuthenticate,
        _data: derp::Input<'_>,
        _reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for exponentiation");
        todo!()
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
            self.response_for_challenge(auth, data, reply)
        }
    }

    pub fn response_for_challenge<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        data: derp::Input<'_>,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("Response for challenge ");

        let alg = self.state.persistent.keys.administration.alg;
        if alg != auth.algorithm {
            warn!("Bad algorithm");
            return Err(Status::IncorrectP1OrP2Parameter);
        }

        if data.len() != alg.challenge_length() {
            warn!("Bad challenge length");
            return Err(Status::IncorrectDataParameter);
        }

        let response = syscall!(self.trussed.encrypt(
            alg.mechanism(),
            self.state.persistent.keys.administration.id,
            data.as_slice_less_safe(),
            &[],
            None
        ))
        .ciphertext;

        reply.expand(&[0x82])?;
        reply.append_len(response.len())?;
        reply.expand(&response)
    }

    pub fn request_for_challenge<const R: usize>(
        &mut self,
        auth: GeneralAuthenticate,
        mut reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for challenge ");

        let alg = self.state.persistent.keys.administration.alg;
        if alg != auth.algorithm {
            warn!("Bad algorithm");
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        let challenge = syscall!(self.trussed.random_bytes(alg.challenge_length())).bytes;
        self.state.runtime.command_cache = Some(CommandCache::AuthenticateChallenge(
            Bytes::from_slice(&challenge).unwrap(),
        ));

        reply.expand(&[0x81])?;
        reply.append_len(challenge.len())?;
        reply.expand(&challenge)
    }

    pub fn witness<const R: usize>(
        &mut self,
        _auth: GeneralAuthenticate,
        _data: derp::Input<'_>,
        _reply: Reply<'_, R>,
    ) -> Result {
        info!("Request for witness");
        todo!()
    }

    pub fn generate_asymmetric_keypair<const R: usize>(
        &mut self,
        reference: AsymmetricKeyReference,
        data: &[u8],
        mut reply: Reply<'_, R>,
    ) -> Result {
        if !self
            .state
            .runtime
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
            reference,
            parsed_mechanism,
            self.trussed,
        );

        // // TEMP
        // let mechanism = trussed::types::Mechanism::P256Prehashed;
        // let mechanism = trussed::types::Mechanism::P256;
        // let commitment = &[37u8; 32];
        // // blocking::dbg!(commitment);
        // let serialization = trussed::types::SignatureSerialization::Asn1Der;
        // // blocking::dbg!(&key);
        // let signature = block!(self.trussed.sign(mechanism, key.clone(), commitment, serialization).map_err(|e| {
        //     blocking::dbg!(e);
        //     e
        // }).unwrap())
        //     .map_err(|error| {
        //         // NoSuchKey
        //         blocking::dbg!(error);
        //         Status::UnspecifiedNonpersistentExecutionError }
        //     )?
        //     .signature;
        // blocking::dbg!(&signature);
        // self.state.persistent.keys.authentication_key = Some(key);
        // self.state.persistent.save(self.trussed);

        // let public_key = syscall!(self.trussed.derive_p256_public_key(
        let public_key = syscall!(self.trussed.derive_key(
            parsed_mechanism.mechanism(),
            secret_key,
            None,
            StorageAttributes::default().set_persistence(Location::Volatile)
        ))
        .key;

        match parsed_mechanism {
            AsymmetricAlgorithms::P256 => {
                let serialized_key = syscall!(self.trussed.serialize_key(
                    trussed::types::Mechanism::P256,
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
                let serialized_e = syscall!(self.trussed.serialize_key(
                    trussed::types::Mechanism::P256,
                    public_key,
                    trussed::types::KeySerialization::RsaE
                ))
                .serialized_key;
                reply.expand(&[0x81])?;
                reply.append_len(serialized_e.len())?;
                reply.expand(&serialized_e)?;

                let serialized_n = syscall!(self.trussed.serialize_key(
                    trussed::types::Mechanism::P256,
                    public_key,
                    trussed::types::KeySerialization::RsaN
                ))
                .serialized_key;
                reply.expand(&[0x82])?;
                reply.append_len(serialized_n.len())?;
                reply.expand(&serialized_n)?;

                reply.prepend_len(offset)?;
            }
        };

        Ok(())
    }

    #[allow(unused)]
    pub fn put_data(&mut self, data: &[u8]) -> Result {
        info!("PutData");

        // if !self.state.runtime.app_security_status.administrator_verified {
        //     return Err(Status::SecurityStatusNotSatisfied);
        // }

        // # PutData
        // 00 DB 3F FF 23
        //    # data object: 5FC109
        //    5C 03 5F C1 09
        //    # data:
        //    53 1C
        //       # actual data
        //       88 1A 89 18 AA 81 D5 48 A5 EC 26 01 60 BA 06 F6 EC 3B B6 05 00 2E B6 3D 4B 28 7F 86
        //

        let input = derp::Input::from(data);
        let (data_object, data) = input
            .read_all(derp::Error::Read, |input| {
                let data_object = derp::expect_tag_and_get_value(input, 0x5c)?;
                let data = derp::expect_tag_and_get_value(input, 0x53)?;
                Ok((data_object.as_slice_less_safe(), data.as_slice_less_safe()))
                // }).unwrap();
            })
            .map_err(|_e| {
                info!("error parsing PutData: {:?}", &_e);
                Status::IncorrectDataParameter
            })?;

        // info!("PutData in {:?}: {:?}", data_object, data);

        if data_object == [0x5f, 0xc1, 0x09] {
            // "Printed Information", supposedly
            // Yubico uses this to store its "Metadata"
            //
            // 88 1A
            //    89 18
            //       # we see here the raw management key? amazing XD
            //       AA 81 D5 48 A5 EC 26 01 60 BA 06 F6 EC 3B B6 05 00 2E B6 3D 4B 28 7F 86

            // TODO: use smarter quota rule, actual data sent is 28B
            if data.len() >= 512 {
                return Err(Status::UnspecifiedCheckingError);
            }

            try_syscall!(self.trussed.write_file(
                trussed::types::Location::Internal,
                trussed::types::PathBuf::from(b"printed-information"),
                trussed::types::Message::from_slice(data).unwrap(),
                None,
            ))
            .map_err(|_| Status::NotEnoughMemory)?;

            return Ok(());
        }

        if data_object == [0x5f, 0xc1, 0x05] {
            // "X.509 Certificate for PIV Authentication", supposedly
            // IOW, the cert for "authentication key"
            // Yubico uses this to store its "Metadata"
            //
            // 88 1A
            //    89 18
            //       # we see here the raw management key? amazing XD
            //       AA 81 D5 48 A5 EC 26 01 60 BA 06 F6 EC 3B B6 05 00 2E B6 3D 4B 28 7F 86

            // TODO: use smarter quota rule, actual data sent is 28B
            if data.len() >= 512 {
                return Err(Status::UnspecifiedCheckingError);
            }

            try_syscall!(self.trussed.write_file(
                trussed::types::Location::Internal,
                trussed::types::PathBuf::from(b"authentication-key.x5c"),
                trussed::types::Message::from_slice(data).unwrap(),
                None,
            ))
            .map_err(|_| Status::NotEnoughMemory)?;

            return Ok(());
        }

        Err(Status::IncorrectDataParameter)
    }

    // match container {
    //     containers::Container::CardHolderUniqueIdentifier =>
    //         piv_types::CardHolderUniqueIdentifier::default()
    //         .encode
    //     _ => todo!(),
    // }
    // todo!();
}
