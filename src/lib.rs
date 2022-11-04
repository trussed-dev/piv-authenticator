#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(not(feature = "delog"))]
#[macro_use]
extern crate log;

#[cfg(feature = "delog")]
delog::generate_macros!();

pub mod commands;
use commands::GeneralAuthenticate;
pub use commands::{Command, YubicoPivExtension};
pub mod constants;
pub mod container;
use container::AttestKeyReference;
pub mod derp;
#[cfg(feature = "apdu-dispatch")]
mod dispatch;
pub mod piv_types;
pub mod state;

pub use piv_types::{Pin, Puk};

#[cfg(feature = "virtual")]
pub mod vpicc;

use core::convert::TryInto;

use flexiber::EncodableHeapless;
use iso7816::{Data, Status};
use trussed::client;
use trussed::{syscall, try_syscall};

use constants::*;

pub type Result = iso7816::Result<()>;

/// PIV authenticator Trussed app.
///
/// The `C` parameter is necessary, as PIV includes command sequences,
/// where we need to store the previous command, so we need to know how
/// much space to allocate.
pub struct Authenticator<T> {
    state: state::State,
    trussed: T,
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

    // TODO: we'd like to listen on multiple AIDs.
    // The way apdu-dispatch currently works, this would deselect, resetting security indicators.
    pub fn deselect(&mut self) {}

    pub fn select<const R: usize>(&mut self, reply: &mut Data<R>) -> Result {
        use piv_types::Algorithms::*;
        info!("selecting PIV maybe");

        let application_property_template = piv_types::ApplicationPropertyTemplate::default()
            .with_application_label(APPLICATION_LABEL)
            .with_application_url(APPLICATION_URL)
            .with_supported_cryptographic_algorithms(&[Tdes, Aes256, P256, Ed25519, X25519]);

        application_property_template
            .encode_to_heapless_vec(reply)
            .unwrap();
        info!("returning: {:02X?}", reply);
        Ok(())
    }

    pub fn respond<const R: usize, const C: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        info!("PIV responding to {:?}", command);
        let parsed_command: Command = command.try_into()?;
        info!("parsed: {:?}", &parsed_command);

        match parsed_command {
            Command::Verify(verify) => self.verify(verify),
            Command::ChangeReference(change_reference) => self.change_reference(change_reference),
            Command::GetData(container) => self.get_data(container, reply),
            Command::Select(_aid) => self.select(reply),
            Command::GeneralAuthenticate(authenticate) => {
                self.general_authenticate(authenticate, command.data(), reply)
            }
            Command::YkExtension(yk_command) => {
                self.yubico_piv_extension(command.data(), yk_command, reply)
            }
            _ => todo!(),
        }
    }

    // maybe reserve this for the case VerifyLogin::PivPin?
    pub fn login(&mut self, login: commands::VerifyLogin) -> Result {
        if let commands::VerifyLogin::PivPin(pin) = login {
            // the actual PIN verification
            let persistent_state = self.state.persistent(&mut self.trussed)?;

            if persistent_state.remaining_pin_retries() == 0 {
                return Err(Status::OperationBlocked);
            }

            if persistent_state.verify_pin(&pin) {
                persistent_state.reset_consecutive_pin_mismatches(&mut self.trussed);
                self.state.runtime.app_security_status.pin_verified = true;
                Ok(())
            } else {
                let remaining =
                    persistent_state.increment_consecutive_pin_mismatches(&mut self.trussed);
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
                    let retries = self
                        .state
                        .persistent(&mut self.trussed)?
                        .remaining_pin_retries();
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
        let persistent_state = self.state.persistent(&mut self.trussed)?;
        if persistent_state.remaining_pin_retries() == 0 {
            return Err(Status::OperationBlocked);
        }

        if !persistent_state.verify_pin(&old_pin) {
            let remaining =
                persistent_state.increment_consecutive_pin_mismatches(&mut self.trussed);
            self.state.runtime.app_security_status.pin_verified = false;
            return Err(Status::RemainingRetries(remaining));
        }

        persistent_state.reset_consecutive_pin_mismatches(&mut self.trussed);
        persistent_state.set_pin(new_pin, &mut self.trussed);
        self.state.runtime.app_security_status.pin_verified = true;
        Ok(())
    }

    pub fn change_puk(&mut self, old_puk: commands::Puk, new_puk: commands::Puk) -> Result {
        let persistent_state = self.state.persistent(&mut self.trussed)?;
        if persistent_state.remaining_puk_retries() == 0 {
            return Err(Status::OperationBlocked);
        }

        if !persistent_state.verify_puk(&old_puk) {
            let remaining =
                persistent_state.increment_consecutive_puk_mismatches(&mut self.trussed);
            self.state.runtime.app_security_status.puk_verified = false;
            return Err(Status::RemainingRetries(remaining));
        }

        persistent_state.reset_consecutive_puk_mismatches(&mut self.trussed);
        persistent_state.set_puk(new_puk, &mut self.trussed);
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
        reply: &mut Data<R>,
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
        let mut input = derp::Reader::new(derp::Input::from(data));

        let Ok((tag,data)) = derp::read_tag_and_get_value(&mut input) else {
            return Err(Status::IncorrectDataParameter);
        };

        // part 2 table 7
        match tag {
            0x80 => self.request_for_witness(auth, data, reply),
            0x81 => self.request_for_challenge(auth, data, reply),
            0x82 => self.request_for_response(auth, data, reply),
            0x85 => self.request_for_exponentiation(auth, data, reply),
            _ => Err(Status::IncorrectDataParameter),
        }
    }

    pub fn request_for_response<const R: usize>(
        &mut self,
        _auth: GeneralAuthenticate,
        _data: derp::Input<'_>,
        _reply: &mut Data<R>,
    ) -> Result {
        todo!()
    }

    pub fn request_for_exponentiation<const R: usize>(
        &mut self,
        _auth: GeneralAuthenticate,
        _data: derp::Input<'_>,
        _reply: &mut Data<R>,
    ) -> Result {
        todo!()
    }

    pub fn request_for_challenge<const R: usize>(
        &mut self,
        _auth: GeneralAuthenticate,
        _data: derp::Input<'_>,
        _reply: &mut Data<R>,
    ) -> Result {
        todo!()
    }

    pub fn request_for_witness<const R: usize>(
        &mut self,
        _auth: GeneralAuthenticate,
        _data: derp::Input<'_>,
        _reply: &mut Data<R>,
    ) -> Result {
        todo!()
    }

    pub fn generate_asymmetric_keypair<const R: usize, const C: usize>(
        &mut self,
        data: &[u8],
        reply: &mut Data<R>,
    ) -> Result {
        if !self.state.runtime.app_security_status.management_verified {
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
        let (mechanism, _pin_policy, _touch_policy) = input
            .read_all(derp::Error::Read, |input| {
                derp::nested(input, 0xac, |input| {
                    let mechanism = derp::expect_tag_and_get_value(input, 0x80)?;
                    // let parameter = derp::expect_tag_and_get_value(input, 0x81)?;
                    let pin_policy = derp::expect_tag_and_get_value(input, 0xaa)?;
                    let touch_policy = derp::expect_tag_and_get_value(input, 0xab)?;
                    // Ok((mechanism.as_slice_less_safe(), parameter.as_slice_less_safe()))
                    Ok((
                        mechanism.as_slice_less_safe(),
                        pin_policy.as_slice_less_safe(),
                        touch_policy.as_slice_less_safe(),
                    ))
                })
            })
            .map_err(|_e| {
                info!("error parsing GenerateAsymmetricKeypair: {:?}", &_e);
                Status::IncorrectDataParameter
            })?;

        // if mechanism != &[0x11] {
        // HA! patch in Ed255
        if mechanism != [0x22] {
            return Err(Status::InstructionNotSupportedOrInvalid);
        }

        // ble policy

        if let Some(key) = self
            .state
            .persistent(&mut self.trussed)?
            .keys
            .authentication_key
        {
            syscall!(self.trussed.delete(key));
        }

        // let key = syscall!(self.trussed.generate_p256_private_key(
        // let key = syscall!(self.trussed.generate_p256_private_key(
        let key = syscall!(self
            .trussed
            .generate_ed255_private_key(trussed::types::Location::Internal,))
        .key;

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
        let persistent_state = self.state.persistent(&mut self.trussed)?;
        persistent_state.keys.authentication_key = Some(key);
        persistent_state.save(&mut self.trussed);

        // let public_key = syscall!(self.trussed.derive_p256_public_key(
        let public_key = syscall!(self
            .trussed
            .derive_ed255_public_key(key, trussed::types::Location::Volatile,))
        .key;

        let serialized_public_key = syscall!(self.trussed.serialize_key(
            // trussed::types::Mechanism::P256,
            trussed::types::Mechanism::Ed255,
            public_key,
            trussed::types::KeySerialization::Raw,
        ))
        .serialized_key;

        // info!("supposed SEC1 pubkey, len {}: {:X?}", serialized_public_key.len(), &serialized_public_key);

        // P256 SEC1 has 65 bytes, Ed255 pubkeys have 32
        // let l2 = 65;
        let l2 = 32;
        let l1 = l2 + 2;

        reply
            .extend_from_slice(&[0x7f, 0x49, l1, 0x86, l2])
            .unwrap();
        reply.extend_from_slice(&serialized_public_key).unwrap();

        Ok(())
    }

    pub fn put_data(&mut self, data: &[u8]) -> Result {
        info!("PutData");

        // if !self.state.runtime.app_security_status.management_verified {
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

    fn get_data<const R: usize>(
        &mut self,
        container: container::Container,
        reply: &mut Data<R>,
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
                    .encode_to_heapless_vec(reply)
                    .unwrap();
                info!("returning CCC {:02X?}", reply);
            }

            // '5FC1 02' (351B)
            Container::CardHolderUniqueIdentifier => {
                let guid = self.state.persistent(&mut self.trussed)?.guid();
                piv_types::CardHolderUniqueIdentifier::default()
                    .with_guid(guid)
                    .encode_to_heapless_vec(reply)
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
        reply: &mut Data<R>,
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
                persistent_state.reset_management_key(&mut self.trussed);
                self.state.runtime.app_security_status.pin_verified = false;
                self.state.runtime.app_security_status.puk_verified = false;
                self.state.runtime.app_security_status.management_verified = false;

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

            YubicoPivExtension::SetManagementKey(_touch_policy) => {
                // cmd := apdu{
                //     instruction: insSetMGMKey,
                //     param1:      0xff,
                //     param2:      0xff,
                //     data: append([]byte{
                //         alg3DES, keyCardManagement, 24,
                //     }, key[:]...),
                // }
                // TODO check we are authenticated with old management key

                // example:  03 9B 18
                //      B0 20 7A 20 DC 39 0B 1B A5 56 CC EB 8D CE 7A 8A C8 23 E6 F5 0D 89 17 AA
                if data.len() != 3 + 24 {
                    return Err(Status::IncorrectDataParameter);
                }
                let (prefix, new_management_key) = data.split_at(3);
                if prefix != [0x03, 0x9b, 0x18] {
                    return Err(Status::IncorrectDataParameter);
                }
                let new_management_key: [u8; 24] = new_management_key.try_into().unwrap();
                self.state
                    .persistent(&mut self.trussed)?
                    .set_management_key(&new_management_key, &mut self.trussed);
            }

            _ => return Err(Status::FunctionNotSupported),
        }
        Ok(())
    }
}
