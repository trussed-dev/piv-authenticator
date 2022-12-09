// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use core::convert::TryFrom;

use hex_literal::hex;

macro_rules! enum_subset {
    (

        $(#[$outer:meta])*
        $vis:vis enum $name:ident: $sup:ident {
            $($var:ident),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr(u8)]
        $vis enum $name {
            $(
                $var,
            )*
        }

        impl TryFrom<$sup> for $name
        {
            type Error = ::iso7816::Status;
            fn try_from(val: $sup) -> ::core::result::Result<Self, Self::Error> {
                match val {
                    $(
                        $sup::$var => Ok($name::$var),
                    )*
                    _ => Err(::iso7816::Status::KeyReferenceNotFound)
                }
            }
        }

        impl From<$name> for $sup
        {
            fn from(v: $name) -> $sup {
                match v {
                    $(
                        $name::$var => $sup::$var,
                    )*
                }
            }
        }

        impl PartialEq<$sup> for $name {
            fn eq(&self, other: &$sup) -> bool {
                match (self,other) {
                    $(
                        | ($name::$var, $sup::$var)
                    )* => true,
                    _ => false
                }
            }
        }

        impl TryFrom<u8> for $name {
            type Error = ::iso7816::Status;
            fn try_from(tag: u8) -> ::core::result::Result<Self, Self::Error> {
                let v: $sup = tag.try_into()?;
                match v {
                    $(
                        $sup::$var => Ok($name::$var),
                    )*
                    _ => Err(::iso7816::Status::KeyReferenceNotFound)
                }
            }
        }
    }
}

pub(crate) use enum_subset;

/// Security condition for the use of a given key.
pub enum SecurityCondition {
    Pin,
    Always,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredIndex(u8);

crate::enum_u8! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum KeyReference {
        GlobalPin = 0x00,
        SecureMessaging = 0x04,
        ApplicationPin = 0x80,
        PinUnblockingKey = 0x81,
        PrimaryFinger = 0x96,
        SecondaryFinger = 0x97,
        PairingCode = 0x98,

        PivAuthentication = 0x9A,
        PivCardApplicationAdministration = 0x9B,
        DigitalSignature = 0x9C,
        KeyManagement = 0x9D,
        CardAuthentication = 0x9E,

        Retired01 = 0x82,
        Retired02 = 0x83,
        Retired03 = 0x84,
        Retired04 = 0x85,
        Retired05 = 0x86,
        Retired06 = 0x87,
        Retired07 = 0x88,
        Retired08 = 0x89,
        Retired09 = 0x8A,
        Retired10 = 0x8B,
        Retired11 = 0x8C,
        Retired12 = 0x8D,
        Retired13 = 0x8E,
        Retired14 = 0x8F,
        Retired15 = 0x90,
        Retired16 = 0x91,
        Retired17 = 0x92,
        Retired18 = 0x93,
        Retired19 = 0x94,
        Retired20 = 0x95,
    }
}

impl KeyReference {
    pub fn use_security_condition(self) -> SecurityCondition {
        match self {
            Self::SecureMessaging
            | Self::PivCardApplicationAdministration
            | Self::KeyManagement => SecurityCondition::Always,
            _ => SecurityCondition::Pin,
        }
    }
}

macro_rules! impl_use_security_condition {
    ($($name:ident),*) => {
        $(
            impl $name {
                pub fn use_security_condition(self) -> SecurityCondition {
                    let tmp: KeyReference = self.into();
                    tmp.use_security_condition()
                }
            }
        )*
    };
}

enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AttestKeyReference: KeyReference {
        PivAuthentication,
    }
}

enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AsymmetricKeyReference: KeyReference {
        // SecureMessaging,
        PivAuthentication,
        DigitalSignature,
        KeyManagement,
        CardAuthentication,
        Retired01,
        Retired02,
        Retired03,
        Retired04,
        Retired05,
        Retired06,
        Retired07,
        Retired08,
        Retired09,
        Retired10,
        Retired11,
        Retired12,
        Retired13,
        Retired14,
        Retired15,
        Retired16,
        Retired17,
        Retired18,
        Retired19,
        Retired20,

    }
}

enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum GenerateKeyReference: AsymmetricKeyReference {
        // SecureMessaging,
        PivAuthentication,
        DigitalSignature,
        KeyManagement,
        CardAuthentication,
    }
}

enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ChangeReferenceKeyReference: KeyReference {
        GlobalPin,
        ApplicationPin,
        PinUnblockingKey,
    }
}

enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum VerifyKeyReference: KeyReference {
        GlobalPin,
        ApplicationPin,
        PrimaryFinger,
        SecondaryFinger,
        PairingCode,

    }
}

enum_subset! {

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AuthenticateKeyReference: KeyReference {
        SecureMessaging,
        PivAuthentication,
        PivCardApplicationAdministration,
        DigitalSignature,
        KeyManagement,
        CardAuthentication,
        Retired01,
        Retired02,
        Retired03,
        Retired04,
        Retired05,
        Retired06,
        Retired07,
        Retired08,
        Retired09,
        Retired10,
        Retired11,
        Retired12,
        Retired13,
        Retired14,
        Retired15,
        Retired16,
        Retired17,
        Retired18,
        Retired19,
        Retired20,
    }
}

impl_use_security_condition!(
    AttestKeyReference,
    AsymmetricKeyReference,
    ChangeReferenceKeyReference,
    VerifyKeyReference,
    AuthenticateKeyReference
);

macro_rules! impl_try_from {
    ($(($left:ident, $right:ident)),*) => {
        $(
            impl TryFrom<$left> for $right {
                type Error = ::iso7816::Status;
                fn try_from(val: $left) -> Result<Self,Self::Error> {
                    let tmp = KeyReference::from(val);
                    tmp.try_into()
                }

            }
        )*
    };
}

impl_try_from!((AuthenticateKeyReference, AsymmetricKeyReference));

/// The 36 data objects defined by PIV (SP 800-37-4, Part 1).
///
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Container {
    // static
    CardCapabilityContainer,
    // generated at card creation
    CardHolderUniqueIdentifier,
    X509CertificateFor9A,
    CardholderFingerprints,
    SecurityObject,
    CardholderFacialImage,
    X509CertificateFor9E,
    X509CertificateFor9C,
    X509CertificateFor9D,
    PrintedInformation,
    DiscoveryObject,
    KeyHistoryObject,
    RetiredCert01,
    RetiredCert02,
    RetiredCert03,
    RetiredCert04,
    RetiredCert05,
    RetiredCert06,
    RetiredCert07,
    RetiredCert08,
    RetiredCert09,
    RetiredCert10,
    RetiredCert11,
    RetiredCert12,
    RetiredCert13,
    RetiredCert14,
    RetiredCert15,
    RetiredCert16,
    RetiredCert17,
    RetiredCert18,
    RetiredCert19,
    RetiredCert20,
    CardholderIrisImages,
    BiometricInformationTemplatesGroupTemplate,
    SecureMessagingCertificateSigner,
    PairingCodeReferenceDataContainer,
}

// these are just the "contact" rules, need to model "contactless" also
pub enum ReadAccessRule {
    Always,
    Pin,
    PinOrOcc,
}

impl Container {
    //     const fn minimum_capacity(self) -> usize {
    //         use Container::*;
    //         match self {
    //             CardCapabilityContainer => 287,
    //             CardHolderUniqueIdentifier => 2916,
    //             CardholderFingerprints => 4006,
    //             SecurityObject => 1336,
    //             CardholderFacialImage => 12710,
    //             PrintedInformation => 245,
    //             DiscoveryObject => 19,
    //             KeyHistoryObject => 128,
    //             CardholderIrisImages => 7106,
    //             BiometricInformationTemplate => 65,
    //             SecureMessagingCertificateSigner => 2471,
    //             PairingCodeReferenceDataContainer => 12,
    //             // the others are X509 certificates
    //             _ => 1905,
    //         }
    //     }

    pub const fn contact_access_rule(self) -> ReadAccessRule {
        use Container::*;
        use ReadAccessRule::*;
        match self {
            CardholderFingerprints => Pin,
            CardholderFacialImage => Pin,
            PrintedInformation => PinOrOcc,
            CardholderIrisImages => Pin,
            PairingCodeReferenceDataContainer => PinOrOcc,
            _ => Always,
        }
    }
}

impl TryFrom<&[u8]> for Container {
    type Error = ();
    fn try_from(tag: &[u8]) -> Result<Self, ()> {
        use Container::*;
        Ok(match tag {
            hex!("5FC107") => CardCapabilityContainer,
            hex!("5FC102") => CardHolderUniqueIdentifier,
            hex!("5FC105") => X509CertificateFor9A,
            hex!("5FC103") => CardholderFingerprints,
            hex!("5FC106") => SecurityObject,
            hex!("5FC108") => CardholderFacialImage,
            hex!("5FC101") => X509CertificateFor9E,
            hex!("5FC10A") => X509CertificateFor9C,
            hex!("5FC10B") => X509CertificateFor9D,
            hex!("5FC109") => PrintedInformation,
            hex!("7E") => DiscoveryObject,

            hex!("5FC10D") => RetiredCert01,
            hex!("5FC10E") => RetiredCert02,
            hex!("5FC10F") => RetiredCert03,
            hex!("5FC110") => RetiredCert04,
            hex!("5FC111") => RetiredCert05,
            hex!("5FC112") => RetiredCert06,
            hex!("5FC113") => RetiredCert07,
            hex!("5FC114") => RetiredCert08,
            hex!("5FC115") => RetiredCert09,
            hex!("5FC116") => RetiredCert10,
            hex!("5FC117") => RetiredCert11,
            hex!("5FC118") => RetiredCert12,
            hex!("5FC119") => RetiredCert13,
            hex!("5FC11A") => RetiredCert14,
            hex!("5FC11B") => RetiredCert15,
            hex!("5FC11C") => RetiredCert16,
            hex!("5FC11D") => RetiredCert17,
            hex!("5FC11E") => RetiredCert18,
            hex!("5FC11F") => RetiredCert19,
            hex!("5FC120") => RetiredCert20,

            hex!("5FC121") => CardholderIrisImages,
            hex!("7F61") => BiometricInformationTemplatesGroupTemplate,
            hex!("5FC122") => SecureMessagingCertificateSigner,
            hex!("5FC123") => PairingCodeReferenceDataContainer,
            _ => return Err(()),
        })
    }
}
