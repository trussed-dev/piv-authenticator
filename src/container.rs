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

pub struct Tag<'a>(&'a [u8]);
impl<'a> Tag<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self(slice)
    }
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

enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AttestKeyReference: KeyReference {
        PivAuthentication,
    }
}

enum_subset! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum GenerateAsymmetricKeyReference: KeyReference {
        SecureMessaging,
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

/// The 36 data objects defined by PIV (SP 800-37-4, Part 1).
///
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Container {
    CardCapabilityContainer,
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
    RetiredX509Certificate(RetiredIndex),

    CardholderIrisImages,
    BiometricInformationTemplatesGroupTemplate,
    SecureMessagingCertificateSigner,
    PairingCodeReferenceDataContainer,
}

pub struct ContainerId(u16);

impl From<Container> for ContainerId {
    fn from(container: Container) -> Self {
        use Container::*;
        Self(match container {
            CardCapabilityContainer => 0xDB00,
            CardHolderUniqueIdentifier => 0x3000,
            X509CertificateFor9A => 0x0101,
            CardholderFingerprints => 0x6010,
            SecurityObject => 0x9000,
            CardholderFacialImage => 0x6030,
            X509CertificateFor9E => 0x0500,
            X509CertificateFor9C => 0x0100,
            X509CertificateFor9D => 0x0102,
            PrintedInformation => 0x3001,
            DiscoveryObject => 0x6050,
            KeyHistoryObject => 0x6060,
            RetiredX509Certificate(RetiredIndex(i)) => 0x1000u16 + i as u16,
            CardholderIrisImages => 0x1015,
            BiometricInformationTemplatesGroupTemplate => 0x1016,
            SecureMessagingCertificateSigner => 0x1017,
            PairingCodeReferenceDataContainer => 0x1018,
        })
    }
}

// these are just the "contact" rules, need to model "contactless" also
pub enum ReadAccessRule {
    Always,
    Pin,
    PinOrOcc,
}

// impl Container {
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

//     const fn contact_access_rule(self) -> {
//         use Container::*;
//         use ReadAccessRule::*;
//         match self {
//             CardholderFingerprints => Pin,
//             CardholderFacialImage => Pin,
//             PrintedInformation => PinOrOcc,
//             CardholderIrisImages => Pin,
//             PairingCodeReferenceDataContainer => PinOrOcc,
//             _ => Always,
//         }
//     }
// }

impl TryFrom<Tag<'_>> for Container {
    type Error = ();
    fn try_from(tag: Tag<'_>) -> Result<Self, ()> {
        use Container::*;
        Ok(match tag.0 {
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

            hex!("5FC10D") => RetiredX509Certificate(RetiredIndex(1)),
            hex!("5FC10E") => RetiredX509Certificate(RetiredIndex(2)),
            hex!("5FC10F") => RetiredX509Certificate(RetiredIndex(3)),
            hex!("5FC110") => RetiredX509Certificate(RetiredIndex(4)),
            hex!("5FC111") => RetiredX509Certificate(RetiredIndex(5)),
            hex!("5FC112") => RetiredX509Certificate(RetiredIndex(6)),
            hex!("5FC113") => RetiredX509Certificate(RetiredIndex(7)),
            hex!("5FC114") => RetiredX509Certificate(RetiredIndex(8)),
            hex!("5FC115") => RetiredX509Certificate(RetiredIndex(9)),
            hex!("5FC116") => RetiredX509Certificate(RetiredIndex(10)),
            hex!("5FC117") => RetiredX509Certificate(RetiredIndex(11)),
            hex!("5FC118") => RetiredX509Certificate(RetiredIndex(12)),
            hex!("5FC119") => RetiredX509Certificate(RetiredIndex(13)),
            hex!("5FC11A") => RetiredX509Certificate(RetiredIndex(14)),
            hex!("5FC11B") => RetiredX509Certificate(RetiredIndex(15)),
            hex!("5FC11C") => RetiredX509Certificate(RetiredIndex(16)),
            hex!("5FC11D") => RetiredX509Certificate(RetiredIndex(17)),
            hex!("5FC11E") => RetiredX509Certificate(RetiredIndex(18)),
            hex!("5FC11F") => RetiredX509Certificate(RetiredIndex(19)),
            hex!("5FC120") => RetiredX509Certificate(RetiredIndex(20)),

            hex!("5FC121") => CardholderIrisImages,
            hex!("7F61") => BiometricInformationTemplatesGroupTemplate,
            hex!("5FC122") => SecureMessagingCertificateSigner,
            hex!("5FC123") => PairingCodeReferenceDataContainer,
            _ => return Err(()),
        })
    }
}
