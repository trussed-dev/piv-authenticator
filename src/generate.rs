use iso7816::Status;
use trussed_core::{
    syscall,
    types::{KeyId, KeySerialization},
};

use crate::{reply::Reply, AsymmetricAlgorithms};

pub fn serialize_public_key(
    public_key: KeyId,
    algorithm: AsymmetricAlgorithms,
    client: &mut impl crate::Client,
    mut reply: Reply<'_>,
) -> Result<(), Status> {
    match algorithm {
        AsymmetricAlgorithms::P256 => {
            let serialized_key = syscall!(client.serialize_key(
                algorithm.key_mechanism(),
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
            let serialized_key = syscall!(client.serialize_key(
                algorithm.key_mechanism(),
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
            use trussed_rsa_types::RsaPublicParts;
            reply.expand(&[0x7F, 0x49])?;
            let offset = reply.len();
            let tmp = syscall!(client.serialize_key(
                algorithm.key_mechanism(),
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
    }
    Ok(())
}
