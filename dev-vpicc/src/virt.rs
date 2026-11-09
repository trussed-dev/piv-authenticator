//! Virtual trussed client (mostly for testing)

pub mod dispatch {

    use trussed::{
        backend::{Backend as _, BackendId},
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
        service::ServiceResources,
        types::Context,
    };
    use trussed_auth::AuthExtension;
    use trussed_auth_backend::{AuthBackend, AuthContext, FilesystemLayout, MAX_HW_KEY_LEN};
    use trussed_chunked::ChunkedExtension;
    use trussed_core::{
        Error,
        api::{Reply, Request, reply, request},
        types::{Bytes, Location},
    };
    use trussed_hpke::HpkeExtension;
    use trussed_rsa_alloc::SoftwareRsa;
    use trussed_staging::{StagingBackend, StagingContext};
    use trussed_wrap_key_to_file::WrapKeyToFileExtension;

    /// Backends used by piv
    pub const BACKENDS: &[BackendId<Backend>] = &[
        BackendId::Custom(Backend::Staging),
        BackendId::Custom(Backend::Auth),
        BackendId::Custom(Backend::Rsa),
        BackendId::Core,
    ];

    #[derive(Debug, Clone, Copy)]
    pub enum Backend {
        Auth,
        Rsa,
        Staging,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum Extension {
        Auth,
        Chunked,
        Hpke,
        WrapKeyToFile,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
                Extension::Chunked => 1,
                Extension::Hpke => 2,
                Extension::WrapKeyToFile => 3,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                1 => Ok(Extension::Chunked),
                2 => Ok(Extension::Hpke),
                3 => Ok(Extension::WrapKeyToFile),
                _ => Err(Error::InternalError),
            }
        }
    }

    /// Dispatch implementation with the backends required by piv
    #[derive(Debug)]
    pub struct Dispatch {
        auth: AuthBackend,
        staging: StagingBackend,
    }

    /// Dispatch context for the backends required by piv
    #[derive(Default)]
    pub struct DispatchContext {
        auth: AuthContext,
        staging: StagingContext,
    }

    impl Dispatch {
        pub fn new() -> Self {
            Self {
                auth: AuthBackend::new(Location::Internal, FilesystemLayout::V0),
                staging: StagingBackend::new(),
            }
        }

        pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
            Self {
                auth: AuthBackend::with_hw_key(Location::Internal, hw_key, FilesystemLayout::V0),
                staging: StagingBackend::new(),
            }
        }
    }

    impl Default for Dispatch {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ExtensionDispatch for Dispatch {
        type BackendId = Backend;
        type Context = DispatchContext;
        type ExtensionId = Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Auth => {
                    self.auth
                        .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
                }
                Backend::Staging => self.staging.request(
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                Backend::Rsa => SoftwareRsa.request(&mut ctx.core, &mut (), request, resources),
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match backend {
                Backend::Auth => match extension {
                    Extension::Auth => self.auth.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.auth,
                        request,
                        resources,
                    ),
                    Extension::Chunked|Extension::Hpke|Extension::WrapKeyToFile => Err(Error::RequestNotAvailable),
                }
                Backend::Staging =>match extension {
                    Extension::Chunked => {
                        <StagingBackend as ExtensionImpl<ChunkedExtension>>::extension_request_serialized(
                            &mut self.staging,
                            &mut ctx.core,
                            &mut ctx.backends.staging,
                            request,
                            resources
                        )
                    }
                    Extension::Hpke => {
                        <StagingBackend as ExtensionImpl<HpkeExtension>>::extension_request_serialized(
                            &mut self.staging,
                            &mut ctx.core,
                            &mut ctx.backends.staging,
                            request,
                            resources
                        )
                    }
                    Extension::WrapKeyToFile => {
                        <StagingBackend as ExtensionImpl<WrapKeyToFileExtension>>::extension_request_serialized(
                            &mut self.staging,
                            &mut ctx.core,
                            &mut ctx.backends.staging,
                            request,
                            resources
                        )
                    }
                    Extension::Auth => Err(Error::RequestNotAvailable),
                }
                Backend::Rsa => Err(Error::RequestNotAvailable),
            }
        }
    }

    impl ExtensionId<AuthExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Auth;
    }
    impl ExtensionId<ChunkedExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Chunked;
    }
    impl ExtensionId<HpkeExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Hpke;
    }
    impl ExtensionId<WrapKeyToFileExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::WrapKeyToFile;
    }
}

use littlefs2::path;
use regex::RegexSet;
use std::{sync::LazyLock, vec::Vec};
use trussed::{
    Platform as _,
    store::{DynFilesystem, Store},
    types::{Path, PathBuf},
    virt::{self, Client, Platform, StorageConfig, StoreConfig},
};
use trussed_core::types::Bytes;

fn dump_directory(fs: &dyn DynFilesystem, path: &Path, collector: &mut Vec<PathBuf>) {
    fs.read_dir_and_then(path, &mut |entries| {
        for entry in entries {
            let entry = entry?;
            if entry.file_type().is_file() {
                collector.push(entry.path().into());
            } else if entry.file_name() != path!(".") && entry.file_name() != path!("..") {
                assert!(entry.file_type().is_dir());
                dump_directory(fs, entry.path(), collector);
            }
        }
        Ok(())
    })
    .unwrap();
}

fn dump_fs(fs: &dyn DynFilesystem) -> Vec<PathBuf> {
    let mut collector = Vec::new();
    dump_directory(fs, path!("/"), &mut collector);
    collector
}

static VALID_PATHS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"^/trussed/data/rng-state.bin$",
        r"^/backend-auth/data/salt$",
        r"^/piv/backend-auth/dat/pin.0\d$",
    ])
    .unwrap()
});

fn cleanup(platform: &mut Platform<'_>) {
    let store = platform.store();
    let mut vfs = dump_fs(store.vfs());

    vfs.retain(|p| !VALID_PATHS.is_match(p.as_str()));
    assert_eq!(vfs, Vec::new());
}

/// Client type using a dispatcher with the backends required by piv
pub type VirtClient<'a> = Client<'a, dispatch::Dispatch>;

/// Run a client using a provided store
pub fn with_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    #[allow(clippy::unwrap_used)]
    virt::with_platform(store, |platform| {
        platform
            .cleanup(Box::new(cleanup))
            .run_client_with_backends(
                client_id,
                dispatch::Dispatch::with_hw_key(Bytes::from(b"some bytes")),
                dispatch::BACKENDS,
                f,
            )
    })
}

/// Run the backend with the extensions required by piv
/// using storage backed by a file
pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
    P: Into<std::path::PathBuf>,
{
    let store = StoreConfig {
        internal: StorageConfig::filesystem(internal.into()),
        external: StorageConfig::ram(),
        volatile: StorageConfig::ram(),
    };
    with_client(store, client_id, f)
}

/// Run the backend with the extensions required by piv
/// using a RAM file storage
pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    with_client(StoreConfig::ram(), client_id, f)
}
