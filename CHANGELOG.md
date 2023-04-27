<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## Unreleased

## [v0.1.2][] (2023-04-24)

- Use `RsaPublicParts::deserialize` instead of `trussed::postcard_deserialize` for compatibility with recent Trussed changes.

[v0.1.2]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.1.2

## [v0.1.1][] (2023-04-17)

- Fix dependency on trussed-rsa-alloc to use the git tag in the `[patch.crates-io]` section to avoid duplicate downstream dependencies

[v0.1.1]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.1.1

## [v0.1.0][] (2023-04-13)

This initial release contains support for the basic PIV card functionality.
It supports basic card administration, key generation and authentication.

Supported algorithms are P-256 and RSA 2048.

[v0.1.0]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.1.0