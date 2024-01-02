# Changelog

## [v0.3.4][] (2024-01-02)

- Fix error when changing the PUK ([#40][])

[#40]: https://github.com/Nitrokey/piv-authenticator/pull/40

[v0.3.4]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.4

## [v0.3.3][] (2023-12-08)

- Reject NFC requests ([#39][])
- Put RSA feature behind a feature flag

[#39]: https://github.com/Nitrokey/piv-authenticator/pull/39

[v0.3.3]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.3

## [v0.3.2][] (2023-06-13)

- Fix P-256 signature ([#33][])

[#33]: https://github.com/Nitrokey/piv-authenticator/pull/33

[v0.3.2]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.2

## [v0.3.1][] (2023-06-02)

- Add setter to the options builder for the UUID ([#32][])

[#32]: https://github.com/Nitrokey/piv-authenticator/pull/32
[v0.3.1]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.1

## [v0.3.0][] (2023-05-31)

- Fix reset not checking that the key is locked ([#29][])
- Make GUID configurable ([#30][])

[#30]: https://github.com/Nitrokey/piv-authenticator/pull/30
[#29]: https://github.com/Nitrokey/piv-authenticator/pull/29

[v0.3.0]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.0

## [v0.2.0][] (2023-04-27)

- Use upstream trussed and trussed-staging ([#24][])

[#24]: https://github.com/Nitrokey/piv-authenticator/pull/24

[v0.2.0]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.2.0

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
