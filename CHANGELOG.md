# Changelog

## [v0.5.0][] (2025-02-26)

[v0.5.0]: https://github.com/trussed-dev/piv-authenticator/releases/tag/v0.4.0

- Add support for RSA 3072, 4096 and nist P-384

## [v0.3.9][] (2025-02-11)

[v0.3.9]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.9

- Fix admin authentication

### Security

- Fix [CVE-2025-25201](https://github.com/Nitrokey/piv-authenticator/security/advisories/GHSA-28p6-c99x-fg8j)

## [v0.3.8][] (2024-10-17)

[v0.3.8]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.8

- Encrypt data on external flash ([#57](https://github.com/Nitrokey/piv-authenticator/pull/57))

## [v0.3.7][] (2024-04-21)

- Bump rsa backend version ([#53][])

[#53]: https://github.com/Nitrokey/piv-authenticator/pull/53

[v0.3.7]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.7

## [v0.3.6][] (2024-04-20)

- RSA key import ([#51][])
- Fix spec compliance issues ([#52][])
- Fix retired key 20 usage causing the device to panic ([#52][])

[#51]: https://github.com/Nitrokey/piv-authenticator/pull/51
[#52]: https://github.com/Nitrokey/piv-authenticator/pull/52

[v0.3.6]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.6

## [v0.3.5][] (2024-04-03)

- Fix default card capabilities value ([#46][])
- Fix storage location for just-initialized PIV ([#47][])
- Update trussed-auth, trussed-staging and make trussed-staging optional ([#48][])
- Allow generating retired keys ([#44][])

[#44]: https://github.com/Nitrokey/piv-authenticator/pull/44
[#46]: https://github.com/Nitrokey/piv-authenticator/pull/46
[#47]: https://github.com/Nitrokey/piv-authenticator/pull/47
[#48]: https://github.com/Nitrokey/piv-authenticator/pull/48

[v0.3.5]: https://github.com/Nitrokey/piv-authenticator/releases/tag/v0.3.5

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
