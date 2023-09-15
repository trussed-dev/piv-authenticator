PIV-Authenticator
=================

`piv-authenticator` is a Rust implementation of the [Personal Identity Verification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf) smartcard.

Supported features
------------------

Nearly all functionality specified by the standard are implemented.

Non-standard management operations are partially implemented. Basic functionality such as factory reset and configuration of the management key is implemented.

See the [tracking issue for command support](https://github.com/Nitrokey/piv-authenticator/issues/1) for more information.

License
-------

This project is licensed under [Apache-2.0][Apache-2.0] OR [MIT][MIT].
Configuration files and examples are licensed under the [CC0 1.0 license][CC0-1.0]. 
You can find a copy of the license texts in the [`LICENSES`](./LICENSES) directory.

[CC0-1.0]: https://creativecommons.org/publicdomain/zero/1.0/
[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0.html
[MIT]: https://en.wikipedia.org/wiki/MIT_License

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in `piv-authenticator` by you, shall be licensed as [Apache-2.0][Apache-2.0] OR [MIT][MIT], without any additional terms or conditions.

Funding
-------

[<img src="https://nlnet.nl/logo/banner.svg" width="200" alt="Logo NLnet: abstract logo of four people seen from above" hspace="20">](https://nlnet.nl/)
[<img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" width="200" alt="Logo NGI Assure: letterlogo shaped like a tag" hspace="20">](https://nlnet.nl/assure/)

This project received funding from the [NGI Assure](https://nlnet.nl/assure/) Fund, a fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's [Next Generation Internet programme](https://ngi.eu/), under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073.
