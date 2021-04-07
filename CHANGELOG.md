# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## 2.0.0 (2021-04-07)


### ⚠ BREAKING CHANGES

* **deps:** Changes to actor interface
* Use latest Dts bump.

*Tidies up some logging
* new Sequence data-type doesn't allow Policy mutations.
* **deps:** actor.rs, rename fn replicas to replicas_public_key, change fn synch return type
* rename money to token

### Features

* **error:** Disambiguate some errors ([bca7817](https://github.com/oetyng/sn_transfers/commit/bca781735bbc64605947f49fd5fead3aa90fa040))
* sn_dts dep update. ([aeb6159](https://github.com/oetyng/sn_transfers/commit/aeb6159a3de02de24d992c619914e074d78ff6d4))
* **actor:** expose history api ([3900c9b](https://github.com/oetyng/sn_transfers/commit/3900c9b2c93f0b45c0b1faf561ad738a0379c7e4))
* **error:** Disambiguate some errors ([705e0be](https://github.com/oetyng/sn_transfers/commit/705e0be5e0bba4cdd08da95d9cdf5f3c175b9242))
* **error:** rename NothingToSync to InvalidActorHistory ([2d150e7](https://github.com/oetyng/sn_transfers/commit/2d150e777f791c2d9a99d12111831e7f2720ca1e))
* use thiserror and create transfers error lib ([dfa7f4f](https://github.com/oetyng/sn_transfers/commit/dfa7f4fd8dcc85ad21a6547aadf9235ae547be0c))
* use udpated DT keypair w/ internal Arc ([aab49eb](https://github.com/oetyng/sn_transfers/commit/aab49eb7ecfd47499cb048f148f87f00cfff796a))
* **audit:** add scheduled security audit scan ([7bbb5c4](https://github.com/oetyng/sn_transfers/commit/7bbb5c43fafd9666364b2a9e308d7c0c9f6824d8))
* **genesis:** expose genesis generator ([7f48117](https://github.com/oetyng/sn_transfers/commit/7f4811752dfb2a18b27fe082b99045ed8d880a00))
* **genesis:** use replica signing for genesis ([0580cfa](https://github.com/oetyng/sn_transfers/commit/0580cfa8844ee413d794d975c2de6843ad945c51))
* **multi_sig:** impl validation proposal flow ([ad5a734](https://github.com/oetyng/sn_transfers/commit/ad5a73407d28a4532afb7d965a149a0f1b0e0b60))
* **multisig-wallet:** expose public key set api ([44f35ab](https://github.com/oetyng/sn_transfers/commit/44f35abe5f8e90bbcbab73aa11a2b8416e0c1d61))
* use Dt 0.12.0 ([b6137fb](https://github.com/oetyng/sn_transfers/commit/b6137fba3ac465bd4ef2a06bb4a2272c3c3dd32b))
* **no PublicId:** updated for data_type changes for No PublicIds ([e2474c6](https://github.com/oetyng/sn_transfers/commit/e2474c6d01b8c4c9e05245dfa9c9e0052110aac7))


### Bug Fixes

* **clippy:** new warnings in latest rustc ([afb2a22](https://github.com/oetyng/sn_transfers/commit/afb2a2258ca97c1bd6f4868fb3c802df178d4445))
* **errors:** pass in correct value to msg ([cb0ca92](https://github.com/oetyng/sn_transfers/commit/cb0ca920f50bac741c2740734394bc3e65d58f84))
* couple of errors ([d1ad37c](https://github.com/oetyng/sn_transfers/commit/d1ad37ced5d8d9dff51559f0431a4df23113b48c))
* don't start new wallet w/ sync ([a1c19cc](https://github.com/oetyng/sn_transfers/commit/a1c19cca6991709ed2026017b4a7d22c36361ea6))
* handle from_history error in from_info ([9a4a6e9](https://github.com/oetyng/sn_transfers/commit/9a4a6e9ae6e149e8e1d699d0485ae327aa1a16d2))
* incorrect error msg ([c89f40d](https://github.com/oetyng/sn_transfers/commit/c89f40daa0b26f6aebcc0da642e3f70f8a489c08))
* **0:** don't allow sending of no money ([fffbf8c](https://github.com/oetyng/sn_transfers/commit/fffbf8ca19debfcbf36a212e184a273ae4ba1830))
* **actor:** move mutation to apply fn ([b51ab31](https://github.com/oetyng/sn_transfers/commit/b51ab31746af06241107de932f7bab236e004294))
* **all:** remove all unwraps from library and test code ([ee0520a](https://github.com/oetyng/sn_transfers/commit/ee0520a1f8ad018c0e7d743762bb9a35880406dd))
* **genesis:** sign correct item ([0e80684](https://github.com/oetyng/sn_transfers/commit/0e806841e26b14f1a2a2de7faeb56c6bfc0a5060))
* **proposals:** don't add current proposal twice ([4bfe044](https://github.com/oetyng/sn_transfers/commit/4bfe044182200288a45d24e5bba78948f1da846d))
* **signature:** use correct keys for validation ([325ca1c](https://github.com/oetyng/sn_transfers/commit/325ca1c4f94781d657b48a1bcfc0c2297b24073b))
* **signing:** receive unserialized data for sign and verify ([ecd1f8f](https://github.com/oetyng/sn_transfers/commit/ecd1f8ffc0dbcb722782f59aad25ecc3df3e0b50))
* add validation of id exists on propagated ([b1750af](https://github.com/oetyng/sn_transfers/commit/b1750afb595b7fc36e27405334b12a1703257c82))
* align transfer-split and actor model changes ([3a0ed37](https://github.com/oetyng/sn_transfers/commit/3a0ed37c080eadb2a1dc8f205ee3a7817f87a68a))
* ignore sig validation for simulated payouts ([554e89d](https://github.com/oetyng/sn_transfers/commit/554e89d6bf595b6f7ef4054b04354216a226a834))
* use master pubkey as id for multisig wallet ([2efe1f2](https://github.com/oetyng/sn_transfers/commit/2efe1f2f393673cb755d622673f31af096a8c8b0))
* wrap replica counter in option ([e5a624a](https://github.com/oetyng/sn_transfers/commit/e5a624a769afa64caca3019919be08f5f9fc156e))
* **validation:** add case zero ([0efd75e](https://github.com/oetyng/sn_transfers/commit/0efd75e8849d5bb40b54da446a222c564211d11e))
* verify correct signature for credit ([53c6b85](https://github.com/oetyng/sn_transfers/commit/53c6b85158693f8c997d424998a0ec4ba34396b7))


* **deps:** update sn_data_types ([1e80c4b](https://github.com/oetyng/sn_transfers/commit/1e80c4b037b2645fd820724b3d0b065a113069cc))
* upgrading data-types to v0.6.0 ([55c0043](https://github.com/oetyng/sn_transfers/commit/55c00431f53c270bb26f1fdc044b8c32d7285f2f))
* **deps:** update sn_data_types ([acc3f80](https://github.com/oetyng/sn_transfers/commit/acc3f800e7fe40958bba9605e579dcb116352473))
* rename money to token ([e6bbab8](https://github.com/oetyng/sn_transfers/commit/e6bbab8373d74106be714896d3ed6413771ae62f))

## [0.7.0](https://github.com/maidsafe/sn_transfers/compare/v0.6.0...v0.7.0) (2021-03-30)


### ⚠ BREAKING CHANGES

* **deps:** Changes to actor interface

### Features

* **error:** Disambiguate some errors ([bca7817](https://github.com/maidsafe/sn_transfers/commit/bca781735bbc64605947f49fd5fead3aa90fa040))


### Bug Fixes

* **clippy:** new warnings in latest rustc ([afb2a22](https://github.com/maidsafe/sn_transfers/commit/afb2a2258ca97c1bd6f4868fb3c802df178d4445))


* **deps:** update sn_data_types ([1e80c4b](https://github.com/maidsafe/sn_transfers/commit/1e80c4b037b2645fd820724b3d0b065a113069cc))

## [0.6.0](https://github.com/maidsafe/sn_transfers/compare/v0.5.0...v0.6.0) (2021-03-22)


### ⚠ BREAKING CHANGES

* Use latest Dts bump.

*Tidies up some logging

### Features

* sn_dts dep update. ([aeb6159](https://github.com/maidsafe/sn_transfers/commit/aeb6159a3de02de24d992c619914e074d78ff6d4))
* **error:** Disambiguate some errors ([705e0be](https://github.com/maidsafe/sn_transfers/commit/705e0be5e0bba4cdd08da95d9cdf5f3c175b9242))
* **error:** rename NothingToSync to InvalidActorHistory ([2d150e7](https://github.com/maidsafe/sn_transfers/commit/2d150e777f791c2d9a99d12111831e7f2720ca1e))


### Bug Fixes

* couple of errors ([d1ad37c](https://github.com/maidsafe/sn_transfers/commit/d1ad37ced5d8d9dff51559f0431a4df23113b48c))
* handle from_history error in from_info ([9a4a6e9](https://github.com/maidsafe/sn_transfers/commit/9a4a6e9ae6e149e8e1d699d0485ae327aa1a16d2))
* incorrect error msg ([c89f40d](https://github.com/maidsafe/sn_transfers/commit/c89f40daa0b26f6aebcc0da642e3f70f8a489c08))

## [0.5.0](https://github.com/maidsafe/sn_transfers/compare/v0.4.2...v0.5.0) (2021-03-03)


### ⚠ BREAKING CHANGES

* new Sequence data-type doesn't allow Policy mutations.

* upgrading data-types to v0.6.0 ([55c0043](https://github.com/maidsafe/sn_transfers/commit/55c00431f53c270bb26f1fdc044b8c32d7285f2f))

### [0.4.2](https://github.com/maidsafe/sn_transfers/compare/v0.4.1...v0.4.2) (2021-03-03)

### [0.4.1](https://github.com/maidsafe/sn_transfers/compare/v0.4.0...v0.4.1) (2021-02-25)

## [0.4.0](https://github.com/maidsafe/sn_transfers/compare/v0.3.3...v0.4.0) (2021-02-22)


### ⚠ BREAKING CHANGES

* **deps:** actor.rs, rename fn replicas to replicas_public_key, change fn synch return type

### Features

* **actor:** expose history api ([3900c9b](https://github.com/maidsafe/sn_transfers/commit/3900c9b2c93f0b45c0b1faf561ad738a0379c7e4))


* **deps:** update sn_data_types ([acc3f80](https://github.com/maidsafe/sn_transfers/commit/acc3f800e7fe40958bba9605e579dcb116352473))

### [0.3.3](https://github.com/maidsafe/sn_transfers/compare/v0.3.2...v0.3.3) (2021-02-22)

### [0.3.2](https://github.com/maidsafe/sn_transfers/compare/v0.3.1...v0.3.2) (2021-02-10)

### [0.3.1](https://github.com/maidsafe/sn_transfers/compare/v0.3.0...v0.3.1) (2021-02-03)

## [0.3.0](https://github.com/maidsafe/sn_transfers/compare/v0.2.12...v0.3.0) (2021-02-01)


### ⚠ BREAKING CHANGES

* rename money to token

* rename money to token ([e6bbab8](https://github.com/maidsafe/sn_transfers/commit/e6bbab8373d74106be714896d3ed6413771ae62f))

### [0.2.12](https://github.com/maidsafe/sn_transfers/compare/v0.2.11...v0.2.12) (2021-02-01)


### Features

* use udpated DT keypair w/ internal Arc ([aab49eb](https://github.com/maidsafe/sn_transfers/commit/aab49eb7ecfd47499cb048f148f87f00cfff796a))


### Bug Fixes

* **signing:** receive unserialized data for sign and verify ([ecd1f8f](https://github.com/maidsafe/sn_transfers/commit/ecd1f8ffc0dbcb722782f59aad25ecc3df3e0b50))

### [0.2.11](https://github.com/maidsafe/sn_transfers/compare/v0.2.10...v0.2.11) (2021-01-29)


### Features

* **genesis:** use replica signing for genesis ([0580cfa](https://github.com/maidsafe/sn_transfers/commit/0580cfa8844ee413d794d975c2de6843ad945c51))
* **multi_sig:** impl validation proposal flow ([ad5a734](https://github.com/maidsafe/sn_transfers/commit/ad5a73407d28a4532afb7d965a149a0f1b0e0b60))
* **multisig-wallet:** expose public key set api ([44f35ab](https://github.com/maidsafe/sn_transfers/commit/44f35abe5f8e90bbcbab73aa11a2b8416e0c1d61))


### Bug Fixes

* **genesis:** sign correct item ([0e80684](https://github.com/maidsafe/sn_transfers/commit/0e806841e26b14f1a2a2de7faeb56c6bfc0a5060))
* **proposals:** don't add current proposal twice ([4bfe044](https://github.com/maidsafe/sn_transfers/commit/4bfe044182200288a45d24e5bba78948f1da846d))
* **signature:** use correct keys for validation ([325ca1c](https://github.com/maidsafe/sn_transfers/commit/325ca1c4f94781d657b48a1bcfc0c2297b24073b))

### [0.2.10](https://github.com/maidsafe/sn_transfers/compare/v0.2.9...v0.2.10) (2021-01-18)

### [0.2.9](https://github.com/maidsafe/sn_transfers/compare/v0.2.8...v0.2.9) (2021-01-05)

### [0.2.8](https://github.com/maidsafe/sn_transfers/compare/v0.2.7...v0.2.8) (2020-12-30)


### Features

* use Dt 0.12.0 ([b6137fb](https://github.com/maidsafe/sn_transfers/commit/b6137fba3ac465bd4ef2a06bb4a2272c3c3dd32b))

### [0.2.7](https://github.com/maidsafe/sn_transfers/compare/v0.2.6...v0.2.7) (2020-12-30)

### [0.2.6](https://github.com/maidsafe/sn_transfers/compare/v0.2.5...v0.2.6) (2020-12-29)


### Features

* use thiserror and create transfers error lib ([dfa7f4f](https://github.com/maidsafe/sn_transfers/commit/dfa7f4fd8dcc85ad21a6547aadf9235ae547be0c))

### [0.2.5](https://github.com/maidsafe/sn_transfers/compare/v0.2.4...v0.2.5) (2020-12-17)


### Bug Fixes

* align transfer-split and actor model changes ([3a0ed37](https://github.com/maidsafe/sn_transfers/commit/3a0ed37c080eadb2a1dc8f205ee3a7817f87a68a))
* don't start new wallet w/ sync ([a1c19cc](https://github.com/maidsafe/sn_transfers/commit/a1c19cca6991709ed2026017b4a7d22c36361ea6))
* ignore sig validation for simulated payouts ([554e89d](https://github.com/maidsafe/sn_transfers/commit/554e89d6bf595b6f7ef4054b04354216a226a834))
* use master pubkey as id for multisig wallet ([2efe1f2](https://github.com/maidsafe/sn_transfers/commit/2efe1f2f393673cb755d622673f31af096a8c8b0))
* wrap replica counter in option ([e5a624a](https://github.com/maidsafe/sn_transfers/commit/e5a624a769afa64caca3019919be08f5f9fc156e))
* **validation:** add case zero ([0efd75e](https://github.com/maidsafe/sn_transfers/commit/0efd75e8849d5bb40b54da446a222c564211d11e))
* verify correct signature for credit ([53c6b85](https://github.com/maidsafe/sn_transfers/commit/53c6b85158693f8c997d424998a0ec4ba34396b7))

### [0.2.4](https://github.com/maidsafe/sn_transfers/compare/v0.2.3...v0.2.4) (2020-11-24)


### Bug Fixes

* **all:** remove all unwraps from library and test code ([ee0520a](https://github.com/maidsafe/sn_transfers/commit/ee0520a1f8ad018c0e7d743762bb9a35880406dd))

### [0.2.3](https://github.com/maidsafe/sn_transfers/compare/v0.2.2...v0.2.3) (2020-11-23)

### [0.2.2](https://github.com/maidsafe/sn_transfers/compare/v0.2.1...v0.2.2) (2020-10-27)


### Features

* **no PublicId:** updated for data_type changes for No PublicIds ([e2474c6](https://github.com/maidsafe/sn_transfers/commit/e2474c6d01b8c4c9e05245dfa9c9e0052110aac7))

### [0.2.1](https://github.com/maidsafe/sn_transfers/compare/v0.2.0...v0.2.1) (2020-10-20)


### Bug Fixes

* **0:** don't allow sending of no money ([fffbf8c](https://github.com/maidsafe/sn_transfers/commit/fffbf8ca19debfcbf36a212e184a273ae4ba1830))
* **actor:** move mutation to apply fn ([b51ab31](https://github.com/maidsafe/sn_transfers/commit/b51ab31746af06241107de932f7bab236e004294))

### [0.2.0](https://github.com/maidsafe/sn_transfers/compare/v0.1.0...v0.2.0) (2020-09-03)

* Update crate name to sn_transfers.
* Expose genesis generator.
* Add initial infusion of money.
* Check against previous 'next' count when applying RegisteredTransfers.
* Support checking SectionProofChain in safe_vaults.
* Add scheduled security audit scan.
* Update simulated payout funcs to credit/debit correct pk.
* Add GetReplicaKeys.
* Add simulated debitting APIs to replica.
* Refactor and fix simulated-payouts APIs.
* Add simulated-payouts feature and include testing API to Replica.
* Fix received debits logic.
* Accumulate remote credits.
* Add peer logic and sig validations.

### [0.1.0](https://github.com/maidsafe/sn_transfers/compare/v0.1.0...v0.1.0) (2020-05-19)

* Initial implementation.
