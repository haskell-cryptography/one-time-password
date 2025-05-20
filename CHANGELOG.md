# CHANGELOG

## 3.0.1.0 — 20-05-2025
* Support latest versions of `text`, `text-display` and `sel`

## 3.0.0.0 — 13-04-2024

* The library has been transferred to the Haskell Cryptography Group's stewardship;
* Switch to use `sel` for the cryptography provider;
* Support for GHC from 9.4 to 9.8;
* See the `OTP.TOTP` and the test suite for example usage.

## 2.0.0
### Changed
* Change versioning to semver
* Use `cryptonite` instead of deprecated `cryptohash` (broken backwards
  compatibility)

## 1.0.0.1

* Documentation typos fixed

## 1.0.0.0

* Forked from OTP (https://github.com/matshch/OTP)
* Rewrote with `cryptohash`
* Add multiple hash functions support
* Tests improoved: all RFC test verctors passed
