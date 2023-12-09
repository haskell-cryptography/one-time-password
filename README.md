<h1 align="center">
  one-time-password
</h1>

<p align="center">
<a href="https://github.com/haskell-cryptography/one-time-password/actions">
  <img src="https://img.shields.io/github/actions/workflow/status/haskell-cryptography/one-time-password/one-time-password.yml?style=flat-square" alt="CI badge" />
</a>
<a href="https://hackage.haskell.org/package/one-time-password">
  <img src="https://img.shields.io/hackage/v/one-time-password?style=flat-square" alt="Hackage" />
</a>
</p>

A One-Time Password (OTP) is a dynamic password used once in conjunction with an account's usual password, a for the purpose of two-factor authentication. 

It can be based on a counter (HOTP) or a timestamp (TOTP). This module provides both methods.

Mobile authenticator applications will typically require a TOTP secret. They are most commonly provided as QR codes to scan.
This library can generate a URI that can be used by a QR Code generator.
