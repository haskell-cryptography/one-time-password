{-# LANGUAGE OverloadedStrings #-}

-- | Time-based One-Time Passwords (TOTP) with the HMAC-SHA-1, HMAC-SHA-256 and HMAC-SHA-512 algorithms.
--
-- They are single-use codes used for <https://en.wikipedia.org/wiki/Multi-factor_authentication 2-Factor Authentication>.
module OTP.TOTP
  ( -- ** Usage
    -- $usage
    OTP

    -- * TOTP

    -- ** HMAC-SHA-1
  , totpSHA1
  , totpSHA1Check

    -- ** HMAC-SHA-256
  , totpSHA256
  , totpSHA256Check

    -- ** HMAC-SHA-512
  , totpSHA512
  , totpSHA512Check

    -- ** Utilities
  , totpToURI
  ) where

import Chronos (Time (..), Timespan (..))
import Data.Text (Text)
import Data.Text qualified as Text
import Data.Text.Display (display)
import Data.Word (Word64)
import Network.URI (escapeURIString, isUnescapedInURI)
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512

import OTP.Commons
  ( Algorithm
  , Digits
  , OTP
  , asSeconds
  , totpCounter
  , totpCounterRange
  )
import OTP.HOTP (hotpSHA1, hotpSHA256, hotpSHA512)
import Debug.Trace (traceShowId)

-- $usage
--
-- > -- Generating a user's TOTP URI
-- > import Chronos (second, now)
-- > import Data.ByteString.Base32 qualified as Base32
-- > import Data.Maybe (fromJust)
-- > import Data.Text.Display
-- > import OTP.Commons
-- > import OTP.TOTP
-- > import Sel.HMAC.SHA256 qualified as SHA256
-- > import Torsor (scale)
-- >
-- > sharedKey <- SHA256.newAuthenticationKey
-- > let period = scale 30 second
-- > let digits = fromJust $ mkDigits 6
-- > let issuer = "Localhost Inc"
-- > let account = "username@localhost.localdomain"
-- >
-- > let uri =
-- >       totpToURI
-- >         (Base32.encodeBase32 $ SHA256.unsafeAuthenticationKeyToBinary key)
-- >         account
-- >         issuer
-- >         digits
-- >         period
-- >         HMAC_SHA1
-- >
-- > -- Validating a user's TOTP digits
-- > let userDigits = …
-- > timestamp <- now
-- > SHA256.totpSHA256Check sharedKey (0, 1) timestamp period digits (display code)

-- | Compute a Time-Based One-Time Password using secret key and time.
--
-- @since 3.0.0.0
totpSHA1
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits
  -- ^ Number of digits in a password
  -> OTP
  -- ^ TOTP
totpSHA1 secret time period = hotpSHA1 secret (totpCounter time period)

-- | Compute a Time-Based One-Time Password using secret key and time.
--
-- @since 3.0.0.0
totpSHA256
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits
  -- ^ Number of digits in a password
  -> OTP
  -- ^ TOTP
totpSHA256 secret time period = hotpSHA256 secret (totpCounter time period)

-- | Compute a Time-Based One-Time Password using secret key and time.
--
-- @since 3.0.0.0
totpSHA512
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits
  -- ^ Number of digits in a password
  -> OTP
  -- ^ TOTP
totpSHA512 secret time period = hotpSHA512 secret (totpCounter time period)

-- | Check presented password against time periods.
--
-- @since 3.0.0.0
totpSHA1Check
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits
  -- ^ Numer of digits in a password
  -> Text
  -- ^ Password given by user
  -> Bool
  -- ^ True if password is valid
totpSHA1Check secret range time period digits pass =
  let counters = totpCounterRange range time period
      passwords = fmap (\c -> display $ hotpSHA1 secret c digits) counters
   in elem pass (traceShowId passwords)

-- | Check presented password against time periods.
--
-- @since 3.0.0.0
totpSHA256Check
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits
  -- ^ Numer of digits in a password
  -> Text
  -- ^ Password given by user
  -> Bool
  -- ^ True if password is valid
totpSHA256Check secret range time period digits pass =
  let counters = totpCounterRange range time period
      passwords = fmap (\c -> display $ hotpSHA256 secret c digits) counters
   in elem pass passwords

-- | Check presented password against time periods.
--
-- @since 3.0.0.0
totpSHA512Check
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits
  -- ^ Numer of digits in a password
  -> Text
  -- ^ Password given by user
  -> Bool
  -- ^ True if password is valid
totpSHA512Check secret range time period digits pass =
  let counters = totpCounterRange range time period
      passwords = fmap (\c -> display $ hotpSHA512 secret c digits) counters
   in elem pass passwords

-- | Create a URI suitable for authenticators.
--
-- The result of this function is best given to a QR Code generator for end-users to scan.
--
-- @since 3.0.0.0
totpToURI
  :: Text
  -- ^ Shared secret key. Must be encoded in base32.
  -> Text
  -- ^ Name of the account (usually an email address)
  -> Text
  -- ^ Issuer
  -> Digits
  -- ^ Amount of digits expected from the end-user
  -> Timespan
  -- ^ Amount of time before the generated code expires
  -> Algorithm
  -- ^ Algorithm required
  -> Text
totpToURI secret account issuer digits period algorithm =
  Text.pack $
    escapeURIString isUnescapedInURI $
      Text.unpack $
        "otpauth://totp/"
          <> issuer
          <> ":"
          <> account
          <> "?secret="
          <> secret
          <> "&issuer="
          <> issuer
          <> "&digits="
          <> display digits
          <> "&algorithm="
          <> display algorithm
          <> "&period="
          <> display (asSeconds period)
