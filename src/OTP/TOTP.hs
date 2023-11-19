module OTP.TOTP
  ( OTP

    -- * TOTP
  , totpSHA1
  , totpSHA1Check
  , totpSHA256
  , totpSHA256Check
  , totpSHA512
  , totpSHA512Check
  ) where

import Chronos (Time (..), Timespan (..))
import Data.Text (Text)
import Data.Text.Display
import Data.Word
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512

import OTP.Commons
import OTP.HOTP

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
   in elem pass passwords

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
