{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

module OTP.Commons
  ( -- * Auxiliary
    OTP (..)
  , Digits
  , Algorithm (..)
  , mkDigits
  , digitsToWord32
  , totpCounter
  , counterRange
  , totpCounterRange
  , asSeconds
  ) where

import Chronos (Time (..), Timespan (..), epoch, second)
import Data.Int (Int64)
import Data.Text.Display
import Data.Text.Lazy.Builder (Builder)
import Data.Text.Lazy.Builder qualified as Text
import Data.Word
import Text.Printf (printf)
import Torsor qualified

-- |
--
-- @since 3.0.0.0
data Algorithm
  = HMAC_SHA1
  | HMAC_SHA256
  | HMAC_SHA512
  deriving stock
    ( Eq
      -- ^ @since 3.0.0.0
    , Ord
      -- ^ @since 3.0.0.0
    , Show
      -- ^ @since 3.0.0.0
    )

-- |
--
-- @since 3.0.0.0
instance Display Algorithm where
  displayBuilder HMAC_SHA1 = "SHA1"
  displayBuilder HMAC_SHA256 = "SHA256"
  displayBuilder HMAC_SHA512 = "SHA512"

-- |
--
-- @since 3.0.0.0
data OTP = OTP
  { digits :: Word32
  , code :: Word32
  }
  deriving stock
    ( Eq
      -- ^ @since 3.0.0.0
    , Ord
      -- ^ @since 3.0.0.0
    , Show
      -- ^ @since 3.0.0.0
    )

-- |
--
-- @since 3.0.0.0
instance Display OTP where
  displayBuilder OTP{digits, code} = displayWord32AsOTP digits code

displayWord32AsOTP :: Word32 -> Word32 -> Builder
displayWord32AsOTP digits code = Text.fromString $ printf ("%0" <> show digits <> "u") code

-- |
--
-- @since 3.0.0.0
newtype Digits = Digits Word32
  deriving newtype (Eq, Show, Ord)
  deriving
    (Display)
    via ShowInstance Digits

digitsToWord32 :: Digits -> Word32
digitsToWord32 (Digits digits) = digits

-- |
--
-- RFC 4226 §5.3 says "Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code".
--
-- This function validates that the number of desired digits is equal or greater than 6.
mkDigits
  :: Word32
  -> Maybe Digits
mkDigits userDigits
  | userDigits >= 6 = Just (Digits userDigits)
  | otherwise = Nothing

-- | Calculate HOTP counter using time. Starting time (T0
-- according to RFC6238) is 0 (begining of UNIX epoch)
--
-- @since 3.0.0.0
totpCounter
  :: Time
  -- ^ Time of totp
  -> Timespan
  -- ^ Time range in seconds
  -> Word64
  -- ^ Resulting counter
totpCounter time period =
  ts2word (asSeconds (sinceEpoch time)) `quot` ts2word (asSeconds period)
  where
    ts2word :: Int64 -> Word64
    ts2word = fromIntegral

-- Until https://github.com/andrewthad/chronos/pull/83 is merged
-- these two functions will live here
sinceEpoch :: Time -> Timespan
sinceEpoch t = Torsor.difference t epoch

asSeconds :: Timespan -> Int64
asSeconds (Timespan t) = case second of
  Timespan s -> t `div` s

-- | Make a sequence of acceptable counters, protected from
-- arithmetic overflow. Maximum range is limited to 1000 due to huge
-- counter ranges being insecure.
--
-- >>> counterRange (0, 0) 9000
-- [9000]
--
-- >>> counterRange (1, 0) 9000
-- [8999,9000]
--
-- >>> length $ counterRange (5000, 0) 9000
-- 501
--
-- >>> length $ counterRange (5000, 5000) 9000
-- 1000
--
-- >>> counterRange (2, 2) maxBound
-- [18446744073709551613,18446744073709551614,18446744073709551615]
--
-- >>> counterRange (2, 2) minBound
-- [0,1,2]
--
-- >>> counterRange (2, 2) (maxBound `div` 2)
-- [9223372036854775805,9223372036854775806,9223372036854775807,9223372036854775808,9223372036854775809]
--
-- >>> counterRange (5, 5) 9000
-- [8995,8996,8997,8998,8999,9000,9001,9002,9003,9004,9005]
--
-- RFC recommends avoiding excessively large values for counter ranges.
--
-- @since 3.0.0.0
counterRange
  :: (Word64, Word64)
  -- ^ Number of counters before and after ideal
  -> Word64
  -- ^ Ideal counter value
  -> [Word64]
counterRange (tolow', tohigh') ideal =
  let tolow = min 500 tolow'
      tohigh = min 499 tohigh'
      l = trim 0 ideal (ideal - tolow)
      h = trim ideal maxBound (ideal + tohigh)
   in [l .. h]
  where
    trim l h = max l . min h

-- | Make a sequence of acceptable periods.
--
-- @since 3.0.0.0
totpCounterRange
  :: (Word64, Word64)
  -> Time
  -> Timespan
  -> [Word64]
totpCounterRange range time period =
  counterRange range $ totpCounter time period
