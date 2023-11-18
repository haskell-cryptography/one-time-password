{-# LANGUAGE GHC2021 #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- | Implements HMAC-Based One-Time Password Algorithm as defined in RFC 4226 and
--  Time-Based One-Time Password Algorithm as defined in RFC 6238.
--
-- Only HMAC-SHA-256 and HMAC-SHA-512 are provided.
module OTP
  ( -- * HOTP
    hotp256
  , hotp256Check
  , hotp512
  , hotp512Check

    -- * TOTP
  , totp256
  , totp256Check
  , totp512
  , totp512Check

    -- * Auxiliary
  , Digits(..)
  , UserDigits
  , totpCounter
  , counterRange
  , totpCounterRange
  ) where

import Chronos (Time (..), Timespan (..), epoch, second)
import Data.Bits
import Data.ByteString qualified as BS
import Data.Kind
import Data.Serialize.Get
import Data.Serialize.Put
import Data.Type.Ord
import Data.Word
import GHC.TypeLits
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512
import System.IO.Unsafe (unsafePerformIO)
import Torsor qualified
import Data.Type.Bool
import Data.Int (Int64)

type UserDigits :: Nat -> Constraint
type UserDigits digits = If (digits >=? 6) (() :: Constraint)
      (TypeError ('Text "You cannot request less than 6 digits (digits requested: "
         ':<>: ShowType digits ':<>: 'Text ")"))

data Digits (n :: Natural) = Digits
  deriving stock (Show)

-- |
--
-- @since 3.0.0.0
data Algorithm = SHA256 | SHA512
  deriving stock (Eq, Show, Ord)

-- | Settings used for TOTP generation
--
-- @since 3.0.0.0
data TOTPSettings = TOTPSettings
  { digits :: Word
  -- ^ The number of digits needed for authentication by the end-user. Must be at least 6.
  , algorithm :: Algorithm
  -- ^ HMAC-SHA-256 or HMAC-SHA-512
  , step :: Timespan
  -- ^ Time step, which is the validity period of a TOTP token in
  , skew :: Timespan
  }
  deriving stock (Eq, Show, Ord)

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
hotp256
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Digits digits
  -- ^ Number of digits in a password. MUST be 6 digits at a minimum, and possibly 7 and 8 digits.
  -> Word32
  -- ^ HOTP
hotp256 key counter digits = unsafePerformIO $ do
  let msg = runPut $ putWord64be counter
  hash <- SHA256.authenticationTagToBinary <$> SHA256.authenticate msg key
  let w = truncateHash $ BS.unpack hash
  pure $ w `mod` (10 ^ (fromInteger @Word32 $ natVal digits))

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
hotp512
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA512.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Digits digits
  -- ^ Number of digits in a password
  -> Word32
  -- ^ HOTP
hotp512 key counter digits = unsafePerformIO $ do
  let msg = runPut $ putWord64be counter
  hash <- SHA512.authenticationTagToBinary <$> SHA512.authenticate msg key
  let w = truncateHash $ BS.unpack hash
  pure $ w `mod` (10 ^ (fromInteger @Word32 $ natVal digits))

truncateHash :: [Word8] -> Word32
truncateHash b =
  let offset = last b .&. 0xF -- take low 4 bits of last byte
      rb = BS.pack $ take 4 $ drop (fromIntegral offset) b -- resulting 4 byte value
   in case runGet getWord32be rb of
        Left e -> error e
        Right res -> res .&. 0x7FFFFFFF -- reset highest bit

-- | Check presented password against a valid range.
hotp256Check
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Digits digits
  -- ^ Number of digits provided
  -> Word32
  -- ^ Digits entered by user
  -> Bool
  -- ^ True if password is valid
hotp256Check secret range counter digits pass =
  let counters = counterRange range counter
      passwords = fmap (\c -> hotp256 secret c digits) counters
   in elem pass passwords

hotp512Check
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA512.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Digits digits
  -- ^ Number of digits in a password
  -> Word32
  -- ^ Password entered by user
  -> Bool
  -- ^ True if password is valid
hotp512Check secret range counter digits pass =
  let counters = counterRange range counter
      passwords = fmap (\c -> hotp512 secret c digits) counters
   in elem pass passwords

-- | Compute a Time-Based One-Time Password using secret key and time.
totp256
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits digits
  -- ^ Number of digits in a password
  -> Word32
  -- ^ TOTP
totp256 secret time period = hotp256 secret (totpCounter time period)

-- | Compute a Time-Based One-Time Password using secret key and time.
totp512
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA512.AuthenticationKey
  -- ^ Shared secret
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits digits
  -- ^ Number of digits in a password
  -> Word32
  -- ^ TOTP
totp512 secret time period = hotp512 secret (totpCounter time period)

-- | Check presented password against time periods.
--
-- @since 3.0.0.0
totp256Check
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits digits
  -- ^ Numer of digits in a password
  -> Word32
  -- ^ Password given by user
  -> Bool
  -- ^ True if password is valid
totp256Check secret range time period digits pass =
  let counters = totpCounterRange range time period
      passwords = fmap (\c -> hotp256 secret c digits) counters
   in elem pass passwords

-- | Check presented password against time periods.
--
-- @since 3.0.0.0
totp512Check
  :: forall (digits :: Natural)
   . (KnownNat digits, UserDigits digits)
  => SHA512.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits digits
  -- ^ Numer of digits in a password
  -> Word32
  -- ^ Password given by user
  -> Bool
  -- ^ True if password is valid
totp512Check secret range time period digits pass =
  let counters = totpCounterRange range time period
      passwords = fmap (\c -> hotp512 secret c digits) counters
   in elem pass passwords

-- | Calculate HOTP counter using time. Starting time (T0
-- according to RFC6238) is 0 (begining of UNIX epoch)
totpCounter
  :: Time
  -- ^ Time of totp
  -> Timespan
  -- ^ Time range in seconds
  -> Word64
  -- ^ Resulting counter
totpCounter time period =
  ts2word (asSeconds (sinceEpoch time)) `div` ts2word (asSeconds period)
  where
    ts2word :: Int64 -> Word64
    ts2word s = fromIntegral s

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
totpCounterRange
  :: (Word64, Word64)
  -> Time
  -> Timespan
  -> [Word64]
totpCounterRange range time period =
  counterRange range $ totpCounter time period
