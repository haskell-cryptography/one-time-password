{-# LANGUAGE DerivingStrategies #-}

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
  --
  --   -- * Auxiliary
  , totpCounter
  , counterRange
  , totpCounterRange
  ) where

import Data.Bits
import Data.ByteString qualified as BS
import Data.Serialize.Get
import Data.Serialize.Put
import Data.Time
import Data.Time.Clock.POSIX
import Data.Word
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
--
-- >>> hotp "1234" 100 6
-- 317569
--
-- >>> hotp SHA512 "1234" 100 6
-- 134131
--
-- >>> hotp SHA512 "1234" 100 8
-- 55134131
hotp256
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Word
  -- ^ Number of digits in a password. Should be between 6 and 8.
  -> IO Word32
  -- ^ HOTP
hotp256 key counter digits = do
  let msg = runPut $ putWord64be counter
  hash <- SHA256.authenticationTagToBinary <$> SHA256.authenticate msg key
  let w = truncateHash $ BS.unpack hash
  pure $ w `mod` (10 ^ digits)

hotp512
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Word
  -- ^ Number of digits in a password
  -> IO Word32
  -- ^ HOTP
hotp512 key counter digits = do
  let msg = runPut $ putWord64be counter
  hash <- SHA512.authenticationTagToBinary <$> SHA512.authenticate msg key
  let w = truncateHash $ BS.unpack hash
  pure $ w `mod` (10 ^ digits)

truncateHash :: [Word8] -> Word32
truncateHash b =
  let offset = last b .&. 0xF -- take low 4 bits of last byte
      rb = BS.pack $ take 4 $ drop (fromIntegral offset) b -- resulting 4 byte value
   in case runGet getWord32be rb of
        Left e -> error e
        Right res -> res .&. (0x80000000 - 1) -- reset highest bit

-- | Check presented password against a valid range.
--
-- >>> hotp "1234" 10 6
-- 50897
--
-- >>> hotpCheck "1234" (0,0) 10 6 50897
-- True
--
-- >>> hotpCheck "1234" (0,0) 9 6 50897
-- False
--
-- >>> hotpCheck "1234" (0,1) 9 6 50897
-- True
--
-- >>> hotpCheck "1234" (1,0) 11 6 50897
-- True
--
-- >>> hotpCheck "1234" (2,2) 8 6 50897
-- True
--
-- >>> hotpCheck "1234" (2,2) 7 6 50897
-- False
--
-- >>> hotpCheck "1234" (2,2) 12 6 50897
-- True
--
-- >>> hotpCheck "1234" (2,2) 13 6 50897
-- False
hotp256Check
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Word
  -- ^ Number of digits provided
  -> Word32
  -- ^ Digits entered by user
  -> IO Bool
  -- ^ True if password is valid
hotp256Check secr rng cnt len pass = do
  let counters = counterRange rng cnt
  passwds <- traverse (\c -> hotp256 secr c len) counters
  pure $ elem pass passwds

hotp512Check
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Word
  -- ^ Number of digits in a password
  -> Word32
  -- ^ Password entered by user
  -> IO Bool
  -- ^ True if password is valid
hotp512Check secr rng cnt len pass = do
  let counters = counterRange rng cnt
  passwds <- traverse (\c -> hotp512 secr c len) counters
  pure $ elem pass passwds

-- | Compute a Time-Based One-Time Password using secret key and time.
--
-- >>> totp "1234" (read "2010-10-10 00:01:00 UTC") 30 6
-- 388892
--
-- >>> totp "1234" (read "2010-10-10 00:01:00 UTC") 30 8
-- 43388892
--
-- >>> totp "1234" (read "2010-10-10 00:01:15 UTC") 30 8
-- 43388892
--
-- >>> totp "1234" (read "2010-10-10 00:01:31 UTC") 30 8
-- 39110359
totp256
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> UTCTime
  -- ^ Time of TOTP
  -> Word64
  -- ^ Time range in seconds
  -> Word
  -- ^ Number of digits in a password
  -> IO Word32
  -- ^ TOTP
totp256 secr time period len =
  hotp256 secr (totpCounter time period) len

-- | Compute a Time-Based One-Time Password using secret key and time.
--
-- >>> totp "1234" (read "2010-10-10 00:01:00 UTC") 30 6
-- 388892
--
-- >>> totp "1234" (read "2010-10-10 00:01:00 UTC") 30 8
-- 43388892
--
-- >>> totp "1234" (read "2010-10-10 00:01:15 UTC") 30 8
-- 43388892
--
-- >>> totp "1234" (read "2010-10-10 00:01:31 UTC") 30 8
-- 39110359
totp512
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> UTCTime
  -- ^ Time of TOTP
  -> Word64
  -- ^ Time range in seconds
  -> Word
  -- ^ Number of digits in a password
  -> IO Word32
  -- ^ TOTP
totp512 secr time period len =
  hotp512 secr (totpCounter time period) len

-- | Check presented password against time periods.
--
-- >>> totp "1234" (read "2010-10-10 00:00:00 UTC") 30 6
-- 778374
--
-- >>> totpCheck "1234" (0, 0) (read "2010-10-10 00:00:00 UTC") 30 6 778374
-- True
--
-- >>> totpCheck "1234" (0, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
-- False
--
-- >>> totpCheck "1234" (1, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
-- True
--
-- >>> totpCheck "1234" (1, 0) (read "2010-10-10 00:01:00 UTC") 30 6 778374
-- False
--
-- >>> totpCheck "1234" (2, 0) (read "2010-10-10 00:01:00 UTC") 30 6 778374
-- True
totp256Check
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> UTCTime
  -- ^ Time of TOTP
  -> Word64
  -- ^ Time range in seconds
  -> Word
  -- ^ Numer of digits in a password
  -> Word32
  -- ^ Password given by user
  -> IO Bool
  -- ^ True if password is valid
totp256Check secr rng time period len pass = do
  let counters = totpCounterRange rng time period
  passwds <- traverse (\c -> hotp256 secr c len) counters
  pure $ elem pass passwds

-- | Check presented password against time periods.
--
-- >>> totp "1234" (read "2010-10-10 00:00:00 UTC") 30 6
-- 778374
--
-- >>> totpCheck "1234" (0, 0) (read "2010-10-10 00:00:00 UTC") 30 6 778374
-- True
--
-- >>> totpCheck "1234" (0, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
-- False
--
-- >>> totpCheck "1234" (1, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
-- True
--
-- >>> totpCheck "1234" (1, 0) (read "2010-10-10 00:01:00 UTC") 30 6 778374
-- False
--
-- >>> totpCheck "1234" (2, 0) (read "2010-10-10 00:01:00 UTC") 30 6 778374
-- True
totp512Check
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> UTCTime
  -- ^ Time of TOTP
  -> Word64
  -- ^ Time range in seconds
  -> Word
  -- ^ Numer of digits in a password
  -> Word32
  -- ^ Password given by user
  -> IO Bool
  -- ^ True if password is valid
totp512Check secr rng time period len pass = do
  let counters = totpCounterRange rng time period
  passwds <- traverse (\c -> hotp512 secr c len) counters
  pure $ elem pass passwds

-- | Calculate HOTP counter using time. Starting time (T0
-- according to RFC6238) is 0 (begining of UNIX epoch)
--
-- >>> totpCounter (read "2010-10-10 00:00:00 UTC") 30
-- 42888960
--
-- >>> totpCounter (read "2010-10-10 00:00:30 UTC") 30
-- 42888961
--
-- >>> totpCounter (read "2010-10-10 00:01:00 UTC") 30
-- 42888962
totpCounter
  :: UTCTime
  -- ^ Time of totp
  -> Word64
  -- ^ Time range in seconds
  -> Word64
  -- ^ Resulting counter
totpCounter time period =
  let timePOSIX = floor $ utcTimeToPOSIXSeconds time
   in timePOSIX `div` period

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
--
-- >>> totpCounterRange (0, 0) (read "2010-10-10 00:01:00 UTC") 30
-- [42888962]
--
-- >>> totpCounterRange (2, 0) (read "2010-10-10 00:01:00 UTC") 30
-- [42888960,42888961,42888962]
--
-- >>> totpCounterRange (0, 2) (read "2010-10-10 00:01:00 UTC") 30
-- [42888962,42888963,42888964]
--
-- >>> totpCounterRange (2, 2) (read "2010-10-10 00:01:00 UTC") 30
-- [42888960,42888961,42888962,42888963,42888964]
totpCounterRange
  :: (Word64, Word64)
  -> UTCTime
  -> Word64
  -> [Word64]
totpCounterRange rng time period =
  counterRange rng $ totpCounter time period
