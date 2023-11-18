{-# LANGUAGE GHC2021 #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
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
  , Digits (..)
  , UserDigits
  , totpCounter
  , counterRange
  , totpCounterRange
  ) where

import Chronos (Time (..), Timespan (..), epoch, second)
import Data.Bits
import Data.ByteString qualified as BS
import Data.Int (Int64)
import Data.Kind
import Data.List qualified as List
import Data.Serialize.Put
import Data.Text (Text)
import Data.Text.Display
import Data.Text.Lazy.Builder (Builder)
import Data.Text.Lazy.Builder qualified as Text
import Data.Type.Bool
import Data.Type.Ord qualified as Type
import Data.Word
import GHC.TypeLits qualified as Type
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512
import System.IO.Unsafe (unsafePerformIO)
import Text.Printf (printf)
import Torsor qualified

-- |
--
-- @since 3.0.0.0
data OTP = OTP
  { digits :: Word32
  , code :: Word32
  }
  deriving stock (Eq, Ord, Show)

-- |
--
-- @since 3.0.0.0
instance Display OTP where
  displayBuilder OTP{digits, code} = displayWord32AsOTP digits code

displayWord32AsOTP :: Word32 -> Word32 -> Builder
displayWord32AsOTP digits code = Text.fromString $ printf ("%0" <> show digits <> "u") code

type UserDigits :: Type.Natural -> Constraint
type UserDigits digits =
  If
    (digits Type.>=? 6)
    (() :: Constraint)
    ( Type.TypeError
        ( 'Type.Text "You cannot request less than 6 digits (digits requested: "
            'Type.:<>: Type.ShowType digits
            'Type.:<>: 'Type.Text ")"
        )
    )

-- |
--
-- @since 3.0.0.0
data Digits (n :: Type.Natural) = Digits
  deriving stock (Eq, Show, Ord)

-- |
--
-- @since 3.0.0.0
data Algorithm = SHA256 | SHA512
  deriving stock (Eq, Show, Ord)

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
--
-- @since 3.0.0.0
hotp256
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
  => SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Digits digits
  -- ^ Number of digits in a password. MUST be 6 digits at a minimum, and possibly 7 and 8 digits.
  -> OTP
  -- ^ HOTP
hotp256 key counter digits = unsafePerformIO $ do
  let msg = runPut $ putWord64be counter
  hash <- SHA256.authenticationTagToBinary <$> SHA256.authenticate msg key
  let code = truncateHash $ BS.unpack hash
  let power = fromInteger @Word32 $ Type.natVal digits
  let result = code `rem` (10 ^ power)
  pure $ OTP power result

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
--
-- @since 3.0.0.0
hotp512
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
  => SHA512.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Digits digits
  -- ^ Number of digits in a password
  -> OTP
  -- ^ HOTP
hotp512 key counter digits = unsafePerformIO $ do
  let msg = runPut $ putWord64be counter
  hash <- SHA512.authenticationTagToBinary <$> SHA512.authenticate msg key
  let code = truncateHash $ BS.unpack hash
  let power = fromInteger @Word32 $ Type.natVal digits
  let result = code `rem` (10 ^ power)
  pure $ OTP power result

-- | Take a hash and truncate it to its low 4 bits of the last byte.
--
-- >>> truncateHash [32,34,234,40,232, 123, 253, 20, 4]
-- 1752956180
--
-- @since 3.0.0.0
truncateHash :: [Word8] -> Word32
truncateHash b =
  let to32 = fromIntegral @Word8 @Word32
      offset = List.last b .&. 0xF
      code = case List.take 4 $ List.drop (fromIntegral offset) b of -- resulting 4 byte value
        [b0, b1, b2, b3] ->
          ((to32 b0 .&. 0x7F) .<<. 24)
            .|. ((to32 b1 .&. 0xFF) .<<. 16)
            .|. ((to32 b2 .&. 0xFF) .<<. 8)
            .|. (to32 b3 .&. 0xFF)
        _ -> error "The impossible happened"
   in code .&. 0x7FFFFFFF

-- | Check presented password against a valid range.
--
-- @since 3.0.0.0
hotp256Check
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
  => SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Digits digits
  -- ^ Number of digits provided
  -> Text
  -- ^ Digits entered by user
  -> Bool
  -- ^ True if password is valid
hotp256Check secret range counter digits pass =
  let counters = counterRange range counter
      passwords = fmap (\c -> display $ hotp256 secret c digits) counters
   in elem pass passwords

-- |
--
-- @since 3.0.0.0
hotp512Check
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
  => SHA512.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Digits digits
  -- ^ Number of digits in a password
  -> Text
  -- ^ Password entered by user
  -> Bool
  -- ^ True if password is valid
hotp512Check secret range counter digits pass =
  let counters = counterRange range counter
      passwords = fmap (\c -> display $ hotp512 secret c digits) counters
   in elem pass passwords

-- | Compute a Time-Based One-Time Password using secret key and time.
--
-- @since 3.0.0.0
totp256
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
  => SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits digits
  -- ^ Number of digits in a password
  -> OTP
  -- ^ TOTP
totp256 secret time period = hotp256 secret (totpCounter time period)

-- | Compute a Time-Based One-Time Password using secret key and time.
--
-- @since 3.0.0.0
totp512
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
  => SHA512.AuthenticationKey
  -- ^ Shared secret
  -> Time
  -- ^ Time of TOTP
  -> Timespan
  -- ^ Time range in seconds
  -> Digits digits
  -- ^ Number of digits in a password
  -> OTP
  -- ^ TOTP
totp512 secret time period = hotp512 secret (totpCounter time period)

-- | Check presented password against time periods.
--
-- @since 3.0.0.0
totp256Check
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
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
  -> Text
  -- ^ Password given by user
  -> Bool
  -- ^ True if password is valid
totp256Check secret range time period digits pass =
  let counters = totpCounterRange range time period
      passwords = fmap (\c -> display $ hotp256 secret c digits) counters
   in elem pass passwords

-- | Check presented password against time periods.
--
-- @since 3.0.0.0
totp512Check
  :: forall (digits :: Type.Natural)
   . (Type.KnownNat digits, UserDigits digits)
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
  -> Text
  -- ^ Password given by user
  -> Bool
  -- ^ True if password is valid
totp512Check secret range time period digits pass =
  let counters = totpCounterRange range time period
      passwords = fmap (\c -> display $ hotp512 secret c digits) counters
   in elem pass passwords

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
