module OTP.HOTP
  ( OTP (..)

    -- ** HMAC-SHA-1
  , newSHA1Key
  , hotpSHA1
  , hotpSHA1Check

    -- ** HMAC-SHA-256
  , newSHA256Key
  , hotpSHA256
  , hotpSHA256Check

    -- ** HMAC-SHA-512
  , newSHA512Key
  , hotpSHA512
  , hotpSHA512Check

    -- ** Re-exports from OTP.Commons
  , Digits
  , mkDigits
  ) where

import Crypto.Hash.SHA1 qualified as SHA1
import Data.Bits
import Data.ByteString qualified as BS
import Data.List qualified as List
import Data.Serialize.Put
import Data.Text (Text)
import Data.Text.Display
import Data.Word
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512
import System.IO.Unsafe (unsafePerformIO)

import OTP.Commons

-- ** HMAC-SHA-1

-- | Create an new random key to be used with the SHA-1 functions
--
-- @since 3.0.0.0
newSHA1Key :: IO SHA256.AuthenticationKey
newSHA1Key = SHA256.newAuthenticationKey

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
--
-- @since 3.0.0.0
hotpSHA1
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Digits
  -- ^ Number of digits in a password. MUST be 6 digits at a minimum, and possibly 7 and 8 digits.
  -> OTP
  -- ^ HOTP
hotpSHA1 authenticationKey counter digits' = unsafePerformIO $ do
  let digits = digitsToWord32 digits'
  let msg = runPut $ putWord64be counter
  let key = SHA256.unsafeAuthenticationKeyToBinary authenticationKey
  let hash = SHA1.hmac key msg
  let code = truncateHash $ BS.unpack hash
  let result = code `rem` (10 ^ digits)
  pure $ OTP digits result

-- | Check presented password against a valid range.
--
-- @since 3.0.0.0
hotpSHA1Check
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Digits
  -- ^ Number of digits provided
  -> Text
  -- ^ Digits entered by user
  -> Bool
  -- ^ True if password is valid
hotpSHA1Check secret range counter digits pass =
  let counters = counterRange range counter
      passwords = fmap (\c -> display $ hotpSHA1 secret c digits) counters
   in elem pass passwords

-- ** HMAC-SHA-256

-- | Create an new random key to be used with the SHA256 functions
--
-- @since 3.0.0.0
newSHA256Key :: IO SHA256.AuthenticationKey
newSHA256Key = SHA256.newAuthenticationKey

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
--
-- @since 3.0.0.0
hotpSHA256
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Digits
  -- ^ Number of digits in a password. MUST be 6 digits at a minimum, and possibly 7 and 8 digits.
  -> OTP
  -- ^ HOTP
hotpSHA256 key counter digits' = unsafePerformIO $ do
  let digits = digitsToWord32 digits'
  let msg = runPut $ putWord64be counter
  hash <- SHA256.authenticationTagToBinary <$> SHA256.authenticate msg key
  let code = truncateHash $ BS.unpack hash
  let result = code `rem` (10 ^ digits)
  pure $ OTP digits result

-- | Check presented password against a valid range.
--
-- @since 3.0.0.0
hotpSHA256Check
  :: SHA256.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Digits
  -- ^ Number of digits provided
  -> Text
  -- ^ Digits entered by user
  -> Bool
  -- ^ True if password is valid
hotpSHA256Check secret range counter digits pass =
  let counters = counterRange range counter
      passwords = fmap (\c -> display $ hotpSHA256 secret c digits) counters
   in elem pass passwords

-- ** HMAC-SHA-256

-- | Create an new random key to be used with the SHA512 functions
--
-- @since 3.0.0.0
newSHA512Key :: IO SHA512.AuthenticationKey
newSHA512Key = SHA512.newAuthenticationKey

-- | Compute HMAC-Based One-Time Password using secret key and counter value.
--
-- @since 3.0.0.0
hotpSHA512
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> Word64
  -- ^ Counter value
  -> Digits
  -- ^ Number of digits in a password
  -> OTP
  -- ^ HOTP
hotpSHA512 key counter digits' = unsafePerformIO $ do
  let digits = digitsToWord32 digits'
  let msg = runPut $ putWord64be counter
  hash <- SHA512.authenticationTagToBinary <$> SHA512.authenticate msg key
  let code = truncateHash $ BS.unpack hash
  let result = code `rem` (10 ^ digits)
  pure $ OTP digits result

-- |
--
-- @since 3.0.0.0
hotpSHA512Check
  :: SHA512.AuthenticationKey
  -- ^ Shared secret
  -> (Word64, Word64)
  -- ^ Valid counter range, before and after ideal
  -> Word64
  -- ^ Ideal (expected) counter value
  -> Digits
  -- ^ Number of digits in a password
  -> Text
  -- ^ Password entered by user
  -> Bool
  -- ^ True if password is valid
hotpSHA512Check secret range counter digits pass =
  let counters = counterRange range counter
      passwords = fmap (\c -> display $ hotpSHA512 secret c digits) counters
   in elem pass passwords

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
   in code .&. 0x7FFFFFFF -- clear the highest bit
