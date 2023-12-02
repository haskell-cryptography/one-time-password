{-# LANGUAGE OverloadedRecordDot #-}

module Test.Comparison where

import Chronos qualified
import Data.Base16.Types qualified as Base
import Data.ByteString.Base16 qualified as Base
import Sel.HMAC.SHA256 qualified as SHA256
import Test.Tasty
import Test.Tasty.HUnit

import Chronos (Time (..))
import Crypto.Hash.Algorithms qualified as Crypton
import Crypto.OTP qualified as Crypton
import Data.ByteString (StrictByteString)
import Data.Int (Int64)
import Data.Text.Display
import Data.Word (Word64)
import OTP.Commons
import OTP.TOTP qualified as TOTP
import Sel.HMAC.SHA512 qualified as SHA512
import Test.Utils
import Torsor

spec :: TestTree
spec =
  testGroup
    "Comparing outputs of other implementations"
    [ testGroup
        "Crypton"
        [ testCase "HMAC-SHA1 TOTP" testCryptonSHA1TOTP
        , testCase "HMAC-SH256 TOTP" testCryptonSHA256TOTP
        , testCase "HMAC-SH512 TOTP" testCryptonSHA512TOTP
        ]
    ]

testCryptonSHA1TOTP :: Assertion
testCryptonSHA1TOTP = do
  let hexKey = "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString hexKey
  let cryptoniteKey = Base.decodeBase16 $ Base.assertBase16 @StrictByteString hexKey
  timestamp@(Time ns) <- Chronos.now
  let seconds = ns `quot` (10 ^ 9 :: Int64)
  let timeStep = scale 30 Chronos.second
  digits <- assertJust $ mkDigits 6

  let cryptoniteTOTP =
        Crypton.totp
          Crypton.defaultTOTPParams
          cryptoniteKey
          (fromIntegral @Int64 @Word64 seconds)

  let ownTotp = TOTP.totpSHA1 key timestamp timeStep digits

  assertEqual
    "OTPs are the same"
    (display ownTotp.code)
    (display cryptoniteTOTP)

testCryptonSHA256TOTP :: Assertion
testCryptonSHA256TOTP = do
  let hexKey = "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString hexKey
  let cryptonKey = Base.decodeBase16 $ Base.assertBase16 @StrictByteString hexKey
  timestamp@(Time ns) <- Chronos.now
  let seconds = ns `quot` (10 ^ 9 :: Int64)
  let timeStep = scale 30 Chronos.second
  digits <- assertJust $ mkDigits 6
  totpParams <-
    assertRight $
      Crypton.mkTOTPParams
        Crypton.SHA256
        0
        30
        Crypton.OTP6
        Crypton.TwoSteps

  let cryptoniteTOTP =
        Crypton.totp
          totpParams
          cryptonKey
          (fromIntegral @Int64 @Word64 seconds)

  let ownTotp = TOTP.totpSHA256 key timestamp timeStep digits

  assertEqual
    "OTPs are the same"
    (display ownTotp.code)
    (display cryptoniteTOTP)

testCryptonSHA512TOTP :: Assertion
testCryptonSHA512TOTP = do
  let hexKey = "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  key <- assertRight $ SHA512.authenticationKeyFromHexByteString hexKey
  let cryptonKey = Base.decodeBase16 $ Base.assertBase16 @StrictByteString hexKey
  timestamp@(Time ns) <- Chronos.now
  let seconds = ns `quot` (10 ^ 9 :: Int64)
  let timeStep = scale 30 Chronos.second
  digits <- assertJust $ mkDigits 6
  totpParams <-
    assertRight $
      Crypton.mkTOTPParams
        Crypton.SHA512
        0
        30
        Crypton.OTP6
        Crypton.TwoSteps

  let cryptoniteTOTP =
        Crypton.totp
          totpParams
          cryptonKey
          (fromIntegral @Int64 @Word64 seconds)

  let ownTotp = TOTP.totpSHA512 key timestamp timeStep digits

  assertEqual
    "OTPs are the same"
    (display ownTotp.code)
    (display cryptoniteTOTP)
