module Test.TOTP where

import Chronos
import Data.ByteString.Base32 qualified as Base32
import Data.Maybe (fromJust)
import Data.Text.Display (display)
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512
import Test.Tasty
import Test.Tasty.HUnit
import Test.Utils
import Torsor (scale)

import OTP.Commons (Algorithm (..), mkDigits, totpCounter)
import OTP.TOTP (totpSHA1, totpSHA1Check, totpSHA256, totpSHA256Check, totpSHA512, totpSHA512Check, totpToURI)

spec :: TestTree
spec =
  testGroup
    "TOTP"
    [ testCase "TOTP counter from time" testTOTPCounterFromTime
    , testCase "HMAC-SHA-1 TOTP codes" testSHA1TOTPCodes
    , testCase "HMAC-SHA-256 TOTP codes" testSHA256TOTPCodes
    , testCase "HMAC-SHA-512 TOTP codes" testSHA512TOTPCodes
    , testCase "URI generation" testTOTPURIGeneration
    ]

testTOTPCounterFromTime :: Assertion
testTOTPCounterFromTime = do
  let dtf = DatetimeFormat (Just '-') (Just ' ') (Just ':')
  let decode txt = datetimeToTime $ fromJust $ Chronos.decode_YmdHMS dtf txt
  assertEqual
    "Correct counter from date 2010-10-10 00:00:00"
    (totpCounter (decode "2010-10-10 00:00:00") (scale 30 second))
    42888960

  assertEqual
    "Correct counter from date 2010-10-10 00:00:30"
    (totpCounter (decode "2010-10-10 00:00:30") (scale 30 second))
    42888961

  assertEqual
    "Correct counter from date 2010-10-10 00:01:00"
    (totpCounter (decode "2010-10-10 00:01:00") (scale 30 second))
    42888962

testSHA1TOTPCodes :: Assertion
testSHA1TOTPCodes = do
  timestamp <- now
  let timeStep = scale 30 second
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = totpSHA1 key timestamp timeStep digits
  let result = totpSHA1Check key (0, 1) timestamp timeStep digits (display code)
  assertBool
    "Can check own code"
    result

testSHA256TOTPCodes :: Assertion
testSHA256TOTPCodes = do
  timestamp <- now
  let timeStep = scale 30 second
  digits <- assertJust $ mkDigits 6

  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = totpSHA256 key timestamp timeStep digits
  let result = totpSHA256Check key (0, 1) timestamp timeStep digits (display code)
  assertBool
    "Can check own code"
    result

testSHA512TOTPCodes :: Assertion
testSHA512TOTPCodes = do
  timestamp <- now
  let timeStep = scale 30 second
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA512.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = totpSHA512 key timestamp timeStep digits
  let result = totpSHA512Check key (0, 1) timestamp timeStep digits (display code)
  assertBool
    "Code is checked"
    result

testTOTPURIGeneration :: Assertion
testTOTPURIGeneration = do
  let period = scale 30 second
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let issuer = "Localhost Inc"
  let account = "username@localhost.localdomain"

  let uri =
        totpToURI
          (Base32.encodeBase32 $ SHA256.unsafeAuthenticationKeyToBinary key)
          account
          issuer
          digits
          period
          HMAC_SHA1

  assertEqual
    "Expected URI"
    "otpauth://totp/Localhost%20Inc:username@localhost.localdomain?secret=5EGLVYWX2GD7MFEAMND47V2QAK6Q3OCHIUIQSWM5UUD6RWUIX5BQ====&issuer=Localhost%20Inc&digits=6&algorithm=SHA1&period=30"
    uri
