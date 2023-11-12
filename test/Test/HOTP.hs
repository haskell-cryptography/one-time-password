module Test.HOTP where

import Test.Tasty

import Data.Text qualified as Text
import OTP
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "HOTP"
    [ testGroup
        "HMAC-SHA-256"
        [ testCase "Expected codes" testExpectedHOTP256Codes
        , testCase "Validate code" testValidateHOTP256
        ]
    , testGroup
        "HMAC-SHA-512"
        [ testCase "Expected codes" testExpectedHOTP512Codes
        , testCase "Validate code" testValidateHOTP512
        ]
    ]

testExpectedHOTP256Codes :: Assertion
testExpectedHOTP256Codes = do
  let key = case SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43" of
        Right k -> k
        Left e -> error (Text.unpack e)
  let counters = [0 .. 10]
  results <- traverse (\counter -> hotp256 key counter 6) counters
  assertEqual
    "Codes are expected and stable"
    [545840, 42194, 783687, 856777, 199784, 809856, 270404, 137308, 219373, 965280, 635343]
    results

testValidateHOTP256 :: Assertion
testValidateHOTP256 = do
  let key = case SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43" of
        Right k -> k
        Left e -> error (Text.unpack e)
  code <- hotp256 key 30 6
  result <- hotp256Check key (29,31) 30 6 code
  assertBool
    "Code is checked"
    result

testExpectedHOTP512Codes :: Assertion
testExpectedHOTP512Codes = do
  let key = case SHA256.authenticationKeyFromHexByteString "11f1bf4c4136f33194c95c80e29dfb091f488ca9ac12b07907e4ed145fd35269" of
        Right k -> k
        Left e -> error (Text.unpack e)
  let counters = [0 .. 10]
  results <- traverse (\counter -> hotp256 key counter 6) counters
  assertEqual
    "Codes are expected and stable"
    [925198, 749302, 925465, 858755, 244674, 366640, 852988, 777459, 49404, 697567, 647501]
    results

testValidateHOTP512 :: Assertion
testValidateHOTP512 = do
  let key = case SHA512.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43" of
        Right k -> k
        Left e -> error (Text.unpack e)
  code <- hotp512 key 30 6
  result <- hotp512Check key (29,31) 30 6 code
  assertBool
    "Code is checked"
    result
