{-# LANGUAGE DataKinds #-}

module Test.HOTP where

import Data.Foldable (forM_)
import Data.Text.Display
import OTP.HOTP
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512

import Data.Text qualified as Text
import OTP.Commons
import Test.Tasty
import Test.Tasty.HUnit
import Test.Utils

spec :: TestTree
spec =
  testGroup
    "HOTP"
    [ testGroup
        "HMAC-SHA-1"
        [ testCase "Expected codes" testExpectedHotpSHA1Codes
        , testCase "Validate code" testValidateHotpSHA1
        ]
    , testGroup
        "HMAC-SHA-256"
        [ testCase "Expected codes" testExpectedHotpSHA256Codes
        , testCase "Validate code" testValidateHotpSHA256
        ]
    , testGroup
        "HMAC-SHA-512"
        [ testCase "Expected codes" testExpectedHOTP512Codes
        , testCase "Validate code" testValidateHOTP512
        ]
    ]

testExpectedHotpSHA1Codes :: Assertion
testExpectedHotpSHA1Codes = do
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let counters = [0 .. 10]
  let results = fmap (\counter -> display $ hotpSHA1 key counter digits) counters
  assertEqual
    "Codes are expected and stable"
    [ "023113"
    , "181354"
    , "151026"
    , "300498"
    , "479326"
    , "661773"
    , "464666"
    , "430540"
    , "941671"
    , "303579"
    , "027354"
    ]
    results

  forM_ results $ \code ->
    assertBool
      ("Code " <> show code <> " is not 6 characters long")
      (Text.length (display code) == 6)

testValidateHotpSHA1 :: Assertion
testValidateHotpSHA1 = do
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = hotpSHA1 key 30 digits
  let result = hotpSHA1Check key (29, 31) 30 digits (display code)
  assertBool
    "Code is checked"
    result

testExpectedHotpSHA256Codes :: Assertion
testExpectedHotpSHA256Codes = do
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let counters = [0 .. 10]
  let results = fmap (\counter -> display $ hotpSHA256 key counter digits) counters
  assertEqual
    "Codes are expected and stable"
    [ "545840"
    , "042194"
    , "783687"
    , "856777"
    , "199784"
    , "809856"
    , "270404"
    , "137308"
    , "219373"
    , "965280"
    , "635343"
    ]
    results

  forM_ results $ \code ->
    assertBool
      ("Code " <> show code <> " is not 6 characters long")
      (Text.length (display code) == 6)

testValidateHotpSHA256 :: Assertion
testValidateHotpSHA256 = do
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = hotpSHA256 key 30 digits
  let result = hotpSHA256Check key (29, 31) 30 digits (display code)
  assertBool
    "Code is checked"
    result

testExpectedHOTP512Codes :: Assertion
testExpectedHOTP512Codes = do
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA512.authenticationKeyFromHexByteString "11f1bf4c4136f33194c95c80e29dfb091f488ca9ac12b07907e4ed145fd35269"
  let counters = [0 .. 10]
  let results = fmap (\counter -> display $ hotpSHA512 key counter digits) counters

  assertEqual
    "Codes are expected and stable"
    [ "789887"
    , "828664"
    , "852597"
    , "476319"
    , "098272"
    , "202574"
    , "057559"
    , "321460"
    , "156051"
    , "151927"
    , "131108"
    ]
    results

  forM_ results $ \code ->
    assertBool
      ("Code " <> show code <> " is not 6 characters long")
      (Text.length (display code) == 6)

testValidateHOTP512 :: Assertion
testValidateHOTP512 = do
  digits <- assertJust $ mkDigits 6
  key <- assertRight $ SHA512.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = hotpSHA512 key 30 digits
  let result = hotpSHA512Check key (29, 31) 30 digits (display code)
  assertBool
    "Code is checked"
    result
