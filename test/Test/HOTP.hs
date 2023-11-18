{-# LANGUAGE DataKinds #-}

module Test.HOTP where

import Data.Foldable (forM_)
import Data.Text.Display
import OTP
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512

import Data.Text qualified as Text
import Test.Tasty
import Test.Tasty.HUnit
import Test.Utils

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
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let counters = [0 .. 10]
  let results = fmap (\counter -> display $ hotp256 key counter (Digits @6)) counters
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

testValidateHOTP256 :: Assertion
testValidateHOTP256 = do
  key <- assertRight $ SHA256.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = hotp256 key 30 (Digits @6)
  let result = hotp256Check key (29, 31) 30 (Digits @6) (display code)
  assertBool
    "Code is checked"
    result

testExpectedHOTP512Codes :: Assertion
testExpectedHOTP512Codes = do
  key <- assertRight $ SHA512.authenticationKeyFromHexByteString "11f1bf4c4136f33194c95c80e29dfb091f488ca9ac12b07907e4ed145fd35269"
  let counters = [0 .. 10]
  let results = fmap (\counter -> display $ hotp512 key counter (Digits @6)) counters

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
  key <- assertRight $ SHA512.authenticationKeyFromHexByteString "e90cbae2d7d187f614806347cfd75002bd0db847451109599da507e8da88bf43"
  let code = hotp512 key 30 (Digits @6)
  let result = hotp512Check key (29, 31) 30 (Digits @6) (display code)
  assertBool
    "Code is checked"
    result
