module Test.TOTP where

import Chronos
import Data.Maybe (fromJust)
import OTP.Commons
import Test.Tasty
import Test.Tasty.HUnit
import Torsor (scale)

spec :: TestTree
spec =
  testGroup
    "TOTP"
    [ testCase "TOTP counter from time" testTOTPCounterFromTime
    ]

testTOTPCounterFromTime :: Assertion
testTOTPCounterFromTime = do
  let dtf = DatetimeFormat (Just '-') (Just ' ') (Just ':')
  let decode txt = datetimeToTime $ fromJust $ Chronos.decode_YmdHMS dtf txt
  assertEqual
    "Correct counter from date"
    (totpCounter (decode "2010-10-10 00:00:00") (scale 30 second))
    42888960

  assertEqual
    "Correct counter from date"
    (totpCounter (decode "2010-10-10 00:00:30") (scale 30 second))
    42888961

  assertEqual
    "Correct counter from date"
    (totpCounter (decode "2010-10-10 00:01:00") (scale 30 second))
    42888962
