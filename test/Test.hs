module Main where

import Sel
import Test.Tasty

import Test.HOTP qualified as HOTP
import Test.TOTP qualified as TOTP

main :: IO ()
main =
  secureMain $
    defaultMain $
      testGroup
        "one-time-password tests"
        [ HOTP.spec
        , TOTP.spec
        ]
