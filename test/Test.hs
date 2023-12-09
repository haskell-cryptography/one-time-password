module Main where

import Sel
import Test.Tasty
import Test.Tasty.QuickCheck (QuickCheckTests)

import Test.Comparison qualified as Comparison
import Test.HOTP qualified as HOTP
import Test.Properties qualified as Properties
import Test.TOTP qualified as TOTP

main :: IO ()
main =
  secureMain $
    defaultMain $
      adjustOption moreTests $
        testGroup
          "one-time-password tests"
          [ HOTP.spec
          , TOTP.spec
          , Properties.spec
          , Comparison.spec
          ]

moreTests :: QuickCheckTests -> QuickCheckTests
moreTests = max 10_000
