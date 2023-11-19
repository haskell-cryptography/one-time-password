module Test.Utils where

import GHC.Stack
import Test.Tasty.HUnit qualified as Test

assertRight :: HasCallStack => Either a b -> IO b
assertRight (Left _a) = Test.assertFailure "Test return Left instead of Right"
assertRight (Right b) = pure b

assertJust :: HasCallStack => Maybe a -> IO a
assertJust Nothing = Test.assertFailure "Test return Nothing instead of Just"
assertJust (Just a) = pure a
