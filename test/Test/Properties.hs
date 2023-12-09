{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Properties where

import Chronos
import Control.Monad (guard)
import Data.Function ((&))
import Data.Functor ((<&>))
import Data.Int (Int64)
import Data.Maybe (fromJust)
import Data.Text qualified as Text
import Data.Text.Display (Display (..), display)
import Data.Word (Word32)
import Sel.HMAC.SHA256 qualified as HMAC
import System.IO.Unsafe (unsafeDupablePerformIO)
import Test.Tasty
import Test.Tasty.QuickCheck
import Torsor qualified

import OTP.Commons
import OTP.TOTP qualified as TOTP

spec :: TestTree
spec =
  testGroup
    "Properties"
    [ digitNumberProperty
    , timePeriodProperty
    ]

-- Properties

digitNumberProperty :: TestTree
digitNumberProperty = testProperty "Digit parameter determines the length of the output" $
  property $ \(arbitraryDigits, key, timestamp) ->
    let period = Torsor.scale 30 second
        ArbitraryDigits digits = arbitraryDigits
        totp =
          TOTP.totpSHA1
            (getKey key)
            timestamp
            period
            digits
        expectedLength = digitsToWord32 digits
        actualLength = totp.digits
     in expectedLength === actualLength

timePeriodProperty :: TestTree
timePeriodProperty = testProperty "A code stays stable within a time frame with the same key & digit parameters" $
  property $ \(Key key, ArbitraryDigits digits, SeparationTime separationTime, ArbitraryTime timestamp') ->
    let period = Torsor.scale separationTime second
        validUntil = Torsor.add period timestamp'
        (Timespan nanoseconds) = period
        timestamp = Torsor.add (Timespan (negate $ nanoseconds `div` 2)) validUntil
        totp =
          TOTP.totpSHA1
            key
            timestamp'
            period
            digits
     in counterexample
          ( Text.unpack $
              mconcat
                [ "Time: "
                , display timestamp'
                , ", Separation time (tested period): "
                , display period
                , ", Valid until: "
                , display validUntil
                , ", Time tested: "
                , display timestamp
                ]
          )
          ( TOTP.totpSHA1Check
              key
              (0, 1)
              timestamp
              period
              digits
              (display totp.code)
          )

newtype ArbitraryDigits = ArbitraryDigits Digits
  deriving (Eq, Show) via Digits

instance Arbitrary ArbitraryDigits where
  arbitrary = ArbitraryDigits . fromJust . mkDigits . fromIntegral @Int @Word32 <$> chooseInt (6, 9)

deriving instance Arbitrary Time

newtype Key = Key {getKey :: HMAC.AuthenticationKey}
  deriving newtype (Eq, Ord, Show)

instance Arbitrary Key where
  arbitrary = pure $ Key $ unsafeDupablePerformIO HMAC.newAuthenticationKey

-- | A separation time is a period in which we test the validity of a code.
newtype SeparationTime = SeparationTime Int64
  deriving (Eq, Show, Ord, Num, Enum, Real, Integral) via Int64

instance Arbitrary SeparationTime where
  arbitrary =
    chooseInt (1, 30)
      <&> fromIntegral @Int @Int64
      <&> SeparationTime
  shrink (SeparationTime time) = do
    t' <- shrink time
    guard (t' >= 1)
    pure $ SeparationTime t'

instance Display Time where
  displayBuilder time =
    let format = DatetimeFormat (Just '-') (Just ' ') (Just ':')
     in time
          & timeToDatetime
          & builder_YmdHMS (SubsecondPrecisionFixed 0) format

instance Display Timespan where
  displayBuilder timespan = displayBuilder (asSeconds timespan) <> "s"

newtype ArbitraryTime = ArbitraryTime Time
  deriving (Eq, Show, Ord, Display) via Time

instance Arbitrary ArbitraryTime where
  arbitrary = do
    datetime <- arbitrary @Datetime
    pure $ ArbitraryTime (datetimeToTime datetime)

instance Arbitrary TimeOfDay where
  arbitrary =
    TimeOfDay
      <$> choose (0, 23)
      <*> choose (0, 59)
      -- never use leap seconds for property-based tests
      <*> ( do
              subsecPrecision <- chooseInt (0, 9)
              secs <- chooseInt (0, 59)
              case subsecPrecision of
                0 -> pure (fromIntegral @Int @Int64 secs * 1_000_000_000)
                _ -> do
                  subsecs <- chooseInt (0, ((10 :: Int) ^ subsecPrecision) - 1)
                  let subsecs' = subsecs * ((10 :: Int) ^ (9 - subsecPrecision))
                  if subsecs' < 0 || subsecs' >= 1_000_000_000
                    then error "Mistake in Arbitrary instance for TimeOfDay"
                    else
                      pure
                        ( (fromIntegral @Int @Int64 secs * 1_000_000_000)
                            + fromIntegral @Int @Int64 subsecs
                        )
          )

instance Arbitrary Date where
  arbitrary =
    Date
      <$> fmap Year (choose (1800, 2100))
      <*> fmap Month (choose (0, 11))
      <*> fmap DayOfMonth (choose (1, 28))

instance Arbitrary Datetime where
  arbitrary = Datetime <$> arbitrary <*> arbitrary
