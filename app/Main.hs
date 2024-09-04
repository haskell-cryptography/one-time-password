module Main (main) where

import Chronos (datetimeToTime, decode_YmdHMS, now, second, w3c)
import Data.ByteString (StrictByteString)
import Data.ByteString.Char8 qualified as BSC8
import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text.Display
import Data.Text.Encoding qualified as TE
import Data.Text.IO qualified as TIO
import Data.Version (showVersion)
import Data.Word
import Options.Applicative
import Paths_one_time_password (version)
import Sel (secureMain)
import Sel.HMAC.SHA256 qualified as SHA256
import Sel.HMAC.SHA512 qualified as SHA512
import System.Exit (exitFailure)
import Torsor (scale)

import OTP.Commons
import OTP.HOTP
import OTP.TOTP

main :: IO ()
main =
  secureMain $ do
    now' <- now
    let parserInfo = info (cmdP now' <**> helper <**> simpleVersioner (showVersion version)) (progDesc "One time passwords (OTP) utilities" <> briefDesc)
    customExecParser (prefs showHelpOnEmpty) parserInfo >>= runCmd

type RawSharedSecret = StrictByteString

data Command
  = -- | Compute HMAC-Based One-Time Password using secret key and counter value.
    -- ^ Shared secret
    -- ^ Counter value
    -- ^ Number of digits in a password
    HotpMk Algorithm RawSharedSecret Word64 Digits
  | -- | Check presented password against a valid range.
    -- ^ Shared secret
    -- ^ Valid counter range, before and after ideal
    -- ^ Ideal (expected) counter value
    -- ^ Number of digits in a password
    -- ^ Password entered by user
    HotpCheck Algorithm RawSharedSecret (Word64, Word64) Word64 Digits Text
  | -- | Compute a Time-Based One-Time Password using secret key and time.
    -- ^ Shared secret
    -- ^ Time of TOTP
    -- ^ Time range in seconds
    -- ^ Number of digits in a password
    TotpMk Algorithm RawSharedSecret Time Timespan Digits
  | -- | Check presented password against time periods.
    -- ^ Shared secret
    -- ^ Valid counter range, before and after ideal
    -- ^ Time of TOTP
    -- ^ Time range in seconds
    -- ^ Numer of digits in a password
    -- ^ Password given by user
    TotpCheck Algorithm RawSharedSecret (Word64, Word64) Time Timespan Digits Text
  | -- | Create a URI suitable for authenticators.
    -- ^ Shared secret key. Must be encoded in base32.
    -- ^ Name of the account (usually an email address)
    -- ^ Issuer
    -- ^ Amount of digits expected from the end-user
    -- ^ Amount of time before the generated code expires
    -- ^ Algorithm required
    TotpMkUri Text Text Text Digits Timespan Algorithm
  | -- | Create an new random key to be used with the SHA-1 functions
    KeyGen Algorithm

cmdP :: Time -> Parser Command
cmdP now' =
  hsubparser
    ( command "hotp" (info hotpCmdP (progDesc "HOTP commands"))
        <> command "totp" (info totpCmdP (progDesc "TOTP commands"))
        <> command "key-gen" (info keyGenCmdP (progDesc "Generate keys"))
    )
  where
    hotpCmdP =
      hsubparser $
        command
          "make"
          (info hotpMakeP (progDesc "Compute HMAC-Based One-Time Password using secret key and counter value"))
          <> command
            "check"
            (info hotpCheckP (progDesc "Check presented password against a valid range"))

    totpCmdP =
      hsubparser $
        command
          "make"
          (info totpMakeP (progDesc "Compute a Time-Based One-Time Password using secret key and time"))
          <> command
            "check"
            (info totpCheckP (progDesc "Check presented password against time periods"))
          <> command
            "uri"
            (info totpUriP (progDesc "Create a URI suitable for authenticators"))

    hotpMakeP :: Parser Command
    hotpMakeP =
      HotpMk
        <$> algorithmP
        <*> rawSharedSecretP
        <*> counterP
        <*> digitsP

    hotpCheckP :: Parser Command
    hotpCheckP =
      HotpCheck
        <$> algorithmP
        <*> rawSharedSecretP
        <*> timeRangeP
        <*> counterP
        <*> digitsP
        <*> passwordP

    totpMakeP :: Parser Command
    totpMakeP =
      TotpMk
        <$> algorithmP
        <*> rawSharedSecretP
        <*> timeP
        <*> timespanP
        <*> digitsP
    totpCheckP :: Parser Command
    totpCheckP =
      TotpCheck
        <$> algorithmP
        <*> rawSharedSecretP
        <*> timeRangeP
        <*> timeP
        <*> timespanP
        <*> digitsP
        <*> passwordP
    totpUriP :: Parser Command
    totpUriP =
      TotpMkUri
        <$> base32RawSharedSecretP
        <*> accountNameP
        <*> issuerP
        <*> digitsP
        <*> timespanP
        <*> algorithmP

    keyGenCmdP :: Parser Command
    keyGenCmdP =
      KeyGen
        <$> algorithmP

    algorithmP :: Parser Algorithm
    algorithmP =
      option (maybeReader mkAlgorithm) $
        long "algorithm"
          <> short 'a'
          <> metavar "ALGORITHM"
          <> help "Hash algorithm (sha1, sha256, sha512)"
          <> value HMAC_SHA1
          <> showDefault
          <> completeWith ["sha1", "sha256", "sha512"]

    mkAlgorithm :: String -> Maybe Algorithm
    mkAlgorithm =
      \case
        "sha1" -> Just HMAC_SHA1
        "sha256" -> Just HMAC_SHA256
        "sha512" -> Just HMAC_SHA512
        _ -> Nothing

    rawSharedSecretP :: Parser RawSharedSecret
    rawSharedSecretP =
      option (BSC8.pack <$> str) $
        long "secret"
          <> short 's'
          <> metavar "SECRET"
          <> help "Shared secret"

    digitsP :: Parser Digits
    digitsP =
      option (auto >>= mkReaderFromMaybe "Invalid number of digits" . mkDigits) $
        long "digits"
          <> short 'd'
          <> metavar "DIGITS"
          <> help "Number of digits in a password (at least 6)"
          <> value (fromJust $ mkDigits 6)
          <> showDefault

    timespanP :: Parser Timespan
    timespanP =
      option (fmap (flip scale second) auto) $
        long "timespan"
          <> short 'n'
          <> metavar "TIMESPAN"
          <> help "Time range in seconds"
          <> value (scale 30 second)
          <> showDefault

    timeP :: Parser Time
    timeP =
      option (auto >>= mkReaderFromMaybe "Invalid time" . mkTime) $
        long "time"
          <> short 't'
          <> metavar "TIME"
          <> help "Time of TOTP (iso or 'now')"
          <> value now'
          <> showDefault

    mkTime :: Text -> Maybe Time
    mkTime =
      \case
        "now" -> Just now'
        x -> datetimeToTime <$> decode_YmdHMS w3c x

    counterP :: Parser Word64
    counterP =
      option auto $
        long "counter"
          <> short 'c'
          <> metavar "COUNTER"
          <> help "Ideal counter value"
          <> value 0
          <> showDefault

    timeRangeP :: Parser (Word64, Word64)
    timeRangeP = (,) <$> counterRangeLowP <*> counterRangeHighP
      where
        counterRangeLowP =
          option auto $
            long "counter-range-low"
              <> metavar "COUNTER_RANGE_LOW"
              <> help "Valid counter range, before specified counter"
              <> value 0
              <> showDefault

        counterRangeHighP =
          option auto $
            long "counter-range-high"
              <> metavar "COUNTER_RANGE_HIGH"
              <> help "Valid counter range, after specified counter"
              <> value 0
              <> showDefault

    passwordP :: Parser Text
    passwordP =
      option auto $
        long "password"
          <> short 'p'
          <> metavar "PASSWORD"
          <> help "Password"

    base32RawSharedSecretP :: Parser Text
    base32RawSharedSecretP =
      option str $
        long "secret"
          <> short 's'
          <> metavar "SECRET"
          <> help "Shared secret"

    accountNameP :: Parser Text
    accountNameP =
      option str $
        long "account-name"
          <> short 'a'
          <> metavar "ACCOUNT-NAME"
          <> help "Name of the account (usually an email address)"

    issuerP :: Parser Text
    issuerP =
      option str $
        long "issuer"
          <> short 'i'
          <> metavar "ISSUER"
          <> help "Issuer"

    mkReaderFromMaybe :: String -> Maybe a -> ReadM a
    mkReaderFromMaybe err = maybe (readerError err) return

-- Define the main parser for Command

runCmd :: Command -> IO ()
runCmd =
  \case
    HotpMk algorithm rawSecret counter digits' ->
      case algorithm of
        HMAC_SHA1 -> do
          secret <- read256Secret rawSecret
          displayOtp $ hotpSHA1 secret counter digits'
        HMAC_SHA256 -> do
          secret <- read256Secret rawSecret
          displayOtp $ hotpSHA256 secret counter digits'
        HMAC_SHA512 -> do
          secret <- read512Secret rawSecret
          displayOtp $ hotpSHA512 secret counter digits'
    HotpCheck algorithm rawSecret range counter digits' pass ->
      case algorithm of
        HMAC_SHA1 -> do
          secret <- read256Secret rawSecret
          displayCheckedOtp $ hotpSHA1Check secret range counter digits' pass
        HMAC_SHA256 -> do
          secret <- read256Secret rawSecret
          displayCheckedOtp $ hotpSHA256Check secret range counter digits' pass
        HMAC_SHA512 -> do
          secret <- read512Secret rawSecret
          displayCheckedOtp $ hotpSHA512Check secret range counter digits' pass
    TotpMk algorithm rawSecret time period digits' ->
      case algorithm of
        HMAC_SHA1 -> do
          secret <- read256Secret rawSecret
          displayOtp $ totpSHA1 secret time period digits'
        HMAC_SHA256 -> do
          secret <- read256Secret rawSecret
          displayOtp $ totpSHA256 secret time period digits'
        HMAC_SHA512 -> do
          secret <- read512Secret rawSecret
          displayOtp $ totpSHA512 secret time period digits'
    TotpCheck algorithm rawSecret range time period digits' pass ->
      case algorithm of
        HMAC_SHA1 -> do
          secret <- read256Secret rawSecret
          displayCheckedOtp $ totpSHA1Check secret range time period digits' pass
        HMAC_SHA256 -> do
          secret <- read256Secret rawSecret
          displayCheckedOtp $ totpSHA256Check secret range time period digits' pass
        HMAC_SHA512 -> do
          secret <- read512Secret rawSecret
          displayCheckedOtp $ totpSHA512Check secret range time period digits' pass
    TotpMkUri secret account issuer digits' period algorithm ->
      TIO.putStrLn $ totpToURI secret account issuer digits' period algorithm
    KeyGen algorithm ->
      case algorithm of
        HMAC_SHA1 ->
          TIO.putStrLn . TE.decodeUtf8 . SHA256.unsafeAuthenticationKeyToHexByteString =<< newSHA1Key
        HMAC_SHA256 ->
          TIO.putStrLn . TE.decodeUtf8 . SHA256.unsafeAuthenticationKeyToHexByteString =<< newSHA256Key
        HMAC_SHA512 ->
          TIO.putStrLn . TE.decodeUtf8 . SHA512.unsafeAuthenticationKeyToHexByteString =<< newSHA512Key
  where
    displayOtp :: OTP -> IO ()
    displayOtp = TIO.putStrLn . display
    displayCheckedOtp :: Bool -> IO ()
    displayCheckedOtp p =
      if p
        then putStrLn "Match"
        else putStrLn "don't match" >> exitFailure
    read256Secret :: RawSharedSecret -> IO SHA256.AuthenticationKey
    read256Secret rawSecret =
      case SHA256.authenticationKeyFromHexByteString rawSecret of
        Right secret -> return secret
        Left err -> TIO.putStrLn ("Cannot read secret: " <> err) >> exitFailure
    read512Secret :: RawSharedSecret -> IO SHA512.AuthenticationKey
    read512Secret rawSecret =
      case SHA512.authenticationKeyFromHexByteString rawSecret of
        Right secret -> return secret
        Left err -> TIO.putStrLn ("Cannot read secret: " <> err) >> exitFailure
