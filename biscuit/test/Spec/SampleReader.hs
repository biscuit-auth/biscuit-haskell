{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DeriveTraversable  #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}
module Spec.SampleReader where

import           Debug.Trace

import           Control.Arrow                 ((&&&))
import           Control.Monad                 (join, void, when)
import           Data.Aeson
import           Data.Aeson.Types              (typeMismatch, unexpected)
import           Data.Attoparsec.Text          (parseOnly)
import           Data.Bifunctor                (Bifunctor (..))
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as BS
import           Data.Foldable                 (traverse_)
import           Data.List.NonEmpty            (NonEmpty (..))
import           Data.Map.Strict               (Map)
import qualified Data.Map.Strict               as Map
import           Data.Text                     (Text, pack)
import           Data.Text.Encoding            (encodeUtf8)
import           GHC.Generics                  (Generic)

import           Test.Tasty                    hiding (Timeout)
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Datalog.Executor (ExecutionError (..),
                                                ResultError (..))
import           Auth.Biscuit.Datalog.Parser   (blockParser, verifierParser)
import           Auth.Biscuit.Token

getB :: ParsedSignedBlock -> Block
getB ((_, b), _, _) = b

getAuthority :: Biscuit OpenOrSealed Checked -> Block
getAuthority = getB . authority

getBlocks :: Biscuit OpenOrSealed Checked -> [Block]
getBlocks = fmap getB . blocks

instance FromJSON SecretKey where
  parseJSON = withText "Ed25519 secret key" $ \t -> do
    let bs = encodeUtf8 t
        res = parseSecretKeyHex bs
        notSk = typeMismatch "Ed25519 secret key" (String t)
    maybe notSk pure res

instance FromJSON PublicKey where
  parseJSON = withText "Ed25519 public key" $ \t -> do
    let bs = encodeUtf8 t
        res = parsePublicKeyHex bs
        notPk = typeMismatch "Ed25519 public key" (String t)
    maybe notPk pure res

instance FromJSON Verifier where
  parseJSON = withText "verifier" $ \t -> do
    let res = parseVerifier t
        notVerifier e = typeMismatch e (String t)
    either notVerifier pure res

parseVerifier :: Text -> Either String Verifier
parseVerifier = parseOnly verifierParser

parseBlock :: Text -> Either String Block
parseBlock = parseOnly blockParser

data SampleFile a
  = SampleFile
  { root_private_key :: SecretKey
  , root_public_key  :: PublicKey
  , testcases        :: [TestCase a]
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass FromJSON

data RustResult e a
  = Err e
  | Ok a
  deriving stock (Generic, Eq, Show)

instance Bifunctor RustResult where
  bimap f g = \case
    Err e -> Err $ f e
    Ok  a -> Ok $ g a

instance (FromJSON e, FromJSON a) => FromJSON (RustResult e a) where
   parseJSON = genericParseJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

data ValidationR
  = ValidationR
  { world         :: Maybe WorldDesc
  , result        :: RustResult [Text] Int
  , verifier_code :: Verifier
  } deriving stock (Eq, Show, Generic)
    deriving anyclass FromJSON


checkResult :: Show a
            => RustResult [Text] Int
            -> Either a b
            -> Assertion
checkResult r e = case (r, e) of
  (Err es, Right _) -> assertFailure $ "Got success, but expected failure: " <> show es
  (Ok   _, Left  e) -> assertFailure $ "Expected success, but got failure: " <> show e
  _ -> pure ()


data TestCase a
  = TestCase
  { title       :: String
  , filename    :: a
  , token       :: NonEmpty BlockDesc
  , validations :: Map String ValidationR
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass FromJSON

data BlockDesc
  = BlockDesc
  { symbols :: [Text]
  , code    :: Text
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass FromJSON

data WorldDesc
  =  WorldDesc
  { facts    :: [Text]
  , rules    :: [Text]
  , checks   :: [Text]
  , policies :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass FromJSON

readBiscuits :: SampleFile FilePath -> IO (SampleFile (FilePath, ByteString))
readBiscuits =
   traverse $ traverse (BS.readFile . ("test/samples/v2/" <>)) . join (&&&) id

readSamplesFile :: IO (SampleFile (FilePath, ByteString))
readSamplesFile = do
  Just f <- decodeFileStrict' "test/samples/v2/samples.json"
  readBiscuits f

checkTokenBlocks :: (String -> IO ())
                 -> Biscuit OpenOrSealed Checked
                 -> NonEmpty BlockDesc
                 -> Assertion
checkTokenBlocks step b blockDescs = do
  step "Checking blocks"
  let bs = getAuthority b :| getBlocks b
      expected = traverse (parseBlock . code) blockDescs
  expected @?= Right bs

processTestCase :: (String -> IO ())
                -> PublicKey -> TestCase (FilePath, ByteString)
                -> Assertion
processTestCase step rootPk TestCase{..} = do
  step "Parsing "
  let vList = Map.toList validations
  case parse rootPk (snd filename) of
    Left parseError -> traverse_ (processFailedValidation step parseError) vList
    Right biscuit   -> do
      checkTokenBlocks step biscuit token
      traverse_ (processValidation step biscuit) vList

parseErrorToRust :: ParseError -> RustResult [Text] a
parseErrorToRust = Err . pure . \case
  InvalidHexEncoding -> "todo"
  InvalidB64Encoding -> "todo"
  InvalidProtobufSer w e -> pack $ "todo " <> show w <> e
  InvalidProtobuf True "Invalid signature" -> "Format(InvalidSignatureSize(16))"
  InvalidProtobuf w e -> "todo"
  InvalidProof -> "todo"
  InvalidSignatures -> "Format(Signature(InvalidSignature(\"signature error\")))"

processFailedValidation :: (String -> IO ())
                        -> ParseError
                        -> (String, ValidationR)
                        -> Assertion
processFailedValidation step e (name, ValidationR{result}) = do
  step $ "Checking validation " <> name
  checkResult result (Left e)

execErrorToRust :: Either ExecutionError a -> RustResult [Text] Int
execErrorToRust (Right _) = Ok 0
execErrorToRust (Left e) = Err $ case e of
  Timeout                            -> ["todo"]
  TooManyFacts                       -> ["todo"]
  TooManyIterations                  -> ["todo"]
  FactsInBlocks                      -> ["todo"]
  ResultError (NoPoliciesMatched cs) -> ["todo"]
  ResultError (FailedChecks cs)      -> ["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource($0), operation(#read), right($0, #read)\" })"]
  ResultError (DenyRuleMatched cs q) -> ["todo"]

processValidation :: (String -> IO ())
                  -> Biscuit OpenOrSealed Checked
                  -> (String, ValidationR)
                  -> Assertion
processValidation step b (name, ValidationR{..}) = do
  when (name /= "") $ step ("Checking " <> name)
  w    <- maybe (assertFailure "missing verifier contents") pure world
  pols <- either (assertFailure . show) pure $ parseVerifier $ foldMap (<> ";") (policies w)
  res <- verifyBiscuit b (verifier_code <> pols)
  checkResult result res

runTests :: (String -> IO ())
         -> Assertion
runTests step = do
  step "Parsing sample file"
  SampleFile{..} <- readSamplesFile
  traverse_ (processTestCase step root_public_key) testcases

specs :: TestTree
specs = testCaseSteps "Biscuit samples - compliance checks" runTests

mkTestCase :: PublicKey -> TestCase (FilePath, ByteString) -> TestTree
mkTestCase root_public_key tc@TestCase{filename} =
  testCaseSteps (fst filename) (\step -> processTestCase step root_public_key tc)

getSpecs :: IO TestTree
getSpecs = do
  SampleFile{..} <- readSamplesFile
  pure $ testGroup "Biscuit samples - compliance checks"
       $ mkTestCase root_public_key <$> testcases
