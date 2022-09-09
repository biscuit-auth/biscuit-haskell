{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DeriveTraversable  #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE QuasiQuotes        #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE TypeApplications   #-}
module Spec.SampleReader where

import           Control.Arrow                 ((&&&))
import           Control.Lens                  ((^?))
import           Control.Monad                 (join, void, when, (<=<))
import           Data.Aeson
import           Data.Aeson.Lens               (key)
import           Data.Aeson.Types              (typeMismatch, unexpected)
import           Data.Attoparsec.Text          (endOfInput, parseOnly,
                                                skipSpace)
import           Data.Bifunctor                (Bifunctor (..))
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Base16        as Hex
import qualified Data.ByteString.Lazy          as LBS
import           Data.Foldable                 (traverse_)
import           Data.List.NonEmpty            (NonEmpty (..), toList)
import           Data.Map.Strict               (Map)
import qualified Data.Map.Strict               as Map
import           Data.Maybe                    (fromJust, isJust, isNothing)
import           Data.Text                     (Text, pack, unpack)
import           Data.Text.Encoding            (decodeUtf8, encodeUtf8)
import           Data.Traversable              (for)
import           GHC.Generics                  (Generic)
import           System.Directory              (createDirectory,
                                                getTemporaryDirectory)
import           System.FilePath               (isRelative)
import           System.Random                 (randomRIO)

import           Test.Tasty                    hiding (Timeout)
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Datalog.AST      (renderAuthorizer, renderBlock)
import           Auth.Biscuit.Datalog.Executor (ExecutionError (..),
                                                ResultError (..))
import           Auth.Biscuit.Datalog.Parser   (authorizerParser, blockParser)
import           Auth.Biscuit.Token
import           Paths_biscuit_haskell         (getDataFileName)

getB :: ParsedSignedBlock -> Block
getB ((_, b), _, _, _) = b

getAuthority :: Biscuit p Verified -> Block
getAuthority = getB . authority

getBlocks :: Biscuit p Verified -> [Block]
getBlocks = fmap getB . blocks

instance FromJSON SecretKey where
  parseJSON = withText "Ed25519 secret key" $ \t -> do
    let bs = encodeUtf8 t
        res = parseSecretKeyHex bs
        notSk = typeMismatch "Ed25519 secret key" (String t)
    maybe notSk pure res

instance ToJSON SecretKey where
  toJSON = toJSON . decodeUtf8 . serializeSecretKeyHex

instance FromJSON PublicKey where
  parseJSON = withText "Ed25519 public key" $ \t -> do
    let bs = encodeUtf8 t
        res = parsePublicKeyHex bs
        notPk = typeMismatch "Ed25519 public key" (String t)
    maybe notPk pure res

instance ToJSON PublicKey where
  toJSON = toJSON . decodeUtf8 . serializePublicKeyHex

instance FromJSON Authorizer where
  parseJSON = withText "authorizer" $ \t -> do
    let res = parseAuthorizer t
        notAuthorizer e = typeMismatch e (String t)
    either notAuthorizer pure res

instance ToJSON Authorizer where
  toJSON = toJSON . renderAuthorizer

parseAuthorizer :: Text -> Either String Authorizer
parseAuthorizer = parseOnly authorizerParser

parseBlock :: Text -> Either String Block
parseBlock = parseOnly (blockParser <* skipSpace <* endOfInput)

data SampleFile a
  = SampleFile
  { root_private_key :: SecretKey
  , root_public_key  :: PublicKey
  , testcases        :: [TestCase a]
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass (FromJSON, ToJSON)

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

instance (ToJSON e, ToJSON a) => ToJSON (RustResult e a) where
   toJSON = genericToJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

type RustError = Value

data ValidationR
  = ValidationR
  { world           :: Maybe WorldDesc
  , result          :: RustResult RustError Int
  , authorizer_code :: Authorizer
  , revocation_ids  :: [Text]
  } deriving stock (Eq, Show, Generic)
    deriving anyclass (FromJSON, ToJSON)

checkResult :: Show a
            => (a -> RustError -> Assertion)
            -> RustResult RustError Int
            -> Either a b
            -> Assertion
checkResult f r e = case (r, e) of
  (Err es, Right _) -> assertFailure $ "Got success, but expected failure: " <> show es
  (Ok   _, Left  e) -> assertFailure $ "Expected success, but got failure: " <> show e
  (Err es, Left e) -> f e es
  _ -> pure ()


data TestCase a
  = TestCase
  { title       :: String
  , filename    :: a
  , token       :: NonEmpty BlockDesc
  , validations :: Map String ValidationR
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass (FromJSON, ToJSON)

data BlockDesc
  = BlockDesc
  { symbols :: [Text]
  , code    :: Text
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data WorldDesc
  =  WorldDesc
  { facts    :: [Text]
  , rules    :: [Text]
  , checks   :: [Text]
  , policies :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

readBiscuits :: SampleFile FilePath -> IO (SampleFile (FilePath, ByteString))
readBiscuits =
  let pickFile f =
        if isRelative f
        then
          getDataFileName ("test/samples/v2/" <> f)
        else
          pure f
   in traverse $ traverse (BS.readFile <=< pickFile) . join (&&&) id

readSamplesFile :: FilePath -> IO (SampleFile (FilePath, ByteString))
readSamplesFile tempFile = do
  f <- either fail pure =<< eitherDecodeFileStrict' tempFile
  readBiscuits f

checkTokenBlocks :: (String -> IO ())
                 -> Biscuit OpenOrSealed Verified
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

compareParseErrors :: ParseError -> RustError -> Assertion
compareParseErrors pe re =
  let mustMatch p = assertBool (show (re,pe)) $ isJust $ re ^? p
      mustMatchEither ps = assertBool (show (re, pe)) $ any isJust $ (re ^?) <$> ps
   in case pe of
        InvalidHexEncoding ->
          assertFailure $ "InvalidHexEncoding can't appear here " <> show re
        InvalidB64Encoding ->
          mustMatch $ key "Base64"
        InvalidProtobufSer True s ->
          mustMatch $ key "Format" . key "DeserializationError"
        InvalidProtobuf True s ->
          mustMatch $ key "Format" . key "DeserializationError"
        InvalidProtobufSer False s ->
          mustMatch $ key "Format" . key "BlockDeserializationError"
        InvalidProtobuf False s ->
          mustMatch $ key "Format" . key "BlockDeserializationError"
        -- the signature size is now verified just before verifying the
        -- signature itself, not at deserialization time, since we want
        -- to interpret signatures only relative to the verifying public
        -- key.
        InvalidSignatures ->
          mustMatchEither
            [ key "Format" . key "Signature" . key "InvalidSignature"
            , key "Format" . key "InvalidSignatureSize"
            ]
        InvalidProof ->
          assertFailure $ "InvalidProof can't appear here " <> show re
        RevokedBiscuit ->
          assertFailure $ "RevokedBiscuit can't appear here " <> show re

compareExecErrors :: ExecutionError -> RustError -> Assertion
compareExecErrors ee re =
  let errorMessage = "ExecutionError mismatch: " <> show ee <> " " <> unpack (decodeUtf8 . LBS.toStrict $ encode re)
      mustMatch p = assertBool errorMessage $ isJust $ re ^? p
      -- todo compare `Unauthorized` contents
   in case ee of
        Timeout                            -> mustMatch $ key "RunLimit" . key "Timeout"
        TooManyFacts                       -> mustMatch $ key "RunLimit" . key "TooManyFacts"
        TooManyIterations                  -> mustMatch $ key "RunLimit" . key "TooManyIterations"
        InvalidRule                        -> mustMatch $ key "FailedLogic" . key "InvalidBlockRule"
        ResultError (NoPoliciesMatched cs) -> mustMatch $ key "FailedLogic" . key "Unauthorized"
        ResultError (FailedChecks cs)      -> mustMatch $ key "FailedLogic" . key "Unauthorized"
        ResultError (DenyRuleMatched cs q) -> mustMatch $ key "FailedLogic" . key "Unauthorized"

processFailedValidation :: (String -> IO ())
                        -> ParseError
                        -> (String, ValidationR)
                        -> Assertion
processFailedValidation step e (name, ValidationR{result}) = do
  step $ "Checking validation " <> name
  checkResult compareParseErrors result (Left e)

processValidation :: (String -> IO ())
                  -> Biscuit OpenOrSealed Verified
                  -> (String, ValidationR)
                  -> Assertion
processValidation step b (name, ValidationR{..}) = do
  when (name /= "") $ step ("Checking " <> name)
  w    <- maybe (assertFailure "missing authorizer contents") pure world
  pols <- either (assertFailure . show) pure $ parseAuthorizer $ foldMap (<> ";") (policies w)
  res <- authorizeBiscuit b (authorizer_code <> pols)
  checkResult compareExecErrors result res
  let revocationIds = decodeUtf8 . Hex.encode <$> toList (getRevocationIds b)
  step "Comparing revocation ids"
  revocation_ids @?= revocationIds


runTests :: FilePath
         -> (String -> IO ())
         -> Assertion
runTests sampleFiles step = do
  step "Parsing sample file"
  SampleFile{..} <- readSamplesFile sampleFiles
  traverse_ (processTestCase step root_public_key) testcases

mkTestCase :: PublicKey -> TestCase (FilePath, ByteString) -> TestTree
mkTestCase root_public_key tc@TestCase{filename} =
  testCaseSteps (fst filename) (\step -> processTestCase step root_public_key tc)

getSpecs :: FilePath -> IO TestTree
getSpecs sampleFiles = do
  SampleFile{..} <- readSamplesFile sampleFiles
  pure $ testGroup "Biscuit samples - compliance checks"
       $ mkTestCase root_public_key <$> testcases

mkTestCaseFromBiscuit
  :: String
  -> FilePath
  -> Biscuit Open Verified
  -> [(String, Authorizer)]
  -> IO (TestCase FilePath)
mkTestCaseFromBiscuit title filename biscuit authorizers = do
  let mkBlockDesc :: Block -> BlockDesc
      mkBlockDesc b = BlockDesc
        { code = renderBlock b
        , symbols = []
        }
      mkValidation :: Authorizer -> IO ValidationR
      mkValidation authorizer = do
        Right success <- authorizeBiscuit biscuit authorizer
        pure ValidationR
          { world = Just $ WorldDesc
             { facts = []
             , rules = []
             , checks = []
             , policies = []
             }
          , result = Ok 0
          , authorizer_code = authorizer
          , revocation_ids = decodeUtf8 . Hex.encode <$> toList (getRevocationIds biscuit)
          }
  BS.writeFile filename (serialize biscuit)
  let token = mkBlockDesc <$> getAuthority biscuit :| getBlocks biscuit
  validations <- Map.fromList <$> traverse (traverse mkValidation) authorizers

  pure TestCase{..}

addCases :: FilePath
         -> [(String, FilePath, Biscuit Open Verified, Authorizer)]
         -> IO ()
addCases tempFile cases = do
  f <- readSamples
  newCases <- for cases $ \(name, path, biscuit, auth) -> do
    mkTestCaseFromBiscuit name path biscuit [("", auth)]
  let newF = f { testcases = testcases f <> newCases }
  putStrLn "writing new"
  encodeFile tempFile newF

getTempDir :: IO FilePath
getTempDir = do
  suffix <- randomRIO (10000 :: Int, 99999)
  directory <- getTemporaryDirectory
  let tempDir = directory <> "/biscuit-haskell-tests-" <> show suffix
  createDirectory tempDir
  pure tempDir

readSamples =
  either fail pure =<< eitherDecodeFileStrict' @(SampleFile FilePath) =<< getDataFileName "test/samples/v2/samples.json"

generateCases :: IO FilePath
generateCases = do
  putStrLn "generating new"
  tempDir <- getTempDir
  let samplesFile = tempDir <> "/" <> "samples-new.json"
  putStrLn "step 2"
  print =<< getDataFileName "test/samples/v2/samples.json"
  SampleFile{root_private_key} <- readSamples
  let (eSkOne, ePkOne) = (id &&& toPublic) $ fromJust $ parseSecretKeyHex "0932c942ef3535daac4b34eaff9ab6a848b730adbb49dfb24714d1f67c26a49b"
  let (eSkTwo, ePkTwo) = (id &&& toPublic) $ fromJust $ parseSecretKeyHex "c520e19539e88fea4ccb388ad242ac962cafe8158a3a9da04c17159281c668fc"
  let (eSkThree, ePkThree) = (id &&& toPublic) $ fromJust $ parseSecretKeyHex "d547622fe6f3afeb83200b5dcc4a8efcb8fd53cde9833da313a9bdf6c12a035c"
  b1 <- do
      b <- mkBiscuit root_private_key [block|right("read"); check if group("admin") trusting ${ePkOne};|]
      addSignedBlock eSkOne [block|group("admin"); check if right("read"); |] b
  let a1 = [authorizer|allow if true;|]
  b2 <- do
      b <- mkBiscuit root_private_key [block|
                   query(0);
                   check if true trusting previous, ${ePkOne};
               |]
      b' <- addSignedBlock eSkOne [block|
                   query(1);
                   query(1,2) <- query(1), query(2) trusting ${ePkTwo} ;
                   check if query(2), query(3) trusting ${ePkTwo};
                   check if query(1) trusting ${ePkOne};
                 |] b
      b'' <- addSignedBlock eSkTwo [block|
                   query(2);
                   check if query(2), query(3) trusting ${ePkTwo};
                   check if query(1) trusting ${ePkOne};
                 |] b'
      b''' <- addSignedBlock eSkTwo [block|
                   query(3);
                   check if query(2), query(3) trusting ${ePkTwo};
                   check if query(1) trusting ${ePkOne};
                 |] b''
      addBlock [block|
           query(4);
           check if query(2) trusting ${ePkTwo};
           check if query(4) trusting ${ePkThree};
         |] b'''
  let a2 = [authorizer|
     check if query(1,2) trusting ${ePkOne}, ${ePkTwo};
     deny if query(3);
     deny if query(1,2);
     deny if query(0) trusting ${ePkOne};
     allow if true;
  |]
  addCases samplesFile
    [ ("third-party block", tempDir <> "/test24_third_party.bc", b1, a1)
    , ("third-party blocks keys", tempDir <> "/test25_third_party_keys.bc", b2, a2)
    ]
  pure samplesFile
