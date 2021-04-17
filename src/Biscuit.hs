{-# LANGUAGE ApplicativeDo   #-}
{-# LANGUAGE NamedFieldPuns  #-}
{-# LANGUAGE RecordWildCards #-}
module Biscuit
  ( Biscuit
  , biscuitAuthority
  , biscuitBlocks
  , mkBiscuit
  , Block (..)
  , Seed
  , randomSeed
  , seedFromBytes
  , KeyPair
  , randomKeyPair
  , getPublic
  , verifyBiscuit
  , Verifier (..)
  , attenuateBiscuit
  , serializeBiscuit
  ) where

import           Control.Concurrent     (runInBoundThread)
import           Control.Monad          (mfilter)
import           Control.Monad.Except   (ExceptT (..), runExceptT)
import           Crypto.Random          (getRandomBytes)
import           Data.Bifunctor         (first)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.Either.Validation (Validation (..))
import           Data.Foldable          (fold, traverse_)
import           Data.Functor           (($>))
import           Data.Functor.Compose   (Compose (..))
import           Data.List.NonEmpty     (NonEmpty (..))
import           Data.Text              (Text)
import qualified Data.Text              as T

import qualified Biscuit.Internal       as Internal

newtype Seed = Seed ByteString

randomSeed :: IO Seed
randomSeed = Seed <$> getRandomBytes 32

seedFromBytes :: ByteString -> Maybe Seed
seedFromBytes bs =
  if BS.length bs == 32
  then Just $ Seed bs
  else Nothing

data KeyPair = KeyPair
  { _private :: Internal.KeyPair
  , _public  :: Internal.PublicKey
  }

newtype PublicKey = PublicKey Internal.PublicKey

getPublic :: KeyPair -> PublicKey
getPublic KeyPair{_public} = PublicKey _public

randomKeyPair :: IO KeyPair
randomKeyPair = do
  (Seed seed) <- randomSeed
  _private    <- Internal.keyPairNew seed
  _public     <- Internal.keyPairPublic _private
  pure KeyPair{..}

data Biscuit = Biscuit
  { _handle    :: Internal.Biscuit
  , _authority :: Block
  , _blocks    :: [Block]
  } deriving Show

biscuitAuthority :: Biscuit -> Block
biscuitAuthority = _authority

biscuitBlocks :: Biscuit -> [Block]
biscuitBlocks = _blocks

data Block = Block
  { _facts   :: [Text]
  , _rules   :: [Text]
  , _caveats :: [Text]
  , _context :: Maybe Text
  } deriving Show

getBlocks :: Internal.Biscuit -> IO (NonEmpty Block)
getBlocks biscuit = do
  authority <- getBlockAt biscuit 0
  blockCount <- Internal.biscuitBlockCount biscuit
  blocks <- traverse (getBlockAt biscuit) [1..blockCount-1]
  pure $ authority :| blocks

getBlockAt :: Internal.Biscuit -> Int -> IO Block
getBlockAt biscuit blockId = do
  factCount <- Internal.biscuitBlockFactCount biscuit blockId
  _facts <- fmap T.pack <$> traverse (Internal.biscuitBlockFact biscuit blockId) [0..factCount-1]
  ruleCount <- Internal.biscuitBlockRuleCount biscuit blockId
  _rules <- fmap T.pack <$> traverse (Internal.biscuitBlockRule biscuit blockId) [0..ruleCount-1]
  caveatCount <- Internal.biscuitBlockCaveatCount biscuit blockId
  _caveats <- fmap T.pack <$> traverse (Internal.biscuitBlockCaveat biscuit blockId) [0..caveatCount-1]
  _context <- fmap T.pack <$> Internal.biscuitBlockContext biscuit blockId
  pure Block{..}

biscuitFromHandle :: Internal.Biscuit
                  -> IO Biscuit
biscuitFromHandle _handle = do
  _authority :| _blocks <- getBlocks _handle
  pure Biscuit{..}

addDatalogElement :: (String -> IO Bool)
                  -> String
                  -> IO (Validation (NonEmpty DataLogParsingError) ())
addDatalogElement add value = do
  result <- add value
  if result then pure $ Success ()
            else do
                   error <- Internal.getErrorMessage
                   pure $ Failure $ pure $ (value, fold error)

type DataLogParsingError = (String, String)

addFactToBiscuit, addRuleToBiscuit, addCaveatToBiscuit, setContextOnBiscuit
  :: Internal.BiscuitBuilder
  -> Text
  -> IO (Validation (NonEmpty DataLogParsingError) ())
addFactToBiscuit builder =
  addDatalogElement (Internal.biscuitBuilderAddAuthorityFact builder) . T.unpack
addRuleToBiscuit builder =
  addDatalogElement (Internal.biscuitBuilderAddAuthorityRule builder) . T.unpack
addCaveatToBiscuit builder =
  addDatalogElement (Internal.biscuitBuilderAddAuthorityCaveat builder) . T.unpack
setContextOnBiscuit builder =
  addDatalogElement
    (Internal.biscuitBuilderSetAuthorityContext builder) . T.unpack

addFactToBlock, addRuleToBlock, addCaveatToBlock, setContextOnBlock
  :: Internal.BlockBuilder
  -> Text
  -> IO (Validation (NonEmpty DataLogParsingError) ())
addFactToBlock builder =
  addDatalogElement (Internal.blockBuilderAddFact builder) . T.unpack
addRuleToBlock builder =
  addDatalogElement (Internal.blockBuilderAddRule builder) . T.unpack
addCaveatToBlock builder =
  addDatalogElement (Internal.blockBuilderAddCaveat builder) . T.unpack
setContextOnBlock builder =
  addDatalogElement
    (Internal.blockBuilderSetContext builder) . T.unpack

addFactToVerifier, addRuleToVerifier, addCaveatToVerifier
  :: Internal.Verifier
  -> Text
  -> IO (Validation (NonEmpty DataLogParsingError) ())
addFactToVerifier verifier =
  addDatalogElement (Internal.verifierAddFact verifier) . T.unpack
addRuleToVerifier verifier =
  addDatalogElement (Internal.verifierAddRule verifier) . T.unpack
addCaveatToVerifier verifier =
  addDatalogElement (Internal.verifierAddCaveat verifier) . T.unpack

mkBiscuit :: KeyPair
          -> Block
          -> Seed
          -> IO (Either (NonEmpty DataLogParsingError) Biscuit)
mkBiscuit (KeyPair kp _) Block{..} (Seed seed) = runInBoundThread $ do
  builder <- Internal.biscuitBuilder kp
  result <- getCompose $ do
    traverse_ (Compose . addFactToBiscuit builder) _facts
    traverse_ (Compose . addRuleToBiscuit builder) _rules
    traverse_ (Compose . addCaveatToBiscuit builder) _caveats
    traverse_ (Compose . setContextOnBiscuit builder) _context
    pure ()
  case result of
    Failure es -> pure $ Left es
    Success () -> do
      handle  <- Internal.biscuitBuilderBuild builder seed
      Right <$> biscuitFromHandle handle

attenuateBiscuit :: Biscuit
                 -> Block
                 -> KeyPair
                 -> Seed
                 -> IO (Either (NonEmpty DataLogParsingError) Biscuit)
attenuateBiscuit Biscuit{_handle} Block{..} KeyPair{_private} (Seed seed) = do
  builder <- Internal.biscuitCreateBlock _handle
  result <- getCompose $ do
    traverse_ (Compose . addFactToBlock builder) _facts
    traverse_ (Compose . addRuleToBlock builder) _rules
    traverse_ (Compose . addCaveatToBlock builder) _caveats
    traverse_ (Compose . setContextOnBlock builder) _context
    pure ()
  case result of
    Failure es -> pure $ Left es
    Success () -> do
      newHandle <- Internal.biscuitAppendBlock _handle builder _private seed
      Right <$> biscuitFromHandle newHandle

data Verifier = Verifier
  { _vfacts   :: [Text]
  , _vrules   :: [Text]
  , _vcaveats :: [Text]
  } deriving Show

data FailedCaveat
  = FailedCaveat
  { caveat :: Text
  , source :: Either Block Verifier
  }
  deriving Show

data VerificationError
  = InvalidSignature
  | LogicFailedCaveats (NonEmpty FailedCaveat)
  | InvalidVerifier (NonEmpty DataLogParsingError)
  deriving Show

mkVerifier :: Internal.Biscuit
           -> Internal.PublicKey
           -> Verifier
           -> IO (Either (NonEmpty DataLogParsingError) Internal.Verifier)
mkVerifier handle pubKey Verifier{..} = do
  verifier <- Internal.biscuitVerify handle pubKey
  result <- getCompose $ do
    traverse_ (Compose . addFactToVerifier verifier) _vfacts
    traverse_ (Compose . addRuleToVerifier verifier) _vrules
    traverse_ (Compose . addCaveatToVerifier verifier) _vcaveats
    pure ()
  case result of
    Failure es -> pure $ Left es
    Success () -> do
      putStrLn =<< Internal.verifierPrint verifier
      pure $ Right verifier

retrieveValidationError :: Verifier -> Biscuit -> IO VerificationError
retrieveValidationError verifier biscuit = do
  kind <- Internal.errorKind
  case kind of
    Internal.LogicFailedCaveats -> LogicFailedCaveats <$> retrieveCaveatsErrors verifier biscuit
    -- ToDo invalid signature errors happen earlier
    _                           -> pure InvalidSignature

retrieveCaveatsErrors :: Verifier -> Biscuit -> IO (NonEmpty FailedCaveat)
retrieveCaveatsErrors verifier biscuit = do
  errorCount <- Internal.errorCaveatCount
  ids <- if errorCount <= 0
      then fail "Error count should be > 0"
      else pure $ 0 :| [1..errorCount - 1]
  traverse (retrieveCaveatError verifier biscuit) ids

retrieveCaveatError :: Verifier -> Biscuit -> Int -> IO FailedCaveat
retrieveCaveatError verifier Biscuit{_authority,_blocks} caveatId = do
  let getBlock i = if i == 0 then _authority
                             else _blocks !! (i-1)
  isVerifier <- Internal.errorCaveatIsVerifier caveatId
  caveat <- T.pack <$> Internal.errorCaveatRule caveatId
  source <- if isVerifier
               then pure $ Right verifier
               else do
                       blockId <- Internal.errorCaveatBlockId caveatId
                       pure . Left $ getBlock blockId
  pure FailedCaveat{caveat,source}

verifyBiscuit :: Biscuit
              -> Verifier
              -> PublicKey
              -> IO (Either VerificationError ())
verifyBiscuit biscuit@Biscuit{..} verifier (PublicKey pubKey) = runInBoundThread $ runExceptT $ do
  vHandle <- ExceptT . fmap (first InvalidVerifier) $ mkVerifier _handle pubKey verifier
  ExceptT $ do
    res <- Internal.verifierVerify vHandle
    if res
        then pure $ Right ()
        else Left <$> retrieveValidationError verifier biscuit

serializeBiscuit :: Biscuit -> IO ByteString
serializeBiscuit Biscuit{_handle} = Internal.serialize _handle
