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
  ) where

import           Control.Monad          (mfilter)
import           Control.Monad.Except   (ExceptT (..), runExceptT)
import           Crypto.Random          (getRandomBytes)
import           Data.Bifunctor         (first)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.Either.Validation (Validation)
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
  putStrLn "Get authority block"
  authority <- getBlockAt biscuit 0
  putStrLn "Got authority block"
  blockCount <- Internal.biscuitBlockCount biscuit
  putStrLn $ "Got " <> show blockCount <> " blocks"
  blocks <- traverse (getBlockAt biscuit) [1..blockCount-1]
  pure $ authority :| blocks

getBlockAt :: Internal.Biscuit -> Int -> IO Block
getBlockAt biscuit blockId = do
  putStrLn $ "Reading block " <> show blockId
  factCount <- Internal.biscuitBlockFactCount biscuit blockId
  putStrLn $ "Got " <> show factCount <> " facts"
  _facts <- fmap T.pack <$> traverse (Internal.biscuitBlockFact biscuit blockId) [0..factCount-1]
  ruleCount <- Internal.biscuitBlockRuleCount biscuit blockId
  putStrLn $ "Got " <> show ruleCount <> " rules"
  _rules <- fmap T.pack <$> traverse (Internal.biscuitBlockRule biscuit blockId) [0..ruleCount-1]
  caveatCount <- Internal.biscuitBlockCaveatCount biscuit blockId
  putStrLn $ "Got " <> show caveatCount <> " caveats"
  _caveats <- fmap T.pack <$> traverse (Internal.biscuitBlockCaveat biscuit blockId) [0..caveatCount-1]
  _context <- fmap T.pack <$> Internal.biscuitBlockContext biscuit blockId
  pure Block{..}

biscuitFromHandle :: Internal.Biscuit
                  -> IO Biscuit
biscuitFromHandle _handle = do
  _authority :| _blocks <- getBlocks _handle
  pure Biscuit{..}

mkBiscuit :: KeyPair
          -> Block
          -> Seed
          -> IO Biscuit
mkBiscuit (KeyPair kp _) authority (Seed seed) = do
  builder <- Internal.biscuitBuilder kp
  -- TODO add error handling (check the bool result and extract the error)
  -- Composing IO and Validation will let us group the errors
  factRs <- traverse (Internal.biscuitBuilderAddAuthorityFact builder . T.unpack) (_facts authority)
  ruleRs <- traverse (Internal.biscuitBuilderAddAuthorityRule builder . T.unpack) (_rules authority)
  caveRs <- traverse (Internal.biscuitBuilderAddAuthorityCaveat builder . T.unpack) (_caveats authority)
  ctxR <- traverse (Internal.biscuitBuilderSetAuthorityContext builder . T.unpack) (_context authority)
  print (factRs, ruleRs, caveRs)
  handle  <- Internal.biscuitBuilderBuild builder seed
  putStrLn =<< Internal.biscuitPrint handle
  biscuitFromHandle handle

attenuateBiscuit :: Biscuit
                 -> Block
                 -> KeyPair
                 -> Seed
                 -> IO Biscuit
attenuateBiscuit Biscuit{_handle} Block{..} KeyPair{_private} (Seed seed) = do
  builder <- Internal.biscuitCreateBlock _handle
  factRs <- traverse (Internal.blockBuilderAddFact builder . T.unpack) _facts
  ruleRs <- traverse (Internal.blockBuilderAddRule builder . T.unpack) _rules
  caveRs <- traverse (Internal.blockBuilderAddCaveat builder . T.unpack) _caveats
  ctxR <- traverse (Internal.blockBuilderSetContext builder . T.unpack) _context
  print (factRs, ruleRs, caveRs)
  newHandle <- Internal.biscuitAppendBlock _handle builder _private seed
  biscuitFromHandle newHandle

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
  | InvalidVerifier -- todo register errors
  deriving Show

mkVerifier :: Internal.Biscuit
           -> Internal.PublicKey
           -> Verifier
           -> IO (Either () Internal.Verifier)
mkVerifier handle pubKey Verifier{..} = do
  verifier <- Internal.biscuitVerify handle pubKey
  factRs <- traverse (Internal.verifierAddFact verifier . T.unpack) _vfacts
  ruleRs <- traverse (Internal.verifierAddRule verifier . T.unpack) _vrules
  caveRs <- traverse (Internal.verifierAddCaveat verifier . T.unpack) _vcaveats
  print (factRs, ruleRs, caveRs)
  putStrLn =<< Internal.verifierPrint verifier
  pure $ Right verifier

verifyBiscuit :: Biscuit
              -> Verifier
              -> PublicKey
              -> IO (Either VerificationError ())
verifyBiscuit Biscuit{..} verifier (PublicKey pubKey) = runExceptT $ do
  vHandle <- ExceptT . fmap (first $ const InvalidVerifier) $ mkVerifier _handle pubKey verifier
  ExceptT $ do
    res <- Internal.verifierVerify vHandle
    print =<< Internal.getErrorMessage
    pure $ if res
        then Right ()
        else Left InvalidSignature -- todo
