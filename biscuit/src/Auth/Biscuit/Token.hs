{-# LANGUAGE NamedFieldPuns  #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections   #-}
{-|
  Module      : Auth.Biscuit.Token
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Module defining the main biscuit-related operations
-}
module Auth.Biscuit.Token
  ( Biscuit (..)
  , ParseError (..)
  , VerificationError (..)
  , ExistingBlock
  , mkBiscuit
  , addBlock
  , checkBiscuitSignature
  , parseBiscuit
  , serializeBiscuit
  , verifyBiscuit
  , verifyBiscuitWithLimits

  , BlockWithRevocationIds (..)
  , getRevocationIds
  ) where

import           Control.Monad                 (when)
import           Control.Monad.Except          (runExceptT, throwError)
import           Control.Monad.IO.Class        (liftIO)
import           Data.Bifunctor                (first)
import           Data.ByteString               (ByteString)
import           Data.List.NonEmpty            (NonEmpty ((:|)))
import qualified Data.List.NonEmpty            as NE

import           Auth.Biscuit.Datalog.AST      (Block, Query, Verifier)
import           Auth.Biscuit.Datalog.Executor (BlockWithRevocationIds (..),
                                                ExecutionError, Limits,
                                                defaultLimits,
                                                runVerifierWithLimits)
import qualified Auth.Biscuit.Proto            as PB
import           Auth.Biscuit.ProtoBufAdapter  (Symbols, blockToPb,
                                                commonSymbols, extractSymbols,
                                                pbToBlock)
import           Auth.Biscuit.Sel              (Keypair (publicKey), PublicKey,
                                                Signature (..), aggregate,
                                                hashBytes, newKeypair,
                                                parsePublicKey,
                                                serializePublicKey, signBlock,
                                                verifySignature)
import           Auth.Biscuit.Utils            (maybeToRight)

-- | Protobuf serialization does not have a guaranteed deterministic behaviour,
-- so we need to keep the initial serialized payload around in order to compute
-- a new signature when adding a block.
type ExistingBlock = (ByteString, Block)

-- | A parsed biscuit
data Biscuit
  = Biscuit
  { symbols   :: Symbols
  -- ^ The symbols already defined in the contained blocks
  , authority :: (PublicKey, ExistingBlock)
  -- ^ The authority block, along with the associated public key. The public key
  -- is kept around since it's embedded in the serialized biscuit, but should not
  -- be used for verification. An externally provided public key should be used instead.
  , blocks    :: [(PublicKey, ExistingBlock)]
  -- ^ The extra blocks, along with the public keys needed
  , signature :: Signature
  }
  deriving (Eq, Show)

-- | Create a new biscuit with the provided authority block
mkBiscuit :: Keypair -> Block -> IO Biscuit
mkBiscuit keypair authority = do
  let authorityPub = publicKey keypair
      (s, authoritySerialized) = PB.encodeBlock <$> blockToPb commonSymbols 0 authority
  signature <- signBlock keypair authoritySerialized
  pure $ Biscuit { authority = (authorityPub, (authoritySerialized, authority))
                 , blocks = []
                 , symbols = commonSymbols <> s
                 , signature
                 }

-- | Add a block to an existing biscuit. The block will be signed
-- with a randomly-generated keypair
addBlock :: Block -> Biscuit -> IO Biscuit
addBlock newBlock b@Biscuit{..} = do
  let (s, newBlockSerialized) = PB.encodeBlock <$> blockToPb symbols (length blocks) newBlock
  keypair <- newKeypair
  newSig <- signBlock keypair newBlockSerialized
  endSig <- aggregate signature newSig
  pure $ b { blocks = blocks <> [(publicKey keypair, (newBlockSerialized, newBlock))]
           , symbols = symbols <> s
           , signature = endSig
           }

-- | Only check a biscuit signature. This can be used to perform an early check, before
-- bothering with constructing a verifier.
checkBiscuitSignature :: Biscuit -> PublicKey -> IO Bool
checkBiscuitSignature Biscuit{..} publicKey =
  let publicKeysAndMessages = (publicKey, fst $ snd authority) :| (fmap fst <$> blocks)
   in verifySignature publicKeysAndMessages signature

-- | Errors that can happen when parsing a biscuit
data ParseError
  = InvalidHexEncoding
  -- ^ The provided ByteString is not hex-encoded
  | InvalidB64Encoding
  -- ^ The provided ByteString is not base64-encoded
  | InvalidProtobufSer String
  -- ^ The provided ByteString does not contain properly serialized protobuf values
  | InvalidProtobuf String
  -- ^ The bytestring was correctly deserialized from protobuf, but the values can't be turned into a proper biscuit
  deriving (Eq, Show)

-- | Parse a biscuit from a raw bytestring.
parseBiscuit :: ByteString -> Either ParseError Biscuit
parseBiscuit bs = do
  blockList <- first InvalidProtobufSer $ PB.decodeBlockList bs
  let pbBlocks    = PB.getField $ PB.blocks    blockList
      pbKeys      = PB.getField $ PB.keys      blockList
      pbAuthority = PB.getField $ PB.authority blockList
      pbSignature = PB.getField $ PB.signature blockList
  when (length pbBlocks + 1 /= length pbKeys) $ Left (InvalidProtobufSer $ "Length mismatch " <> show (length pbBlocks, length pbKeys))
  rawAuthority <- first InvalidProtobufSer $ PB.decodeBlock pbAuthority
  rawBlocks    <- traverse (first InvalidProtobufSer . PB.decodeBlock) pbBlocks
  let s = extractSymbols commonSymbols $ rawAuthority : rawBlocks


  parsedAuthority <- (pbAuthority,) <$> blockFromPB s rawAuthority
  parsedBlocks    <- zip pbBlocks <$> traverse (blockFromPB s) rawBlocks
  parsedKeys      <- maybeToRight (InvalidProtobufSer "Invalid pubkeys") $ traverse parsePublicKey pbKeys
  let blocks = zip (drop 1 parsedKeys) parsedBlocks
      authority = (head parsedKeys, parsedAuthority)
      symbols = s
      signature = Signature { parameters = PB.getField $ PB.parameters pbSignature
                            , z = PB.getField $ PB.z pbSignature
                            }
  pure Biscuit{..}

-- | Serialize a biscuit to a raw bytestring
serializeBiscuit :: Biscuit -> ByteString
serializeBiscuit Biscuit{..} =
  let authorityBs = fst $ snd authority
      blocksBs = fst . snd <$> blocks
      keys = serializePublicKey . fst <$> authority : blocks
      Signature{..} = signature
      sigPb = PB.Signature
                { parameters = PB.putField parameters
                , z = PB.putField z
                }
   in PB.encodeBlockList PB.Biscuit
       { authority = PB.putField authorityBs
       , blocks    = PB.putField blocksBs
       , keys      = PB.putField keys
       , signature = PB.putField sigPb
       }

-- | Parse a single block from a protobuf value
blockFromPB :: Symbols -> PB.Block -> Either ParseError Block
blockFromPB s pbBlock  = first InvalidProtobuf $ pbToBlock s pbBlock

-- | An error that can happen when verifying a biscuit
data VerificationError
  = SignatureError
  -- ^ The signature is invalid
  | DatalogError ExecutionError
  -- ^ The checks and policies could not be verified
  deriving (Eq, Show)

-- | Given a provided verifier (a set of facts, rules, checks and policies),
-- and a public key, verify a biscuit:
--
-- - make sure the biscuit has been signed with the private key associated to the public key
-- - make sure the biscuit is valid for the provided verifier
verifyBiscuitWithLimits :: Limits -> Biscuit -> Verifier -> PublicKey -> IO (Either VerificationError Query)
verifyBiscuitWithLimits l b verifier pub = runExceptT $ do
  sigCheck <- liftIO $ checkBiscuitSignature b pub
  when (not sigCheck) $ throwError SignatureError
  authorityBlock :| attBlocks <- liftIO $ getRevocationIds b
  verifResult <- liftIO $ runVerifierWithLimits l authorityBlock attBlocks verifier
  case verifResult of
    Left e  -> throwError $ DatalogError e
    Right p -> pure p

-- | Same as `verifyBiscuitWithLimits`, but with default limits (1ms timeout, max 1000 facts, max 100 iterations)
verifyBiscuit :: Biscuit -> Verifier -> PublicKey -> IO (Either VerificationError Query)
verifyBiscuit = verifyBiscuitWithLimits defaultLimits

-- | Get the components needed to compute revocation ids
getRidComponents :: (PublicKey, ExistingBlock) -> ByteString
                 -> ((ByteString, ByteString), Block)
getRidComponents (pub, (blockBs, block)) param =
  ( ( blockBs <> serializePublicKey pub
    , blockBs <> serializePublicKey pub <> param
    )
  , block
  )

-- | Given revocation ids components and a block, compute the revocation ids
-- and attach them to the block
mkBRID :: ((ByteString, ByteString), Block) -> IO BlockWithRevocationIds
mkBRID ((g,u), bBlock) = do
  genericRevocationId <- hashBytes g
  uniqueRevocationId  <- hashBytes u
  pure BlockWithRevocationIds{..}

-- | Compute the revocation ids for a given biscuit
getRevocationIds :: Biscuit -> IO (NonEmpty BlockWithRevocationIds)
getRevocationIds Biscuit{..} = do
   params <- maybe (fail "") pure . NE.nonEmpty $ parameters signature
   let allBlocks = authority :| blocks
       blocksAndParams = NE.zipWith getRidComponents allBlocks params
       conc ((g1, u1), _) ((g2, u2), b) = ((g1 <> g2, u1 <> u2), b)
       withPreviousBlocks :: NonEmpty ((ByteString, ByteString), Block)
       withPreviousBlocks = NE.scanl1 conc blocksAndParams
   traverse mkBRID withPreviousBlocks
