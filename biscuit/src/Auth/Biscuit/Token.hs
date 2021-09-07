{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE RecordWildCards   #-}
{-|
  Module      : Auth.Biscuit.Token
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Module defining the main biscuit-related operations
-}
module Auth.Biscuit.Token
  ( Biscuit
  , OpenBiscuit
  , SealedBiscuit
  , BiscuitProof (..)


  , ParseError (..)
  , ExistingBlock
  , ParsedSignedBlock
  , mkBiscuit
  , addBlock
  , parseBiscuit
  , serializeBiscuit
  , verifyBiscuit
  , verifyBiscuitWithLimits
  , fromOpen
  , fromSealed

  , Biscuit'
  , rootKeyId
  , symbols
  , authority
  , blocks
  , proof
  , getRevocationIds
  ) where

import           Control.Monad                       (when)
import           Data.Bifunctor                      (first)
import           Data.ByteString                     (ByteString)
import           Data.List.NonEmpty                  (NonEmpty ((:|)))
import qualified Data.List.NonEmpty                  as NE
--
import           Auth.Biscuit.Crypto
import           Auth.Biscuit.Datalog.AST            (Block, Query, Verifier)
import           Auth.Biscuit.Datalog.Executor       (ExecutionError, Limits,
                                                      defaultLimits)
import           Auth.Biscuit.Datalog.ScopedExecutor (runVerifierWithLimits)
import qualified Auth.Biscuit.Proto                  as PB
import           Auth.Biscuit.ProtoBufAdapter        (Symbols, blockToPb,
                                                      commonSymbols,
                                                      extractSymbols, pbToBlock,
                                                      pbToProof,
                                                      pbToSignedBlock)
-- import           Auth.Biscuit.Utils                  (maybeToRight)

-- | Protobuf serialization does not have a guaranteed deterministic behaviour,
-- so we need to keep the initial serialized payload around in order to compute
-- a new signature when adding a block.
type ExistingBlock = (ByteString, Block)
type ParsedSignedBlock = (ExistingBlock, Signature, PublicKey)

-- | A parsed biscuit
data Biscuit' proof
  = Biscuit
  { rootKeyId :: Maybe Int
  -- ^ an optional identifier for the expected public key
  , symbols   :: Symbols
  -- ^ The symbols already defined in the contained blocks
  , authority :: ParsedSignedBlock
  -- ^ The authority block, along with the associated public key. The public key
  -- is kept around since it's embedded in the serialized biscuit, but should not
  -- be used for verification. An externally provided public key should be used instead.
  , blocks    :: [ParsedSignedBlock]
  -- ^ The extra blocks, along with the public keys needed
  , proof     :: proof
  }
  deriving (Eq, Show)

type Biscuit = Biscuit' (Either Signature SecretKey)
type SealedBiscuit = Biscuit' Signature
type OpenBiscuit = Biscuit' SecretKey

fromOpen :: OpenBiscuit -> Biscuit
fromOpen b@Biscuit{proof} = b { proof = Right proof }

fromSealed :: SealedBiscuit -> Biscuit
fromSealed b@Biscuit{proof} = b { proof = Left proof }

toParsedSignedBlock :: Block -> SignedBlock -> ParsedSignedBlock
toParsedSignedBlock block (serializedBlock, sig, pk) = ((serializedBlock, block), sig, pk)


-- | Create a new biscuit with the provided authority block
mkBiscuit :: SecretKey -> Block -> IO OpenBiscuit
mkBiscuit sk authority = do
  let (authoritySymbols, authoritySerialized) = PB.encodeBlock <$> blockToPb commonSymbols authority
  (signedBlock, nextSk) <- signBlock sk authoritySerialized
  pure Biscuit { rootKeyId = Nothing
               , authority = toParsedSignedBlock authority signedBlock
               , blocks = []
               , symbols = commonSymbols <> authoritySymbols
               , proof = nextSk
               }
-- | Add a block to an existing biscuit.
addBlock :: Block -> OpenBiscuit -> IO OpenBiscuit
addBlock block b@Biscuit{..} = do
  let (blockSymbols, blockSerialized) = PB.encodeBlock <$> blockToPb symbols block
  (signedBlock, nextSk) <- signBlock proof blockSerialized
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , symbols = symbols <> blockSymbols
           , proof = nextSk
           }

class BiscuitProof a where
  toPossibleProofs :: a -> Either Signature SecretKey

instance BiscuitProof (Either Signature SecretKey) where
  toPossibleProofs = id
instance BiscuitProof Signature where
  toPossibleProofs = Left
instance BiscuitProof SecretKey where
  toPossibleProofs = Right

-- | Serialize a biscuit to a raw bytestring
serializeBiscuit :: BiscuitProof p => Biscuit' p -> ByteString
serializeBiscuit Biscuit{..} =
  let proofField = case toPossibleProofs proof of
          Left sig -> PB.ProofSignature $ PB.putField (convert sig)
          Right sk -> PB.ProofSecret $ PB.putField (convert sk)
   in PB.encodeBlockList PB.Biscuit
        { rootKeyId = PB.putField Nothing -- TODO
        , authority = PB.putField $ toPBSignedBlock authority
        , blocks    = PB.putField $ toPBSignedBlock <$> blocks
        , proof     = PB.putField proofField
        }

toPBSignedBlock :: ParsedSignedBlock -> PB.SignedBlock
toPBSignedBlock ((block, _), sig, pk) =
  PB.SignedBlock
    { block = PB.putField block
    , nextKey = PB.putField (convert pk)
    , signature = PB.putField (convert sig)
    }

-- | Errors that can happen when parsing a biscuit
data ParseError
  = InvalidHexEncoding
  -- ^ The provided ByteString is not hex-encoded
  | InvalidB64Encoding
  -- ^ The provided ByteString is not base64-encoded
  | InvalidProtobufSer Bool String
  -- ^ The provided ByteString does not contain properly serialized protobuf values
  | InvalidProtobuf Bool String
  -- ^ The bytestring was correctly deserialized from protobuf, but the values can't be turned into a proper biscuit
  | InvalidProof
  -- ^ The bytestring was correctly deserialized from protobuf, but the values can't be turned into a proper biscuit
  | InvalidSignatures
  -- ^ The signatures were invalid
  deriving (Eq, Show)

-- | Parse a biscuit from a raw bytestring, first checking its signature.
parseBiscuit :: PublicKey -> ByteString -> Either ParseError Biscuit
parseBiscuit pk bs = do
  blockList <- first (InvalidProtobufSer True) $ PB.decodeBlockList bs
  let rootKeyId = fromEnum <$> PB.getField (PB.rootKeyId blockList)
  signedAuthority <- first (InvalidProtobuf True) $ pbToSignedBlock $ PB.getField $ PB.authority blockList
  signedBlocks    <- first (InvalidProtobuf True) $ traverse pbToSignedBlock $ PB.getField $ PB.blocks blockList
  proof         <- first (InvalidProtobuf True) $ pbToProof $ PB.getField $ PB.proof blockList

  let allBlocks = NE.reverse $ signedAuthority :| signedBlocks
  let blocksResult = verifyBlocks allBlocks pk
  let proofResult = case proof of
        Left  sig -> verifySignatureProof sig (NE.head allBlocks)
        Right sk  -> verifySecretProof sk     (NE.head allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures

  -- now parsing the block contents
  let toRawSignedBlock (payload, sig, pk') = do
        pbBlock <- first (InvalidProtobufSer False) $ PB.decodeBlock payload
        pure ((payload, pbBlock), sig, pk')

  rawAuthority <- toRawSignedBlock signedAuthority
  rawBlocks    <- traverse toRawSignedBlock signedBlocks

  let symbols = extractSymbols commonSymbols $ (\((_, p), _, _) -> p) <$> rawAuthority : rawBlocks

  authority <- rawSignedBlockToParsedSignedBlock symbols rawAuthority
  blocks    <- traverse (rawSignedBlockToParsedSignedBlock symbols) rawBlocks

  pure Biscuit{..}

rawSignedBlockToParsedSignedBlock :: Symbols
                                  -> ((ByteString, PB.Block), Signature, PublicKey)
                                  -> Either ParseError ParsedSignedBlock
rawSignedBlockToParsedSignedBlock s ((payload, pbBlock), sig, pk) = do
  block   <- first (InvalidProtobuf False) $ pbToBlock s pbBlock
  pure ((payload, block), sig, pk)

getRevocationIds :: Biscuit -> NonEmpty ByteString
getRevocationIds Biscuit{authority, blocks} =
  let allBlocks = authority :| blocks
      getRevocationId (_, sig, _) = convert sig
   in getRevocationId <$> allBlocks

-- | Given a provided verifier (a set of facts, rules, checks and policies),
-- and a public key, verify a biscuit:
--
-- - make sure the biscuit has been signed with the private key associated to the public key
-- - make sure the biscuit is valid for the provided verifier
verifyBiscuitWithLimits :: Limits -> Biscuit' a -> Verifier -> IO (Either ExecutionError Query)
verifyBiscuitWithLimits l Biscuit{..} verifier =
  let toBlockWithRevocationId ((_, block), sig, _) = (block, convert sig)
   in runVerifierWithLimits l
        (toBlockWithRevocationId authority)
        (toBlockWithRevocationId <$> blocks)
        verifier

-- | Same as `verifyBiscuitWithLimits`, but with default limits (1ms timeout, max 1000 facts, max 100 iterations)
verifyBiscuit :: Biscuit' a -> Verifier -> IO (Either ExecutionError Query)
verifyBiscuit = verifyBiscuitWithLimits defaultLimits
