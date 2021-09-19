{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE KindSignatures    #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE RecordWildCards   #-}
{- HLINT ignore "Reduce duplication" -}
{-|
  Module      : Auth.Biscuit.Token
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Module defining the main biscuit-related operations
-}
module Auth.Biscuit.Token
  ( Biscuit
  , BiscuitProof (..)


  , ParseError (..)
  , ExistingBlock
  , ParsedSignedBlock
  , OpenOrSealed
  , Open
  , Sealed
  , Checked
  , NotChecked
  , mkBiscuit
  , addBlock
  , addBlockUnchecked
  , parseBiscuit
  , parseBiscuitUnchecked
  , serializeBiscuit
  , verifyBiscuit
  , verifyBiscuitWithLimits
  , fromOpen
  , fromSealed

  , rootKeyId
  , symbols
  , authority
  , blocks
  , proof
  , getRevocationIds
  , getCheckedBiscuitSignature
  ) where

import           Control.Monad                       (when)
import           Data.Bifunctor                      (first)
import           Data.ByteString                     (ByteString)
import           Data.List.NonEmpty                  (NonEmpty ((:|)))
import qualified Data.List.NonEmpty                  as NE
--
import           Auth.Biscuit.Crypto
import           Auth.Biscuit.Datalog.AST            (Block, Verifier)
import           Auth.Biscuit.Datalog.Executor       (ExecutionError, Limits,
                                                      defaultLimits)
import           Auth.Biscuit.Datalog.ScopedExecutor (VerificationSuccess,
                                                      runVerifierWithLimits)
import qualified Auth.Biscuit.Proto                  as PB
import           Auth.Biscuit.ProtoBufAdapter        (Symbols, blockToPb,
                                                      commonSymbols,
                                                      extractSymbols, pbToBlock,
                                                      pbToProof,
                                                      pbToSignedBlock)

-- | Protobuf serialization does not have a guaranteed deterministic behaviour,
-- so we need to keep the initial serialized payload around in order to compute
-- a new signature when adding a block.
type ExistingBlock = (ByteString, Block)
type ParsedSignedBlock = (ExistingBlock, Signature, PublicKey)

data OpenOrSealed
  = SealedProof Signature
  | OpenProof SecretKey

newtype Open = Open SecretKey
newtype Sealed = Sealed Signature

newtype Checked = Checked PublicKey
data NotChecked = NotChecked

-- | A parsed biscuit
data Biscuit proof check
  = Biscuit
  { rootKeyId  :: Maybe Int
  -- ^ an optional identifier for the expected public key
  , symbols    :: Symbols
  -- ^ The symbols already defined in the contained blocks
  , authority  :: ParsedSignedBlock
  -- ^ The authority block, along with the associated public key. The public key
  -- is kept around since it's embedded in the serialized biscuit, but should not
  -- be used for verification. An externally provided public key should be used instead.
  , blocks     :: [ParsedSignedBlock]
  -- ^ The extra blocks, along with the public keys needed
  , proof      :: proof
  , proofCheck :: check
  }
  deriving (Eq, Show)

fromOpen :: Biscuit Open Checked -> Biscuit OpenOrSealed Checked
fromOpen b@Biscuit{proof = Open p } = b { proof = OpenProof p }

fromSealed :: Biscuit Sealed Checked -> Biscuit OpenOrSealed Checked
fromSealed b@Biscuit{proof = Sealed p } = b { proof = SealedProof p }

toParsedSignedBlock :: Block -> SignedBlock -> ParsedSignedBlock
toParsedSignedBlock block (serializedBlock, sig, pk) = ((serializedBlock, block), sig, pk)


-- | Create a new biscuit with the provided authority block
mkBiscuit :: SecretKey -> Block -> IO (Biscuit Open Checked)
mkBiscuit sk authority = do
  let (authoritySymbols, authoritySerialized) = PB.encodeBlock <$> blockToPb commonSymbols authority
  (signedBlock, nextSk) <- signBlock sk authoritySerialized
  pure Biscuit { rootKeyId = Nothing
               , authority = toParsedSignedBlock authority signedBlock
               , blocks = []
               , symbols = commonSymbols <> authoritySymbols
               , proof = Open nextSk
               , proofCheck = Checked $ toPublic sk
               }

-- | Add a block to an existing biscuit.
addBlock :: Block
         -> Biscuit Open Checked
         -> IO (Biscuit Open Checked)
addBlock block b@Biscuit{..} = do
  let (blockSymbols, blockSerialized) = PB.encodeBlock <$> blockToPb symbols block
      Open p = proof
  (signedBlock, nextSk) <- signBlock p blockSerialized
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , symbols = symbols <> blockSymbols
           , proof = Open nextSk
           }

-- | Add a block to an existing biscuit, without checking its signatures first
addBlockUnchecked :: Block -> Biscuit Open NotChecked -> IO (Biscuit Open NotChecked)
addBlockUnchecked block b@Biscuit{..} = do
  let (blockSymbols, blockSerialized) = PB.encodeBlock <$> blockToPb symbols block
      Open p = proof
  (signedBlock, nextSk) <- signBlock p blockSerialized
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , symbols = symbols <> blockSymbols
           , proof = Open nextSk
           }

class BiscuitProof a where
  toPossibleProofs :: a -> OpenOrSealed

instance BiscuitProof OpenOrSealed where
  toPossibleProofs = id
instance BiscuitProof Sealed where
  toPossibleProofs (Sealed sig) = SealedProof sig
instance BiscuitProof Open where
  toPossibleProofs (Open sk) = OpenProof sk

-- | Serialize a biscuit to a raw bytestring
serializeBiscuit :: BiscuitProof p => Biscuit p Checked -> ByteString
serializeBiscuit Biscuit{..} =
  let proofField = case toPossibleProofs proof of
          SealedProof sig -> PB.ProofSignature $ PB.putField (convert sig)
          OpenProof   sk  -> PB.ProofSecret $ PB.putField (convert sk)
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

data BiscuitWrapper
  = BiscuitWrapper
  { wAuthority :: SignedBlock
  , wBlocks    :: [SignedBlock]
  , wProof     :: OpenOrSealed
  , wRootKeyId :: Maybe Int
  }

parseBiscuitWrapper :: ByteString -> Either ParseError BiscuitWrapper
parseBiscuitWrapper bs = do
  blockList <- first (InvalidProtobufSer True) $ PB.decodeBlockList bs
  let rootKeyId = fromEnum <$> PB.getField (PB.rootKeyId blockList)
  signedAuthority <- first (InvalidProtobuf True) $ pbToSignedBlock $ PB.getField $ PB.authority blockList
  signedBlocks    <- first (InvalidProtobuf True) $ traverse pbToSignedBlock $ PB.getField $ PB.blocks blockList
  proof         <- first (InvalidProtobuf True) $ pbToProof $ PB.getField $ PB.proof blockList

  pure $ BiscuitWrapper
    { wAuthority = signedAuthority
    , wBlocks = signedBlocks
    , wProof  = either SealedProof
                       OpenProof
                       proof
    , wRootKeyId = rootKeyId
    , ..
    }

parseBlocks :: BiscuitWrapper -> Either ParseError (Symbols, NonEmpty ParsedSignedBlock)
parseBlocks BiscuitWrapper{..} = do
  let toRawSignedBlock (payload, sig, pk') = do
        pbBlock <- first (InvalidProtobufSer False) $ PB.decodeBlock payload
        pure ((payload, pbBlock), sig, pk')

  rawAuthority <- toRawSignedBlock wAuthority
  rawBlocks    <- traverse toRawSignedBlock wBlocks

  let symbols = extractSymbols commonSymbols $ (\((_, p), _, _) -> p) <$> rawAuthority : rawBlocks

  authority <- rawSignedBlockToParsedSignedBlock symbols rawAuthority
  blocks    <- traverse (rawSignedBlockToParsedSignedBlock symbols) rawBlocks
  pure (symbols, authority :| blocks)

parseBiscuitUnchecked :: ByteString -> Either ParseError (Biscuit OpenOrSealed NotChecked)
parseBiscuitUnchecked bs = do
  w@BiscuitWrapper{..} <- parseBiscuitWrapper bs
  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Biscuit { rootKeyId = wRootKeyId
                 , proof = wProof
                 , proofCheck = NotChecked
                 , .. }

-- | Parse a biscuit from a raw bytestring, first checking its signature.
parseBiscuit :: PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Checked)
parseBiscuit pk bs = do
  w@BiscuitWrapper{..} <- parseBiscuitWrapper bs
  let allBlocks = NE.reverse $ wAuthority :| wBlocks
  let blocksResult = verifyBlocks allBlocks pk
  let proofResult = case wProof of
        SealedProof sig -> verifySignatureProof sig (NE.head allBlocks)
        OpenProof   sk  -> verifySecretProof sk     (NE.head allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures

  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Biscuit { rootKeyId = wRootKeyId
                 , proof = wProof
                 , proofCheck = Checked pk
                 , .. }

rawSignedBlockToParsedSignedBlock :: Symbols
                                  -> ((ByteString, PB.Block), Signature, PublicKey)
                                  -> Either ParseError ParsedSignedBlock
rawSignedBlockToParsedSignedBlock s ((payload, pbBlock), sig, pk) = do
  block   <- first (InvalidProtobuf False) $ pbToBlock s pbBlock
  pure ((payload, block), sig, pk)

getRevocationIds :: Biscuit OpenOrSealed Checked -> NonEmpty ByteString
getRevocationIds Biscuit{authority, blocks} =
  let allBlocks = authority :| blocks
      getRevocationId (_, sig, _) = convert sig
   in getRevocationId <$> allBlocks

-- | Given a provided verifier (a set of facts, rules, checks and policies),
-- and a public key, verify a biscuit:
--
-- - make sure the biscuit has been signed with the private key associated to the public key
-- - make sure the biscuit is valid for the provided verifier
verifyBiscuitWithLimits :: Limits -> Biscuit a Checked -> Verifier -> IO (Either ExecutionError VerificationSuccess)
verifyBiscuitWithLimits l Biscuit{..} verifier =
  let toBlockWithRevocationId ((_, block), sig, _) = (block, convert sig)
   in runVerifierWithLimits l
        (toBlockWithRevocationId authority)
        (toBlockWithRevocationId <$> blocks)
        verifier

-- | Same as `verifyBiscuitWithLimits`, but with default limits (1ms timeout, max 1000 facts, max 100 iterations)
verifyBiscuit :: Biscuit a Checked -> Verifier -> IO (Either ExecutionError VerificationSuccess)
verifyBiscuit = verifyBiscuitWithLimits defaultLimits

-- | Retrieve the `PublicKey` which was used to verify the `Biscuit` signatures
getCheckedBiscuitSignature :: Biscuit a Checked -> PublicKey
getCheckedBiscuitSignature Biscuit{proofCheck} =
  let Checked pk = proofCheck
   in pk
