{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE RecordWildCards    #-}
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
  , rootKeyId
  , symbols
  , authority
  , blocks
  , proof
  , proofCheck
  , ParseError (..)
  , ExistingBlock
  , ParsedSignedBlock
  -- $openOrSealed
  , OpenOrSealed
  , Open
  , Sealed
  , BiscuitProof (..)
  , Checked
  , NotChecked
  , mkBiscuit
  , addBlock
  , addBlockUnchecked
  , BiscuitEncoding (..)
  , ParserConfig (..)
  , parseBiscuitUnchecked
  , parseBiscuitWith
  , serializeBiscuit
  , verifyBiscuit
  , verifyBiscuitWithLimits
  , fromOpen
  , fromSealed
  , asOpen
  , asSealed
  , seal
  , sealUnchecked

  , getRevocationIds
  , getCheckedBiscuitSignature

  ) where

import           Control.Monad                       (join, when)
import           Data.Bifunctor                      (first)
import           Data.ByteString                     (ByteString)
import qualified Data.ByteString.Base64.URL          as B64
import           Data.List.NonEmpty                  (NonEmpty ((:|)))
import qualified Data.List.NonEmpty                  as NE
import           Data.Set                            (Set)
import qualified Data.Set                            as Set

import           Auth.Biscuit.Crypto                 (PublicKey, SecretKey,
                                                      Signature, SignedBlock,
                                                      convert,
                                                      getSignatureProof,
                                                      signBlock, toPublic,
                                                      verifyBlocks,
                                                      verifySecretProof,
                                                      verifySignatureProof)
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
                                                      pbToSignedBlock,
                                                      signedBlockToPb)

-- | Protobuf serialization does not have a guaranteed deterministic behaviour,
-- so we need to keep the initial serialized payload around in order to compute
-- a new signature when adding a block.
type ExistingBlock = (ByteString, Block)
type ParsedSignedBlock = (ExistingBlock, Signature, PublicKey)

-- $openOrSealed
--
-- Biscuit tokens can be /open/ (capable of being attenuated further) or
-- /sealed/ (not capable of being attenuated further). Some operations
-- like verification work on both kinds, while others (like attenuation)
-- only work on a single kind. The 'OpenOrSealed', 'Open' and 'Sealed' trio
-- represents the different possibilities. 'OpenOrSealed' is usually obtained
-- through parsing, while 'Open' is obtained by creating a new biscuit (or
-- attenuating an existing one), and 'Sealed' is obtained by sealing an open
-- biscuit

-- | This datatype represents the final proof of a biscuit, which can be either
-- /open/ or /sealed/. This is the typical state of a biscuit that's been parsed.
data OpenOrSealed
  = SealedProof Signature
  | OpenProof SecretKey
  deriving (Eq, Show)

-- | This datatype represents the final proof of a biscuit statically known to be
-- /open/ (capable of being attenuated further). In that case the proof is a secret
-- key that can be used to sign a new block.
newtype Open = Open SecretKey

-- | This datatype represents the final proof of a biscuit statically known to be
-- /sealed/ (not capable of being attenuated further). In that case the proof is a
-- signature proving that the party who sealed the token did know the last secret
-- key.
newtype Sealed = Sealed Signature

-- | This class allows functions working on both open and sealed biscuits to accept
-- indifferently 'OpenOrSealed', 'Open' or 'Sealed' biscuits. It has no laws, it only
-- projects 'Open' and 'Sealed' to the general 'OpenOrSealed' case.
class BiscuitProof a where
  toPossibleProofs :: a -> OpenOrSealed

instance BiscuitProof OpenOrSealed where
  toPossibleProofs = id
instance BiscuitProof Sealed where
  toPossibleProofs (Sealed sig) = SealedProof sig
instance BiscuitProof Open where
  toPossibleProofs (Open sk) = OpenProof sk

-- $checkedOrUnchecked
--
-- The default parsing mechanism for biscuits checks the signature before parsing the blocks
-- contents (this reduces the attack surface, as only biscuits with a valid signature are parsed).
-- In some cases, we still want to operate on biscuits without knowing the public key necessary
-- to check signatures (eg for inspection, or for generically adding attenuation blocks). In that
-- case, we can have parsed tokens which signatures have /not/ been verified. In order to
-- accidentally forgetting to check signatures, parsed biscuits keep track of whether the
-- signatures have been checked with a dedicated type parameter, which can be instantiated with
-- two types: 'Checked' and 'NotChecked'. 'Checked' additionally keeps track of the 'PublicKey'
-- that has been used to verify the signatures.

-- | Proof that a biscuit had its signatures verified with the carried root 'PublicKey'
newtype Checked = Checked PublicKey
  deriving stock (Eq, Show)

-- | Marker that a biscuit was parsed without having its signatures verified. Such a biscuit
-- cannot be trusted yet.
data NotChecked = NotChecked
  deriving stock (Eq, Show)

-- | A parsed biscuit. The @proof@ type param can be one of 'Open', 'Sealed' or 'OpenOrSealed'.
-- It describes whether a biscuit is open to further attenuation, or sealed and not modifyable
-- further.
--
-- The @check@ type param can be either 'Checked' or 'NotChecked' and keeps track of whether
-- the blocks signatures (and final proof) have been verified with a given root 'PublicKey'.
--
-- The constructor is not exposed in order to ensure that 'Biscuit' values can only be created
-- by trusted code paths.
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
  -- ^ The final proof allowing to check the validity of a biscuit
  , proofCheck :: check
  -- ^ A value that keeps track of whether the biscuit signatures have been checked or not.
  }
  deriving (Eq, Show)

-- | Turn a 'Biscuit' statically known to be 'Open' into a more generic 'OpenOrSealed' 'Biscuit'
-- (essentially /forgetting/ about the fact it's 'Open')
fromOpen :: Biscuit Open Checked -> Biscuit OpenOrSealed Checked
fromOpen b@Biscuit{proof = Open p } = b { proof = OpenProof p }

-- | Turn a 'Biscuit' statically known to be 'Sealed' into a more generic 'OpenOrSealed' 'Biscuit'
-- (essentially /forgetting/ about the fact it's 'Sealed')
fromSealed :: Biscuit Sealed Checked -> Biscuit OpenOrSealed Checked
fromSealed b@Biscuit{proof = Sealed p } = b { proof = SealedProof p }

asSealed :: Biscuit OpenOrSealed Checked -> Maybe (Biscuit Sealed Checked)
asSealed b@Biscuit{proof} = case proof of
  SealedProof p -> Just $ b { proof = Sealed p }
  _             -> Nothing

asOpen :: Biscuit OpenOrSealed Checked -> Maybe (Biscuit Open Checked)
asOpen b@Biscuit{proof}   = case proof of
  OpenProof p -> Just $ b { proof = Open p }
  _           -> Nothing

toParsedSignedBlock :: Block -> SignedBlock -> ParsedSignedBlock
toParsedSignedBlock block (serializedBlock, sig, pk) = ((serializedBlock, block), sig, pk)

-- | Create a new biscuit with the provided authority block. Such a biscuit is 'Open' to
-- further attenuation.
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

addBlock' :: Block
          -> Biscuit Open check
          -> IO (Biscuit Open check)
addBlock' block b@Biscuit{..} = do
  let (blockSymbols, blockSerialized) = PB.encodeBlock <$> blockToPb symbols block
      Open p = proof
  (signedBlock, nextSk) <- signBlock p blockSerialized
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , symbols = symbols <> blockSymbols
           , proof = Open nextSk
           }

-- | Add a block to an existing biscuit. Only 'Open' biscuits can be attenuated; the
-- newly created biscuit is 'Open' as well.
addBlock :: Block
         -> Biscuit Open Checked
         -> IO (Biscuit Open Checked)
addBlock = addBlock'

-- | Add a block to an existing biscuit, without checking its signatures first
addBlockUnchecked :: Block -> Biscuit Open NotChecked -> IO (Biscuit Open NotChecked)
addBlockUnchecked = addBlock'

sealBiscuit' :: Biscuit Open check -> Biscuit Sealed check
sealBiscuit' b@Biscuit{..} =
  let Open sk = proof
      ((lastPayload, _), lastSig, lastPk) = NE.last $ authority :| blocks
      newProof = Sealed $ getSignatureProof (lastPayload, lastSig, lastPk) sk
   in b { proof = newProof }

seal :: Biscuit Open Checked -> Biscuit Sealed Checked
seal = sealBiscuit'

sealUnchecked :: Biscuit Open NotChecked -> Biscuit Sealed NotChecked
sealUnchecked = sealBiscuit'

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
toPBSignedBlock ((block, _), sig, pk) = signedBlockToPb (block, sig, pk)

-- | Errors that can happen when parsing a biscuit. Since complete parsing of a biscuit
-- requires a signature check, an invalid signature check is a parsing error
data ParseError
  = InvalidHexEncoding
  -- ^ The provided ByteString is not hex-encoded
  | InvalidB64Encoding
  -- ^ The provided ByteString is not base64-encoded
  | InvalidProtobufSer Bool String
  -- ^ The provided ByteString does not contain properly serialized protobuf values
  | InvalidProtobuf Bool String
  -- ^ The bytestring was correctly deserialized from protobuf, but the values can't be turned into a proper biscuit
  | InvalidSignatures
  -- ^ The signatures were invalid
  | InvalidProof
  -- ^ The biscuit final proof was invalid
  | RevokedBiscuit
  -- ^ The biscuit has been revoked
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

checkRevocation :: Applicative m
                => (Set ByteString -> m Bool)
                -> BiscuitWrapper
                -> m (Either ParseError BiscuitWrapper)
checkRevocation isRevoked bw@BiscuitWrapper{wAuthority,wBlocks} =
  let getRevocationId (_, sig, _) = convert sig
      revocationIds = getRevocationId <$> wAuthority :| wBlocks
      keepIfNotRevoked True  = Left RevokedBiscuit
      keepIfNotRevoked False = Right bw
   in keepIfNotRevoked <$> isRevoked (Set.fromList $ NE.toList revocationIds)

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

parseBiscuit' :: PublicKey -> BiscuitWrapper -> Either ParseError (Biscuit OpenOrSealed Checked)
parseBiscuit' pk w@BiscuitWrapper{..} = do
  let allBlocks = wAuthority :| wBlocks
  let blocksResult = verifyBlocks allBlocks pk
  let proofResult = case wProof of
        SealedProof sig -> verifySignatureProof sig (NE.last allBlocks)
        OpenProof   sk  -> verifySecretProof sk     (NE.last allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures

  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Biscuit { rootKeyId = wRootKeyId
                 , proof = wProof
                 , proofCheck = Checked pk
                 , .. }

-- | Biscuits can be transmitted as raw bytes, or as base64-encoded text. This datatype
-- lets the parser know about the expected encoding.
data BiscuitEncoding
  = RawBytes
  | UrlBase64

-- | Parsing a biscuit involves various steps. This data type allows configuring those steps.
data ParserConfig m
  = ParserConfig
  { encoding     :: BiscuitEncoding
  -- ^ Is the biscuit base64-encoded, or is it raw binary?
  , isRevoked    :: Set ByteString -> m Bool
  -- ^ Has one of the token blocks been revoked?
  -- 'fromRevocationList' lets you build this function from a static revocation list
  , getPublicKey :: Maybe Int -> PublicKey
  -- ^ How to select the public key based on the token 'rootKeyId'
  }

parseBiscuitWith :: Applicative m
                 => ParserConfig m
                 -> ByteString
                 -> m (Either ParseError (Biscuit OpenOrSealed Checked))
parseBiscuitWith ParserConfig{..} bs =
  let input = case encoding of
        RawBytes  -> Right bs
        UrlBase64 -> first (const InvalidB64Encoding) . B64.decodeBase64 $ bs
      parsedWrapper = parseBiscuitWrapper =<< input
      wrapperToBiscuit w@BiscuitWrapper{wRootKeyId} =
        let pk = getPublicKey wRootKeyId
         in (parseBiscuit' pk =<<) <$> checkRevocation isRevoked w
   in join <$> traverse wrapperToBiscuit parsedWrapper

rawSignedBlockToParsedSignedBlock :: Symbols
                                  -> ((ByteString, PB.Block), Signature, PublicKey)
                                  -> Either ParseError ParsedSignedBlock
rawSignedBlockToParsedSignedBlock s ((payload, pbBlock), sig, pk) = do
  block   <- first (InvalidProtobuf False) $ pbToBlock s pbBlock
  pure ((payload, block), sig, pk)

-- | Extract the list of revocation ids from a biscuit.
-- To reject revoked biscuits, please use 'parseWith' instead. This function
-- should only be used for debugging purposes.
getRevocationIds :: Biscuit proof check -> NonEmpty ByteString
getRevocationIds Biscuit{authority, blocks} =
  let allBlocks = authority :| blocks
      getRevocationId (_, sig, _) = convert sig
   in getRevocationId <$> allBlocks

-- | Generic version of 'verifyBiscuitWithLimits' which takes custom 'Limits'.
verifyBiscuitWithLimits :: Limits -> Biscuit a Checked -> Verifier -> IO (Either ExecutionError VerificationSuccess)
verifyBiscuitWithLimits l Biscuit{..} verifier =
  let toBlockWithRevocationId ((_, block), sig, _) = (block, convert sig)
   in runVerifierWithLimits l
        (toBlockWithRevocationId authority)
        (toBlockWithRevocationId <$> blocks)
        verifier

-- | Given a biscuit with a checked signature and a verifier (a set of facts, rules, checks
-- and policies), verify a biscuit:
--
-- - all the checks declared in the biscuit and verifier must pass
-- - an allow policy provided by the verifier has to match (policies are tried in order)
-- - the datalog computation must happen in an alloted time, with a capped number of generated
--   facts and a capped number of iterations
--
-- checks and policies declared in the verifier only operate on the authority block. Facts
-- declared by extra blocks cannot interfere with previous blocks.
--
-- Specific runtime limits can be specified by using 'verifyBiscuitWithLimits'. 'verifyBiscuit'
-- uses a set of defaults defined in 'defaultLimits'.
verifyBiscuit :: Biscuit proof Checked -> Verifier -> IO (Either ExecutionError VerificationSuccess)
verifyBiscuit = verifyBiscuitWithLimits defaultLimits

-- | Retrieve the `PublicKey` which was used to verify the `Biscuit` signatures
getCheckedBiscuitSignature :: Biscuit a Checked -> PublicKey
getCheckedBiscuitSignature Biscuit{proofCheck} =
  let Checked pk = proofCheck
   in pk
