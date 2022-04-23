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
  , AuthorizedBiscuit (..)
  -- $openOrSealed
  , OpenOrSealed
  , Open
  , Sealed
  , BiscuitProof (..)
  , Verified
  , Unverified
  , mkBiscuit
  , mkBiscuitWith
  , addBlock
  , BiscuitEncoding (..)
  , ParserConfig (..)
  , parseBiscuitWith
  , parseBiscuitUnverified
  , checkBiscuitSignatures
  , serializeBiscuit
  , authorizeBiscuit
  , authorizeBiscuitWithLimits
  , fromOpen
  , fromSealed
  , asOpen
  , asSealed
  , seal

  , getRevocationIds
  , getVerifiedBiscuitPublicKey

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
import           Auth.Biscuit.Datalog.AST            (Authorizer, Block)
import           Auth.Biscuit.Datalog.Executor       (ExecutionError, Limits,
                                                      defaultLimits)
import           Auth.Biscuit.Datalog.ScopedExecutor (AuthorizationSuccess,
                                                      runAuthorizerWithLimits)
import qualified Auth.Biscuit.Proto                  as PB
import           Auth.Biscuit.ProtoBufAdapter        (blockToPb, extractSymbols,
                                                      pbToBlock, pbToProof,
                                                      pbToSignedBlock,
                                                      signedBlockToPb)
import           Auth.Biscuit.Symbols

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
  deriving stock (Eq, Show)

-- | This datatype represents the final proof of a biscuit statically known to be
-- /sealed/ (not capable of being attenuated further). In that case the proof is a
-- signature proving that the party who sealed the token did know the last secret
-- key.
newtype Sealed = Sealed Signature
  deriving stock (Eq, Show)

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

-- $verifiedOrUnverified
--
-- The default parsing mechanism for biscuits checks the signature before parsing the blocks
-- contents (this reduces the attack surface, as only biscuits with a valid signature are parsed).
-- In some cases, we still want to operate on biscuits without knowing the public key necessary
-- to check signatures (eg for inspection, or for generically adding attenuation blocks). In that
-- case, we can have parsed tokens which signatures have /not/ been verified. In order to
-- accidentally forgetting to check signatures, parsed biscuits keep track of whether the
-- signatures have been verified with a dedicated type parameter, which can be instantiated with
-- two types: 'Verified' and 'Unverified'. 'Verified' additionally keeps track of the 'PublicKey'
-- that has been used to verify the signatures.

-- | Proof that a biscuit had its signatures verified with the carried root 'PublicKey'
newtype Verified = Verified PublicKey
  deriving stock (Eq, Show)

-- | Marker that a biscuit was parsed without having its signatures verified. Such a biscuit
-- cannot be trusted yet.
data Unverified = Unverified
  deriving stock (Eq, Show)

-- | A parsed biscuit. The @proof@ type param can be one of 'Open', 'Sealed' or 'OpenOrSealed'.
-- It describes whether a biscuit is open to further attenuation, or sealed and not modifyable
-- further.
--
-- The @check@ type param can be either 'Verified' or 'Unverified' and keeps track of whether
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
  -- ^ A value that keeps track of whether the biscuit signatures have been verified or not.
  }
  deriving (Eq, Show)

-- | Turn a 'Biscuit' statically known to be 'Open' into a more generic 'OpenOrSealed' 'Biscuit'
-- (essentially /forgetting/ about the fact it's 'Open')
fromOpen :: Biscuit Open check -> Biscuit OpenOrSealed check
fromOpen b@Biscuit{proof = Open p } = b { proof = OpenProof p }

-- | Turn a 'Biscuit' statically known to be 'Sealed' into a more generic 'OpenOrSealed' 'Biscuit'
-- (essentially /forgetting/ about the fact it's 'Sealed')
fromSealed :: Biscuit Sealed check -> Biscuit OpenOrSealed check
fromSealed b@Biscuit{proof = Sealed p } = b { proof = SealedProof p }

-- | Try to turn a 'Biscuit' that may be open or sealed into a biscuit that's statically known
-- to be 'Sealed'.
asSealed :: Biscuit OpenOrSealed check -> Maybe (Biscuit Sealed check)
asSealed b@Biscuit{proof} = case proof of
  SealedProof p -> Just $ b { proof = Sealed p }
  _             -> Nothing

-- | Try to turn a 'Biscuit' that may be open or sealed into a biscuit that's statically known
-- to be 'Open'.
asOpen :: Biscuit OpenOrSealed check -> Maybe (Biscuit Open check)
asOpen b@Biscuit{proof}   = case proof of
  OpenProof p -> Just $ b { proof = Open p }
  _           -> Nothing

toParsedSignedBlock :: Block -> SignedBlock -> ParsedSignedBlock
toParsedSignedBlock block (serializedBlock, sig, pk) = ((serializedBlock, block), sig, pk)

-- | Create a new biscuit with the provided authority block. Such a biscuit is 'Open' to
-- further attenuation.
mkBiscuit :: SecretKey -> Block -> IO (Biscuit Open Verified)
mkBiscuit = mkBiscuitWith Nothing

-- | Create a new biscuit with the provided authority block and root key id. Such a biscuit is 'Open' to
-- further attenuation.
mkBiscuitWith :: Maybe Int -> SecretKey -> Block -> IO (Biscuit Open Verified)
mkBiscuitWith rootKeyId sk authority = do
  let (authoritySymbols, authoritySerialized) = PB.encodeBlock <$> blockToPb newSymbolTable authority
  (signedBlock, nextSk) <- signBlock sk authoritySerialized
  pure Biscuit { rootKeyId
               , authority = toParsedSignedBlock authority signedBlock
               , blocks = []
               , symbols = addFromBlock newSymbolTable authoritySymbols
               , proof = Open nextSk
               , proofCheck = Verified $ toPublic sk
               }

-- | Add a block to an existing biscuit. Only 'Open' biscuits can be attenuated; the
-- newly created biscuit is 'Open' as well.
addBlock :: Block
         -> Biscuit Open check
         -> IO (Biscuit Open check)
addBlock block b@Biscuit{..} = do
  let (blockSymbols, blockSerialized) = PB.encodeBlock <$> blockToPb symbols block
      Open p = proof
  (signedBlock, nextSk) <- signBlock p blockSerialized
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , symbols = addFromBlock symbols blockSymbols
           , proof = Open nextSk
           }

-- | Turn an 'Open' biscuit into a 'Sealed' one, preventing it from being attenuated
-- further. A 'Sealed' biscuit cannot be turned into an 'Open' one.
seal :: Biscuit Open check -> Biscuit Sealed check
seal b@Biscuit{..} =
  let Open sk = proof
      ((lastPayload, _), lastSig, lastPk) = NE.last $ authority :| blocks
      newProof = Sealed $ getSignatureProof (lastPayload, lastSig, lastPk) sk
   in b { proof = newProof }

-- | Serialize a biscuit to a raw bytestring
serializeBiscuit :: BiscuitProof p => Biscuit p Verified -> ByteString
serializeBiscuit Biscuit{..} =
  let proofField = case toPossibleProofs proof of
          SealedProof sig -> PB.ProofSignature $ PB.putField (convert sig)
          OpenProof   sk  -> PB.ProofSecret $ PB.putField (convert sk)
   in PB.encodeBlockList PB.Biscuit
        { rootKeyId = PB.putField $ fromIntegral <$> rootKeyId
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

  let symbols = extractSymbols $ (\((_, p), _, _) -> p) <$> rawAuthority : rawBlocks

  authority <- rawSignedBlockToParsedSignedBlock symbols rawAuthority
  blocks    <- traverse (rawSignedBlockToParsedSignedBlock symbols) rawBlocks
  pure (symbols, authority :| blocks)

-- | Parse a biscuit without performing any signatures check. This function is intended to
-- provide tooling (eg adding a block, or inspecting a biscuit) without having to verify
-- its signatures. Running an 'Authorizer' is not possible without checking signatures.
-- 'checkBiscuitSignatures' allows a delayed signature check. For normal auth workflows,
-- please use 'parseWith' (or 'parse', or 'parseB64') instead, as they check signatures
-- before completely parsing the biscuit.
parseBiscuitUnverified :: ByteString -> Either ParseError (Biscuit OpenOrSealed Unverified)
parseBiscuitUnverified bs = do
  w@BiscuitWrapper{..} <- parseBiscuitWrapper bs
  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Biscuit { rootKeyId = wRootKeyId
                 , proof = wProof
                 , proofCheck = Unverified
                 , .. }

parseBiscuit' :: PublicKey -> BiscuitWrapper -> Either ParseError (Biscuit OpenOrSealed Verified)
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
                 , proofCheck = Verified pk
                 , .. }

-- | Check the signatures (and final proof) of an already parsed biscuit. These checks normally
-- happen during the parsing phase, but can be delayed (or even ignored) in some cases. This
-- fuction allows to turn a 'Unverified' 'Biscuit' into a 'Verified' one after it has been parsed
-- with 'parseBiscuitUnverified'.
checkBiscuitSignatures :: BiscuitProof proof
                       => (Maybe Int -> PublicKey)
                       -> Biscuit proof Unverified
                       -> Either ParseError (Biscuit proof Verified)
checkBiscuitSignatures getPublicKey b@Biscuit{..} = do
  let pk = getPublicKey rootKeyId
      toSignedBlock ((payload, _), sig, nextPk) = (payload, sig, nextPk)
      allBlocks = toSignedBlock <$> (authority :| blocks)
      blocksResult = verifyBlocks allBlocks pk
      proofResult = case toPossibleProofs proof of
        SealedProof sig -> verifySignatureProof sig (NE.last allBlocks)
        OpenProof   sk  -> verifySecretProof sk     (NE.last allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures
  pure $ b { proofCheck = Verified pk }

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
                 -> m (Either ParseError (Biscuit OpenOrSealed Verified))
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

-- | Generic version of 'authorizeBiscuitWithLimits' which takes custom 'Limits'.
authorizeBiscuitWithLimits :: Limits -> Biscuit proof Verified -> Authorizer -> IO (Either ExecutionError (AuthorizedBiscuit proof))
authorizeBiscuitWithLimits l biscuit@Biscuit{..} authorizer =
  let toBlockWithRevocationId ((_, block), sig, _) = (block, convert sig)
      withBiscuit authorizationSuccess =
        AuthorizedBiscuit
          { authorizedBiscuit = biscuit
          , authorizationSuccess
          }
   in fmap withBiscuit <$>
        runAuthorizerWithLimits l
          (toBlockWithRevocationId authority)
          (toBlockWithRevocationId <$> blocks)
          authorizer

-- | Given a biscuit with a verified signature and an authorizer (a set of facts, rules, checks
-- and policies), verify a biscuit:
--
-- - all the checks declared in the biscuit and authorizer must pass
-- - an allow policy provided by the authorizer has to match (policies are tried in order)
-- - the datalog computation must happen in an alloted time, with a capped number of generated
--   facts and a capped number of iterations
--
-- checks and policies declared in the authorizer only operate on the authority block. Facts
-- declared by extra blocks cannot interfere with previous blocks.
--
-- Specific runtime limits can be specified by using 'authorizeBiscuitWithLimits'. 'authorizeBiscuit'
-- uses a set of defaults defined in 'defaultLimits'.
authorizeBiscuit :: Biscuit proof Verified -> Authorizer -> IO (Either ExecutionError (AuthorizedBiscuit proof))
authorizeBiscuit = authorizeBiscuitWithLimits defaultLimits

-- | Retrieve the `PublicKey` which was used to verify the `Biscuit` signatures
getVerifiedBiscuitPublicKey :: Biscuit a Verified -> PublicKey
getVerifiedBiscuitPublicKey Biscuit{proofCheck} =
  let Verified pk = proofCheck
   in pk

data AuthorizedBiscuit p
  = AuthorizedBiscuit
  { authorizedBiscuit    :: Biscuit p Verified
  , authorizationSuccess :: AuthorizationSuccess
  }
  deriving (Eq, Show)
