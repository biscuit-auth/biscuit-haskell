{-# LANGUAGE NamedFieldPuns  #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections   #-}
module Token
  ( Biscuit (..)
  , ParseError (..)
  , VerificationError (..)
  , mkBiscuit
  , addBlock
  , checkBiscuitSignature
  , parseBiscuit
  , serializeBiscuit
  , verifyBiscuit
  ) where

import           Control.Monad           (when)
import           Control.Monad.Except    (runExceptT, throwError)
import           Control.Monad.IO.Class  (liftIO)
import           Data.Bifunctor          (first)
import           Data.ByteString         (ByteString)
import           Data.Either.Combinators (maybeToRight)
import           Data.List.NonEmpty      (NonEmpty ((:|)))

import           Datalog.AST             (Block, Verifier)
import           Datalog.Executor        (runVerifier)
import qualified Proto                   as PB
import           ProtoBufAdapter         (Symbols, blockToPb, commonSymbols,
                                          extractSymbols, pbToBlock)
import           Sel                     (Keypair (publicKey), PublicKey,
                                          Signature (..), aggregate, newKeypair,
                                          parsePublicKey, serializePublicKey,
                                          signBlock, verifySignature)

-- Protobuf serialization does not have a guaranteed deterministic behaviour,
-- so we need to keep the initial serialized payload around in order to compute
-- a new signature when adding a block.
type ExistingBlock = (ByteString, Block)

data Biscuit
  = Biscuit
  { symbols   :: Symbols
  , authority :: (PublicKey, ExistingBlock)
  , blocks    :: [(PublicKey, ExistingBlock)]
  , signature :: Signature
  }
  deriving (Eq, Show)

-- | Create a new biscuit with the provided authority block
mkBiscuit :: Keypair -> Block -> IO Biscuit
mkBiscuit keypair authority = do
  let authorityPub = publicKey keypair
      (s, authoritySerialized) = PB.encodeBlock <$> (blockToPb commonSymbols 0 authority)
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
  let (s, newBlockSerialized) = PB.encodeBlock <$> (blockToPb symbols (length blocks) newBlock)
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

data ParseError
  = InvalidHexEncoding
  | InvalidB64Encoding
  | InvalidProtobufSer String
  | InvalidProtobuf String
  deriving (Eq, Show)

parseBiscuit :: ByteString -> Either ParseError Biscuit
parseBiscuit bs = do
  blockList <- first InvalidProtobufSer $ PB.decodeBlockList bs
  let pbBlocks    = PB.getField $ PB.blocks    blockList
      pbKeys      = PB.getField $ PB.keys      blockList
      pbAuthority = PB.getField $ PB.authority blockList
      pbSignature = PB.getField $ PB.signature blockList
  when ((length pbBlocks) + 1 /= length pbKeys) $ Left (InvalidProtobufSer $ "Length mismatch " <> show (length pbBlocks, length pbKeys))
  rawAuthority <- first InvalidProtobufSer $ PB.decodeBlock pbAuthority
  rawBlocks    <- traverse (first InvalidProtobufSer . PB.decodeBlock) pbBlocks
  let s = extractSymbols commonSymbols $ rawAuthority : rawBlocks


  parsedAuthority <- (pbAuthority,) <$> (blockFromPB s) rawAuthority
  parsedBlocks    <- zip pbBlocks <$> traverse (blockFromPB s) rawBlocks
  parsedKeys      <- maybeToRight (InvalidProtobufSer "Invalid pubkeys") $ traverse parsePublicKey pbKeys
  let blocks = zip (drop 1 parsedKeys) parsedBlocks
      authority = (head parsedKeys, parsedAuthority)
      symbols = s
      signature = Signature { parameters = PB.getField $ PB.parameters pbSignature
                            , z = PB.getField $ PB.z pbSignature
                            }
  pure Biscuit{..}

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
       { authority = PB.putField $ authorityBs
       , blocks    = PB.putField $ blocksBs
       , keys      = PB.putField $ keys
       , signature = PB.putField $ sigPb
       }

blockFromPB :: Symbols -> PB.Block -> Either ParseError Block
blockFromPB s pbBlock  = first InvalidProtobuf $ pbToBlock s pbBlock

data VerificationError
  = SignatureError
  | DatalogError
  deriving (Eq, Show)

-- | Given a provided verifier (a set of facts, rules, checks and policies),
-- and a public key, verify a biscuit
-- - make sure the biscuit has been signed with the private key associated to the public key
-- - make sure the biscuit is valid for the provided verifier
verifyBiscuit :: Biscuit -> Verifier -> PublicKey -> IO (Either VerificationError ())
verifyBiscuit b@Biscuit{..} verifier pub = runExceptT $ do
  sigCheck <- liftIO $ checkBiscuitSignature b pub
  when (not sigCheck) $ throwError SignatureError
  let authorityBlock = snd . snd $ authority
      attBlocks = snd . snd <$> blocks
  verifResult <- liftIO $ runVerifier authorityBlock attBlocks verifier
  case verifResult of
    Left ()  -> throwError DatalogError
    Right () -> pure ()
