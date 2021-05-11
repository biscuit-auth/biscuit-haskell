{-# LANGUAGE NamedFieldPuns  #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections   #-}
module Token
  ( Biscuit (..)
  , ParseError (..)
  , mkBiscuit
  , addBlock
  , checkBiscuitSignature
  , parseBiscuit
  ) where

import           Control.Monad           (when)
import           Data.Bifunctor          (first)
import           Data.ByteString         (ByteString)
import           Data.Either.Combinators (maybeToRight)
import           Data.List.NonEmpty      (NonEmpty ((:|)))

import           Datalog.AST             (Block)
import qualified Proto                   as PB
import           ProtoBufAdapter         (Symbols, extractSymbols, pbToBlock)
import           Sel                     (Keypair (publicKey), PublicKey,
                                          Signature (..), aggregate, newKeypair,
                                          parsePublicKey, signBlock,
                                          verifySignature)

-- Protobuf serialization does not have a guaranteed deterministic behaviour,
-- so we need to keep the initial serialized payload around in order to compute
-- a new signature when adding a block.
type ExistingBlock = (ByteString, Block)

data Biscuit
  = Biscuit
  { authority :: ExistingBlock
  , blocks    :: [(PublicKey, ExistingBlock)]
  , signature :: Signature
  }
  deriving (Eq, Show)

-- | Create a new biscuit with the provided authority block
mkBiscuit :: Keypair -> Block -> IO Biscuit
mkBiscuit keypair authority = do
  let authoritySerialized = error "todo" -- protobuf
  signature <- signBlock keypair authoritySerialized
  pure $ Biscuit { authority = (authoritySerialized, authority)
                 , blocks = []
                 , signature
                 }

-- | Add a block to an existing biscuit. The block will be signed
-- with a randomly-generated keypair
addBlock :: Block -> Biscuit -> IO Biscuit
addBlock newBlock b@Biscuit{..} = do
  let newBlockSerialized = error "todo" -- protobuf
  keypair <- newKeypair
  newSig <- signBlock keypair newBlockSerialized
  endSig <- aggregate signature newSig
  pure $ b { blocks = blocks <> [(publicKey keypair, (newBlockSerialized, newBlock))]
           , signature = endSig
           }

-- | Only check a biscuit signature. This can be used to perform an early check, before
-- bothering with constructing a verifier.
checkBiscuitSignature :: Biscuit -> PublicKey -> IO Bool
checkBiscuitSignature Biscuit{..} publicKey =
  let publicKeysAndMessages = (publicKey, fst authority) :| (fmap fst <$> blocks)
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
  let s = extractSymbols $ rawAuthority : rawBlocks


  authority    <- (pbAuthority,) <$> (blockFromPB s) rawAuthority
  parsedBlocks <- zip pbBlocks <$> traverse (blockFromPB s) rawBlocks
  parsedKeys   <- maybeToRight (InvalidProtobufSer "Invalid pubkeys") $ traverse parsePublicKey pbKeys
  let blocks = zip (drop 1 parsedKeys) parsedBlocks
      signature = Signature { parameters = PB.getField $ PB.parameters pbSignature
                            , z = PB.getField $ PB.z pbSignature
                            }
  pure Biscuit{..}

blockFromPB :: Symbols -> PB.Block -> Either ParseError Block
blockFromPB s = first InvalidProtobuf . pbToBlock s
