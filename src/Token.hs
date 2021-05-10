{-# LANGUAGE NamedFieldPuns  #-}
{-# LANGUAGE RecordWildCards #-}
module Token
  ( Biscuit
  , mkBiscuit
  , addBlock
  ) where

import           Data.ByteString (ByteString)

import           Datalog.AST     (Block)
import           Sel             (Keypair (publicKey), PublicKey, Signature,
                                  aggregate, newKeypair, signBlock)

-- Protobuf serialization does not have a guaranteed deterministic behaviour,
-- so we need to keep the initial serialized payload around in order to compute
-- a new signature when adding a block.
type ExistingBlock = (ByteString, Block)

data Biscuit
  = Biscuit
  { authority :: ExistingBlock
  , blocks    :: [(ExistingBlock, PublicKey)]
  , signature :: Signature
  }

mkBiscuit :: Keypair -> Block -> IO Biscuit
mkBiscuit keypair authority = do
  let authoritySerialized = error "todo" -- protobuf
  signature <- signBlock keypair authoritySerialized
  pure $ Biscuit { authority = (authoritySerialized, authority)
                 , blocks = []
                 , signature
                 }

addBlock :: Block -> Biscuit -> IO Biscuit
addBlock newBlock b@Biscuit{..} = do
  let newBlockSerialized = error "todo" -- protobuf
  keypair <- newKeypair
  newSig <- signBlock keypair newBlockSerialized
  endSig <- aggregate signature newSig
  pure $ b { blocks = blocks <> [((newBlockSerialized, newBlock), publicKey keypair)]
           , signature = endSig
           }
