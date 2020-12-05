{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
module Inline where

import           Data.ByteString       (ByteString, copy, packCStringLen)
import           Data.Text             (Text)
import           Foreign.Marshal.Alloc
import qualified Language.C.Inline     as C

type KeyPair = (ByteString, ByteString)
type Biscuit = ByteString

data Block = Block
  { facts   :: [Text]
  , rules   :: [Text]
  , caveats :: [Text]
  }

data BiscuitSpec = BiscuitSpec
  { authority  :: Block
  , blocks     :: [Block]
  , privateKey :: ByteString
  }

C.context (C.baseCtx <> C.bsCtx)

C.include "biscuit_auth.h"

genKp :: ByteString
      -> IO KeyPair
genKp seed =
  allocaBytes 32 $ \keyPairBuf ->
    allocaBytes 32 $ \pubKeyBuf -> do
      [C.block|
        void {
          KeyPair * kp = key_pair_new($bs-ptr:seed, $bs-len:seed);
          PublicKey * pubkey = key_pair_public(kp);

          key_pair_serialize(kp,       $(char* keyPairBuf));
          public_key_serialize(pubkey, $(char* pubKeyBuf));

          // public_key_free(pubkey);
          // key_pair_free(kp);

          return;
        }
      |]
      (,) <$> packCStringLen (keyPairBuf, 32) <*> packCStringLen (pubKeyBuf, 32)
