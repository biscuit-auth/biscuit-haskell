{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE FlexibleContexts #-}
module Biscuit where

#include "biscuit_auth.h"

{#context lib="libbiscuit_auth" #}

import Foreign.C.String
import Foreign.C.Types
import GHC.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import Data.ByteString.Internal
import Data.ByteString
import Data.Coerce (Coercible, coerce)
-- import C2HSImp

{#pointer *Biscuit foreign finalizer biscuit_free newtype#}
{#pointer *BiscuitBuilder foreign finalizer biscuit_builder_free newtype#}
{#pointer *BlockBuilder foreign finalizer block_builder_free newtype#}
{#pointer *KeyPair foreign finalizer key_pair_free newtype#}
{#pointer *PublicKey foreign finalizer public_key_free newtype#}
{#pointer *Verifier foreign finalizer verifier_free newtype#}

withCStringLen' :: String -> ((Ptr CUChar, CULong) -> IO a) -> IO a
withCStringLen' s f =
  let f' (ptr, int) = f (castPtr ptr, toEnum int)
   in withCStringLen s f'

withBSLen :: ByteString -> ((Ptr CUChar, CULong) -> IO a) -> IO a
withBSLen bs f = useAsCStringLen bs $ \(buf, int) -> do
  print @CULong (toEnum int)
  f (castPtr buf, toEnum int)

peekN :: Coercible (ForeignPtr b) b => Ptr b -> IO b
peekN = fmap coerce . newForeignPtr_

getErrorMessage :: IO (Maybe String)
getErrorMessage = do
  res <- {#call error_message #}
  if res == nullPtr
    then pure Nothing
    else Just <$> peekCString res

serialize :: Biscuit
          -> IO ByteString
serialize = flip withBiscuit $ \b -> do
  size <- fromIntegral <$> {#call biscuit_serialized_size #} b
  allocaBytes size $ \buf -> do
    {#call biscuit_serialize #} b buf
    packCStringLen (castPtr buf, size)

serializeKeyPair :: KeyPair
                 -> IO ByteString
serializeKeyPair = flip withKeyPair $ \kp ->
   allocaBytes 32 $ \buf -> do
     {#call key_pair_serialize #} kp buf
     packCStringLen (castPtr buf, 32)

deserializeKeyPair :: ByteString
                   -> IO (Maybe KeyPair)
deserializeKeyPair = flip useAsCString $ \buf -> do
     kp <- {#call key_pair_deserialize #} (castPtr buf)
     if kp /= nullPtr
       then Just <$> peekN kp
       else pure Nothing

serializePublicKey :: PublicKey
                   -> IO ByteString
serializePublicKey = flip withPublicKey $ \pk ->
   allocaBytes 32 $ \buf -> do
     {#call public_key_serialize #} pk buf
     packCStringLen (castPtr buf, 32)

deserializePublicKey :: ByteString
                     -> IO (Maybe PublicKey)
deserializePublicKey = flip useAsCString $ \buf -> do
     pk <- {#call public_key_deserialize #} (castPtr buf)
     if pk /= nullPtr
       then Just <$> peekN pk
       else pure Nothing

{#fun error_message as ^ {} -> `String' peekCString* #}

{#fun key_pair_new as ^ { withBSLen* `ByteString'& } -> `KeyPair' #}

{#fun key_pair_public as ^ { withKeyPair* `KeyPair' } -> `PublicKey' #}

{#fun biscuit_builder as ^ { withKeyPair* `KeyPair' } -> `BiscuitBuilder' #}

{#fun biscuit_builder_add_authority_fact as ^ { `BiscuitBuilder', withCString* `String' } -> `Bool' #}

{#fun biscuit_builder_add_authority_caveat as ^ { `BiscuitBuilder', withCString* `String' } -> `Bool' #}

{#fun biscuit_builder_build as ^ { `BiscuitBuilder', withBSLen* `ByteString'& } -> `Biscuit' #}

{#fun biscuit_from as ^ { withBSLen* `ByteString'& } -> `Biscuit' #}

{#fun biscuit_verify as ^ { `Biscuit', `PublicKey' } -> `Verifier' #}

{#fun verifier_add_caveat as ^ { `Verifier', withCString* `String' } -> `Bool' #}

{#fun verifier_verify as ^ { `Verifier' } -> `Bool' #}

{#fun verifier_print as ^ { `Verifier' } -> `String' peekCString* #}
