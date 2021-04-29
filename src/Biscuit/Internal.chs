{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE FlexibleContexts #-}
{- HLint ignore -}
module Biscuit.Internal where

#include "biscuit_auth.h"

{#context lib="libbiscuit_auth" #}

import Foreign.C.String
import Foreign.C.Types
import GHC.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Data.ByteString.Internal
import Data.ByteString
import Data.Coerce (Coercible, coerce)

-- Pointers
{#pointer *Biscuit foreign finalizer biscuit_free newtype#}
{#pointer *BiscuitBuilder foreign finalizer biscuit_builder_free newtype#}
{#pointer *BlockBuilder foreign finalizer block_builder_free newtype#}
{#pointer *KeyPair foreign finalizer key_pair_free newtype#}
{#pointer *PublicKey foreign finalizer public_key_free newtype#}
{#pointer *Verifier foreign finalizer verifier_free newtype#}

instance Show Biscuit where
  show (Biscuit b) =  show b

-- Helper functions
withCStringLen' :: String -> ((Ptr CUChar, CULong) -> IO a) -> IO a
withCStringLen' s f =
  let f' (ptr, int) = f (castPtr ptr, toEnum int)
   in withCStringLen s f'

withBSLen :: ByteString -> ((Ptr CUChar, CULong) -> IO a) -> IO a
withBSLen bs f = useAsCStringLen bs $ \(buf, int) -> do
  f (castPtr buf, toEnum int)

peekMCString :: CString -> IO (Maybe String)
peekMCString ptr =
  if ptr == nullPtr
  then pure Nothing
  else Just <$> peekCString ptr

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
    _ <- {#call biscuit_serialize #} b buf
    packCStringLen (castPtr buf, size)

serializeKeyPair :: KeyPair
                 -> IO ByteString
serializeKeyPair = flip withKeyPair $ \kp ->
   allocaBytes 32 $ \buf -> do
     _ <- {#call key_pair_serialize #} kp buf
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
     _ <- {#call public_key_serialize #} pk buf
     packCStringLen (castPtr buf, 32)

deserializePublicKey :: ByteString
                     -> IO (Maybe PublicKey)
deserializePublicKey = flip useAsCString $ \buf -> do
     pk <- {#call public_key_deserialize #} (castPtr buf)
     if pk /= nullPtr
       then Just <$> peekN pk
       else pure Nothing

{#fun key_pair_new as ^ { withBSLen* `ByteString'& } -> `KeyPair' #}

{#fun key_pair_public as ^ { withKeyPair* `KeyPair' } -> `PublicKey' #}

{#fun biscuit_builder as ^ { withKeyPair* `KeyPair' } -> `BiscuitBuilder' #}

{#fun biscuit_builder_add_authority_fact as ^ { `BiscuitBuilder', withCString* `String' } -> `Bool' #}

{#fun biscuit_builder_add_authority_rule as ^ { `BiscuitBuilder', withCString* `String' } -> `Bool' #}

{#fun biscuit_builder_add_authority_check as ^ { `BiscuitBuilder', withCString* `String' } -> `Bool' #}

-- todo add missing _authority in C bindings
{#fun biscuit_builder_set_authority_context as ^ { `BiscuitBuilder', withCString* `String' } -> `Bool' #}

{#fun biscuit_block_count as ^ { `Biscuit' } -> `Int' #}

{#fun biscuit_block_fact_count as ^ { `Biscuit', `Int' } -> `Int' #}
{#fun biscuit_block_fact as ^ { `Biscuit', `Int', `Int' } -> `String' peekCString* #}

{#fun biscuit_block_rule_count as ^ { `Biscuit', `Int' } -> `Int' #}
{#fun biscuit_block_rule as ^ { `Biscuit', `Int', `Int' } -> `String' peekCString* #}

{#fun biscuit_block_check_count as ^ { `Biscuit', `Int' } -> `Int' #}
{#fun biscuit_block_check as ^ { `Biscuit', `Int', `Int' } -> `String' peekCString* #}

{#fun biscuit_block_context as ^ { `Biscuit', `Int' } -> `Maybe String' peekMCString* #}

{#fun biscuit_builder_build as ^ { `BiscuitBuilder', withBSLen* `ByteString'& } -> `Biscuit' #}

-- Adding blocks to an existing biscuit
{#fun biscuit_create_block as ^ { `Biscuit' } -> `BlockBuilder' #}
{#fun block_builder_add_fact as ^ { `BlockBuilder', withCString* `String' } -> `Bool' #}
{#fun block_builder_add_rule as ^ { `BlockBuilder', withCString* `String' } -> `Bool' #}
{#fun block_builder_add_check as ^ { `BlockBuilder', withCString* `String' } -> `Bool' #}
{#fun block_builder_set_context as ^ { `BlockBuilder', withCString* `String' } -> `Bool' #}
{#fun biscuit_append_block as ^ { `Biscuit', `BlockBuilder', `KeyPair', withBSLen* `ByteString'& } -> `Biscuit' #}

{#fun biscuit_from as ^ { withBSLen* `ByteString'& } -> `Biscuit' #}


-- Verifier
{#fun biscuit_verify as ^ { `Biscuit', `PublicKey' } -> `Verifier' #}
{#fun verifier_add_fact as ^ { `Verifier', withCString* `String' } -> `Bool' #}
{#fun verifier_add_rule as ^ { `Verifier', withCString* `String' } -> `Bool' #}
{#fun verifier_add_check as ^ { `Verifier', withCString* `String' } -> `Bool' #}
{#fun verifier_verify as ^ { `Verifier' } -> `Bool' #}

-- Printers
{#fun verifier_print as ^ { `Verifier' } -> `String' peekCString* #}
{#fun biscuit_print as ^ { `Biscuit' } -> `String' peekCString* #}

-- Error Management
{# enum ErrorKind {} deriving (Eq,Show) #}
{#fun error_kind as ^ {} -> `ErrorKind' #}
{#fun error_message as ^ {} -> `String' peekCString* #}
{#fun error_check_count as ^ {} -> `Int' #}
{#fun error_check_id as ^ {`Int'} -> `Int' #}
{#fun error_check_block_id as ^ {`Int'} -> `Int' #}
{#fun error_check_rule as ^ {`Int'} -> `String' peekCString* #}
{#fun error_check_is_verifier as ^ {`Int'} -> `Bool' #}
