{-# LANGUAGE ForeignFunctionInterface #-}
module Biscuit where

#include "biscuit_auth.h"

{#context lib="libbiscuit_auth" #}

import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable
-- import C2HS

{#pointer *Biscuit foreign finalizer biscuit_free newtype#}
{#pointer *BiscuitBuilder foreign finalizer biscuit_builder_free newtype#}
{#pointer *BlockBuilder foreign finalizer block_builder_free newtype#}
{#pointer *KeyPair foreign finalizer keypair_free newtype#}
{#pointer *PublicKey foreign finalizer public_key_free newtype#}
{#pointer *Verifier foreign finalizer verifier_free newtype#}
{#pointer *Slice newtype#}
{#pointer *Bytes newtype#}

{#fun pure keypair_new as ^ { alloca- `Ptr Slice' } -> `Ptr KeyPair' id #}
