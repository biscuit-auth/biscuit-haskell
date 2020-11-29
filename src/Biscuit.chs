{-# LANGUAGE ForeignFunctionInterface #-}
module Biscuit where

#include "biscuit_auth.h"

{#context lib="libbiscuit_auth" #}

import Foreign.C.String
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

withCStringLen' :: String -> ((Ptr CUChar, CULong) -> IO a) -> IO a
withCStringLen' s f =
  let f' (ptr, int) = f (castPtr ptr, toEnum int)
   in withCStringLen s f'

{#fun error_message as ^ {} -> `String' peekCString* #}



{#fun pure keypair_new as ^ { withCStringLen'* `String'& } -> `Ptr KeyPair' id #}

{#fun pure keypair_new_print as ^ { withCStringLen'* `String'& } -> `Ptr KeyPair' id #}

{#fun pure keypair_public as ^ { id `Ptr KeyPair' } -> `Ptr PublicKey' id #}

{#fun pure biscuit_builder as ^ { id `Ptr KeyPair' } -> `Ptr BiscuitBuilder' id #}

{#fun biscuit_builder_add_authority_fact as ^ { id `Ptr BiscuitBuilder', withCString* `String' } -> `Bool' #}

{#fun biscuit_builder_add_authority_caveat as ^ { id `Ptr BiscuitBuilder', withCString* `String' } -> `Bool' #}

{#fun pure biscuit_builder_build as ^ { id `Ptr BiscuitBuilder', withCStringLen'* `String'& } -> `Ptr Biscuit' id #}

{#fun pure biscuit_from as ^ { withCStringLen'* `String'& } -> `Ptr Biscuit' id #}

{#fun pure biscuit_verify as ^ { id `Ptr Biscuit', id `Ptr PublicKey' } -> `Ptr Verifier' id #}

{#fun verifier_add_caveat as ^ { id `Ptr Verifier', withCString* `String' } -> `Bool' #}

{#fun pure verifier_verify as ^ { id `Ptr Verifier' } -> `Bool' #}

{#fun pure verifier_print as ^ { id `Ptr Verifier' } -> `String' peekCString* #}
