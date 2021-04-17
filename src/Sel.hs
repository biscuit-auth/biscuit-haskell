module Sel
  ( main
  ) where

import           Data.ByteString
import           Data.ByteString
import           Data.ByteString.Base64
import           Data.ByteString.Internal
import           Data.Coerce              (Coercible, coerce)
import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.Marshal.Alloc
import           Foreign.Ptr
import           Foreign.Storable
import           GHC.ForeignPtr
import           Libsodium

main :: IO ()
main = do
  bs <- getRandom crypto_core_ristretto255_hashbytes
  print $ encodeBase64 bs

cs2int :: CSize -> Int
cs2int = fromInteger . toInteger

getRandom :: CSize -> IO ByteString
getRandom s =
  let si = cs2int s
   in allocaBytes si $ \buf -> do
       randombytes_buf buf s
       packCStringLen (castPtr buf, si)


