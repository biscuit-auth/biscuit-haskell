{-# LANGUAGE NamedFieldPuns  #-}
{-# LANGUAGE RecordWildCards #-}
module Sel
  ( main
  , mkKeyPair
  , signBlock
  , verifySignature
  , Keypair(..)
  ) where

import           Data.ByteString
import           Data.ByteString
import           Data.ByteString.Base64
import           Data.ByteString.Internal
import           Data.Coerce              (Coercible, coerce)
import           Data.Hex                 (hex, unhex)
import           Data.Traversable         (for)
import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.Marshal.Alloc
import           Foreign.Ptr
import           Foreign.Storable
import           GHC.ForeignPtr
import           Libsodium

-- todo newtype ByteStrings
data Keypair
  = Keypair
  { privateKey :: ByteString
  , publicKey  :: ByteString
  } deriving (Eq, Ord)

instance Show Keypair where
  show Keypair{privateKey, publicKey} =
    show (hex privateKey) <> "/" <> show (hex publicKey)

data Signature
  = Signature
  { d :: ByteString
  , z :: ByteString
  } deriving (Eq, Show)

scalarToByteString :: Ptr CUChar -> IO ByteString
scalarToByteString ptr =
  let scalarIntSize = cs2int crypto_core_ristretto255_scalarbytes
   in packCStringLen (castPtr ptr, scalarIntSize)

pointToByteString :: Ptr CUChar -> IO ByteString
pointToByteString ptr =
  let pointIntSize = cs2int crypto_core_ristretto255_bytes
   in packCStringLen (castPtr ptr, pointIntSize)

randomScalar :: (Ptr CUChar -> IO a) -> IO a
randomScalar f = withScalar $ \scalarBuf -> do
        crypto_core_ristretto255_scalar_random scalarBuf
        f scalarBuf

withScalar :: (Scalar -> IO a) -> IO a
withScalar f = do
  let intScalarSize = cs2int crypto_core_ristretto255_scalarbytes
  allocaBytes intScalarSize $ \scalarBuf -> do
    f scalarBuf

withPoint :: (Point -> IO a) -> IO a
withPoint f = do
  let intPointSize = cs2int crypto_core_ristretto255_bytes
  allocaBytes intPointSize $ \pointBuf -> do
    f pointBuf

scalarToPoint :: Ptr CUChar
              -> (Ptr CUChar -> IO a)
              -> IO a
scalarToPoint scalar f =
  withPoint $ \pointBuf -> do
    crypto_scalarmult_ristretto255_base pointBuf scalar
    f pointBuf

mkKeyPair :: IO Keypair
mkKeyPair = do
  randomScalar $ \scalarBuf -> do
    scalarToPoint scalarBuf $ \pointBuf -> do
      privateKey <- scalarToByteString scalarBuf
      publicKey <- pointToByteString pointBuf
      pure Keypair{..}

type Scalar = Ptr CUChar
type Point = Ptr CUChar

hashPoints :: [Point]
           -> (Scalar -> IO a)
           -> IO a
hashPoints points f = do
  state <- crypto_hash_sha512_state'malloc
  crypto_hash_sha512_state'ptr state $ \statePtr -> do
    crypto_hash_sha512_init statePtr
    for points $ \point ->
      crypto_hash_sha512_update statePtr point (fromInteger $ toInteger crypto_core_ristretto255_bytes)
    allocaBytes (cs2int crypto_hash_sha512_bytes) $ \hash -> do
      crypto_hash_sha512_final statePtr hash
      allocaBytes (cs2int crypto_core_ristretto255_scalarbytes) $ \scalar -> do
         crypto_core_ristretto255_scalar_reduce scalar hash
         f scalar

withBSLen :: ByteString
          -> ((Ptr CUChar, CULLong) -> IO a)
          -> IO a
withBSLen bs f = useAsCStringLen bs $ \(buf, int) -> do
      f (castPtr buf, toEnum int)

hashMessage :: ByteString
            -> ByteString
            -> (Scalar -> IO a) -> IO a
hashMessage publicKey message f = do
  withBSLen publicKey $ \(kpBuf, kpLen) -> do
    withBSLen message $ \(msgBuf, msgLen) -> do
      state <- crypto_hash_sha512_state'malloc
      crypto_hash_sha512_state'ptr state $ \statePtr -> do
        crypto_hash_sha512_init statePtr
        crypto_hash_sha512_update statePtr kpBuf kpLen
        crypto_hash_sha512_update statePtr msgBuf msgLen
        allocaBytes (cs2int crypto_hash_sha512_bytes) $ \hash -> do
          crypto_hash_sha512_final statePtr hash
          allocaBytes (cs2int crypto_core_ristretto255_scalarbytes) $ \scalar -> do
             crypto_core_ristretto255_scalar_reduce scalar hash
             f scalar

signBlock :: Keypair
          -> ByteString
          -> IO Signature
signBlock Keypair{publicKey,privateKey} message = do
  randomScalar $ \r -> do
    scalarToPoint r $ \aa -> do
      hashPoints [aa] $ \d -> do
        hashMessage publicKey message $ \e -> do
          withScalar $ \rd -> do
            crypto_core_ristretto255_scalar_mul rd r d
            withScalar $ \epk -> do
              withBSLen privateKey $ \(pk, _) -> do
                crypto_core_ristretto255_scalar_mul epk e pk
                withScalar $ \z -> do
                  crypto_core_ristretto255_scalar_sub z rd epk
                  dBs <- scalarToByteString d
                  zBs <- scalarToByteString z
                  pure Signature { d = dBs
                                 , z = zBs
                                 }

verifySignature :: ByteString
                -> ByteString
                -> Signature
                -> IO Bool
verifySignature publicKey message Signature{d,z} = do
  hashMessage publicKey message $ \e -> do
  withScalar $ \dinv -> do
    withBSLen d $ \(dBuf, _) -> do
      crypto_core_ristretto255_scalar_invert dinv dBuf
      withScalar $ \zdinv -> do
        withBSLen z $ \(zBuf, _) -> do
        crypto_core_ristretto255_scalar_mul zdinv zBuf dinv
        scalarToPoint zdinv $ \zzdinv -> do
          withScalar $ \edinv -> do
            crypto_core_ristretto255_scalar_mul edinv e dinv
            withPoint $ \toto -> do
              withBSLen publicKey $ \(pubBuf, _) -> do
                crypto_scalarmult_ristretto255 toto edinv pubBuf
                withPoint $ \aa -> do
                  crypto_core_ristretto255_add aa zzdinv toto
                  hashPoints [aa] $ \candidateD -> do
                    withScalar $ \diff -> do
                      crypto_core_ristretto255_scalar_sub diff dBuf candidateD
                      res <- sodium_is_zero diff (crypto_core_ristretto255_scalarbytes)
                      pure $ res == 1

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
