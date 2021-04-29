{-# LANGUAGE NamedFieldPuns  #-}
{-# LANGUAGE RecordWildCards #-}
module Sel
  ( main
  , mkKeyPair
  , signBlock
  , verifySignature
  , Keypair(..)
  , Token(..)
  , append
  , new
  , check
  ) where

import           Control.Monad          (when)
import           Data.ByteString        (ByteString, packCStringLen,
                                         useAsCStringLen)
import           Data.ByteString.Base64
import           Data.Foldable          (for_)
import           Data.Functor           (void)
import           Data.Hex               (hex)
import           Data.Primitive.Ptr     (copyPtr)
import           Foreign.C.Types
import           Foreign.Marshal.Alloc
import           Foreign.Ptr
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
  { d :: [ByteString]
  , z :: ByteString
  } deriving (Eq, Show)

data Token
  = Token
  { messages  :: [ByteString]
  , keys      :: [ByteString]
  , signature :: Signature
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
  allocaBytes intScalarSize f

withPoint :: (Point -> IO a) -> IO a
withPoint f = do
  let intPointSize = cs2int crypto_core_ristretto255_bytes
  allocaBytes intPointSize f

scalarToPoint :: Ptr CUChar
              -> (Ptr CUChar -> IO a)
              -> IO a
scalarToPoint scalar f =
  withPoint $ \pointBuf -> do
    void $ crypto_scalarmult_ristretto255_base pointBuf scalar
    f pointBuf

mkKeyPair :: IO Keypair
mkKeyPair =
  randomScalar $ \scalarBuf ->
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
    void $ crypto_hash_sha512_init statePtr
    for_ points $ \point ->
      crypto_hash_sha512_update statePtr point (fromInteger $ toInteger crypto_core_ristretto255_bytes)
    allocaBytes (cs2int crypto_hash_sha512_bytes) $ \hash -> do
      void $ crypto_hash_sha512_final statePtr hash
      allocaBytes (cs2int crypto_core_ristretto255_scalarbytes) $ \scalar -> do
         crypto_core_ristretto255_scalar_reduce scalar hash
         f scalar

withBSLen :: ByteString
          -> ((Ptr CUChar, CULLong) -> IO a)
          -> IO a
withBSLen bs f = useAsCStringLen bs $ \(buf, int) ->
      f (castPtr buf, toEnum int)

copyPointFrom :: Point -> Point -> IO ()
copyPointFrom to from = copyPtr to from (cs2int crypto_core_ristretto255_bytes)

hashMessage :: ByteString
            -> ByteString
            -> (Scalar -> IO a) -> IO a
hashMessage publicKey message f =
  withBSLen publicKey $ \(kpBuf, kpLen) ->
    withBSLen message $ \(msgBuf, msgLen) -> do
      state <- crypto_hash_sha512_state'malloc
      crypto_hash_sha512_state'ptr state $ \statePtr -> do
        void $ crypto_hash_sha512_init statePtr
        void $ crypto_hash_sha512_update statePtr kpBuf kpLen
        void $ crypto_hash_sha512_update statePtr msgBuf msgLen
        allocaBytes (cs2int crypto_hash_sha512_bytes) $ \hash -> do
          void $ crypto_hash_sha512_final statePtr hash
          allocaBytes (cs2int crypto_core_ristretto255_scalarbytes) $ \scalar -> do
             void $ crypto_core_ristretto255_scalar_reduce scalar hash
             f scalar

signBlock :: Keypair
          -> ByteString
          -> IO Signature
signBlock Keypair{publicKey,privateKey} message =
  randomScalar $ \r ->
    scalarToPoint r $ \aa ->
      hashPoints [aa] $ \d ->
        hashMessage publicKey message $ \e ->
          withScalar $ \rd -> do
            crypto_core_ristretto255_scalar_mul rd r d
            withScalar $ \epk ->
              withBSLen privateKey $ \(pk, _) -> do
                crypto_core_ristretto255_scalar_mul epk e pk
                withScalar $ \z -> do
                  crypto_core_ristretto255_scalar_sub z rd epk
                  aaBs <- pointToByteString aa
                  zBs <- scalarToByteString z
                  pure Signature { d = [aaBs]
                                 , z = zBs
                                 }

aggregate :: Signature -> Signature -> IO Signature
aggregate first second =
  withScalar $ \zBuf -> withBSLen (z first) $ \(fz, _) -> withBSLen (z second) $ \(sz, _) -> do
    crypto_core_ristretto255_scalar_add zBuf fz sz
    z <- pointToByteString zBuf
    pure Signature
      { d = d first <> d second
      , z
      }

verifySignature :: [ByteString]
                -> [ByteString]
                -> Signature
                -> IO Bool
verifySignature publicKeys messages Signature{d,z} = do
  when (length publicKeys /= length messages) $ fail "pks / messages mismatch"
  when (length publicKeys == 0) $ fail "empty pks"
  withBSLen z $ \(zBuf, _) ->
    scalarToPoint zBuf $ \zP ->
      computeHashMSums publicKeys messages $ \eiXiRes ->
        computeHashPSums d $ \diAiRes ->
          withPoint $ \res -> withPoint $ \resTmp -> do
            _ <- crypto_core_ristretto255_add resTmp zP eiXiRes
            _ <- crypto_core_ristretto255_sub res resTmp diAiRes
            diff <- sodium_is_zero res crypto_core_ristretto255_scalarbytes
            pure $ diff == 1

{-
  hashMessage publicKey message $ \e ->
    withScalar $ \dinv ->
      withBSLen d $ \(dBuf, _) -> do
        void $ crypto_core_ristretto255_scalar_invert dinv dBuf
        withScalar $ \zdinv ->
          withBSLen z $ \(zBuf, _) -> do
            crypto_core_ristretto255_scalar_mul zdinv zBuf dinv
            scalarToPoint zdinv $ \zzdinv ->
              withScalar $ \edinv -> do
                crypto_core_ristretto255_scalar_mul edinv e dinv
                withPoint $ \toto ->
                  withBSLen publicKey $ \(pubBuf, _) -> do
                    void $ crypto_scalarmult_ristretto255 toto edinv pubBuf
                    withPoint $ \aa -> do
                      void $ crypto_core_ristretto255_add aa zzdinv toto
                      hashPoints [aa] $ \candidateD ->
                        withScalar $ \diff -> do
                          crypto_core_ristretto255_scalar_sub diff dBuf candidateD
                          res <- sodium_is_zero diff crypto_core_ristretto255_scalarbytes
                          pure $ res == 1
                          -}

computeHashMSums :: [ByteString] -- publicKeys
                -> [ByteString] -- messages
                -> (Point -> IO a) -> IO a
computeHashMSums publicKeys messages f = do
  let pairs = zip publicKeys messages
  withPoint $ \eiXiRes -> do
    sodium_memzero eiXiRes crypto_core_ristretto255_bytes
    for_ pairs $ \(publicKey, message) ->
      withPoint $ \eiXi -> withPoint $ \eiXiResTmp ->
        withBSLen publicKey $ \(pkBuf, _) ->
          hashMessage publicKey message $ \ei -> do
            _ <- crypto_scalarmult_ristretto255 eiXi ei pkBuf
            _ <- crypto_core_ristretto255_add eiXiResTmp eiXiRes eiXi
            copyPointFrom eiXiRes eiXiResTmp
    f eiXiRes

computeHashPSums :: [ByteString] -- parameters
                 -> (Point -> IO a) -> IO a
computeHashPSums parameters f = do
  withPoint $ \diAiRes -> do
    sodium_memzero diAiRes crypto_core_ristretto255_bytes
    for_ parameters $ \aa ->
      withPoint $ \diAi -> withPoint $ \diAiResTmp ->
        withBSLen aa $ \(aaBuf, _) ->
          hashPoints [aaBuf] $ \di -> do
            _ <- crypto_scalarmult_ristretto255 diAi di aaBuf
            _ <- crypto_core_ristretto255_add diAiResTmp diAiRes diAi
            copyPointFrom diAiRes diAiResTmp
    f diAiRes

new :: ByteString -> Keypair -> IO Token
new message keypair = do
  signature <- signBlock keypair message
  pure Token
    { messages = [message]
    , keys = [publicKey keypair]
    , signature
    }

append :: ByteString -> Keypair -> Token -> IO Token
append message keypair Token{..} = do
  newSig <- signBlock keypair message
  endSig <- aggregate signature newSig
  pure $ Token
    { messages = messages <> [message]
    , keys = keys <> [publicKey keypair]
    , signature = endSig
    }

check :: Token -> IO Bool
check Token{..} = verifySignature keys messages signature

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
