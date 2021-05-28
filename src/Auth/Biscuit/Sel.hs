{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE RecordWildCards            #-}
{-|
  Module      : Auth.Biscuit.Sel
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Cryptographic primitives necessary to sign and verify biscuit tokens
-}
module Auth.Biscuit.Sel
  ( Keypair (..)
  , PrivateKey
  , PublicKey
  , Signature (..)
  , parsePrivateKey
  , parsePublicKey
  , serializePrivateKey
  , serializePublicKey
  , newKeypair
  , fromPrivateKey
  , signBlock
  , aggregate
  , verifySignature
  , hashBytes
  ) where

import           Control.Monad.Cont     (ContT (..), lift, runContT)
import           Data.ByteString        (ByteString, packCStringLen,
                                         useAsCStringLen)
import qualified Data.ByteString        as BS
import           Data.ByteString.Base16 as Hex
import           Data.Foldable          (for_)
import           Data.Functor           (void)
import           Data.List.NonEmpty     (NonEmpty)
import           Data.Primitive.Ptr     (copyPtr)
import           Foreign.C.Types
import           Foreign.Marshal.Alloc
import           Foreign.Ptr
import           Libsodium

-- | A private key used to generate a biscuit
newtype PrivateKey = PrivateKey ByteString
  deriving newtype (Eq, Ord)

instance Show PrivateKey where
  show (PrivateKey bs) = show $ Hex.encode bs

-- | Parse a private key from raw bytes.
-- This returns `Nothing` if the raw bytes don't have the expected length
parsePrivateKey :: ByteString -> Maybe PrivateKey
parsePrivateKey bs = if BS.length bs == cs2int crypto_core_ristretto255_scalarbytes
                     then Just (PrivateKey bs)
                     else Nothing

-- | Serialize a private key to raw bytes
serializePrivateKey :: PrivateKey -> ByteString
serializePrivateKey (PrivateKey bs) = bs

-- | A public key used to generate a biscuit
newtype PublicKey = PublicKey ByteString
  deriving newtype (Eq, Ord)

-- | Parse a public key from raw bytes.
-- This returns `Nothing` if the raw bytes don't have the expected length
parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey bs = if BS.length bs == cs2int crypto_core_ristretto255_bytes
                     then Just (PublicKey bs)
                     else Nothing

-- | Serialize a public key to raw bytes
serializePublicKey :: PublicKey -> ByteString
serializePublicKey (PublicKey bs) = bs

instance Show PublicKey where
  show (PublicKey bs) = show $ Hex.encode bs

-- | A keypair containing both a private key and a public key
data Keypair
  = Keypair
  { privateKey :: PrivateKey
  -- ^ the private key
  , publicKey  :: PublicKey
  -- ^ the public key
  } deriving (Eq, Ord)

instance Show Keypair where
  show Keypair{privateKey, publicKey} =
    show privateKey <> "/" <> show publicKey

keypairFromScalar :: Scalar -> IO Keypair
keypairFromScalar scalarBuf =
  scalarToPoint scalarBuf $ \pointBuf -> do
    privateKey <- PrivateKey <$> scalarToByteString scalarBuf
    publicKey <- PublicKey <$> pointToByteString pointBuf
    pure Keypair{..}

-- | Generate a random keypair
newKeypair :: IO Keypair
newKeypair = randomScalar keypairFromScalar

-- | Construct a keypair from a private key
fromPrivateKey :: PrivateKey -> IO Keypair
fromPrivateKey (PrivateKey privBs) =
  withBSLen privBs $ keypairFromScalar . fst

-- | The signature of a series of blocks (raw bytestrings)
data Signature
  = Signature
  { parameters :: [ByteString]
  -- ^ the list of parameters used to sign each block
  , z          :: ByteString
  -- ^ the aggregated signature
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

type Scalar = Ptr CUChar
type Point = Ptr CUChar

-- | Hash a bytestring with SHA256
hashBytes :: ByteString
          -> IO ByteString
hashBytes message = (`runContT` pure) $ do
  out <- ContT $ allocaBytes $ cs2int crypto_hash_sha256_bytes
  (buf, len) <- ContT $ withBSLen message
  void $ lift $ crypto_hash_sha256 out buf len
  lift $ packCStringLen (castPtr out, cs2int crypto_hash_sha256_bytes)

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

-- | Sign a single block with the given keypair
signBlock :: Keypair
          -> ByteString
          -> IO Signature
signBlock Keypair{publicKey,privateKey} message = do
  let PublicKey pubBs = publicKey
      PrivateKey prvBs = privateKey
  randomScalar $ \r ->
    scalarToPoint r $ \aa ->
      hashPoints [aa] $ \d ->
        hashMessage pubBs message $ \e ->
          withScalar $ \rd -> do
            crypto_core_ristretto255_scalar_mul rd r d
            withScalar $ \epk ->
              withBSLen prvBs $ \(pk, _) -> do
                crypto_core_ristretto255_scalar_mul epk e pk
                withScalar $ \z -> do
                  crypto_core_ristretto255_scalar_sub z rd epk
                  aaBs <- pointToByteString aa
                  zBs <- scalarToByteString z
                  pure Signature { parameters = [aaBs]
                                 , z = zBs
                                 }

-- | Aggregate two signatures into a single one
aggregate :: Signature -> Signature -> IO Signature
aggregate first second =
  withScalar $ \zBuf -> withBSLen (z first) $ \(fz, _) -> withBSLen (z second) $ \(sz, _) -> do
    crypto_core_ristretto255_scalar_add zBuf fz sz
    z <- pointToByteString zBuf
    pure Signature
      { parameters = parameters first <> parameters second
      , z
      }

-- | Verify a signature, given a list of messages and associated
-- public keys
verifySignature :: NonEmpty (PublicKey,ByteString)
                -> Signature
                -> IO Bool
verifySignature messagesAndPks Signature{parameters,z} =
  withBSLen z $ \(zBuf, _) ->
    scalarToPoint zBuf $ \zP ->
      computeHashMSums messagesAndPks $ \eiXiRes ->
        computeHashPSums parameters $ \diAiRes ->
          withPoint $ \res -> withPoint $ \resTmp -> do
            _ <- crypto_core_ristretto255_add resTmp zP eiXiRes
            _ <- crypto_core_ristretto255_sub res resTmp diAiRes
            diff <- sodium_is_zero res crypto_core_ristretto255_scalarbytes
            pure $ diff == 1

computeHashMSums :: NonEmpty (PublicKey, ByteString)
                 -> (Point -> IO a) -> IO a
computeHashMSums messagesAndPks f =
  withPoint $ \eiXiRes -> do
    sodium_memzero eiXiRes crypto_core_ristretto255_bytes
    for_ messagesAndPks $ \(PublicKey publicKey, message) ->
      withPoint $ \eiXi -> withPoint $ \eiXiResTmp ->
        withBSLen publicKey $ \(pkBuf, _) ->
          hashMessage publicKey message $ \ei -> do
            _ <- crypto_scalarmult_ristretto255 eiXi ei pkBuf
            _ <- crypto_core_ristretto255_add eiXiResTmp eiXiRes eiXi
            copyPointFrom eiXiRes eiXiResTmp
    f eiXiRes

computeHashPSums :: [ByteString] -- parameters
                 -> (Point -> IO a) -> IO a
computeHashPSums parameters f =
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

cs2int :: CSize -> Int
cs2int = fromInteger . toInteger
