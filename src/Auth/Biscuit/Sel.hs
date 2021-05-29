{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE RecordWildCards            #-}
{- HLINT ignore "Reduce duplication" -}
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

import           Control.Monad.Cont     (ContT (..), runContT)
import           Control.Monad.IO.Class (MonadIO, liftIO)
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

keypairFromScalar :: Scalar -> CIO a Keypair
keypairFromScalar scalarBuf = do
  pointBuf <- scalarToPoint scalarBuf
  privateKey <- PrivateKey <$> scalarToByteString scalarBuf
  publicKey <-  PublicKey <$> pointToByteString pointBuf
  pure Keypair{..}

-- | Generate a random keypair
newKeypair :: IO Keypair
newKeypair = runCIO $ do
  scalar <- randomScalar
  keypairFromScalar scalar

-- | Construct a keypair from a private key
fromPrivateKey :: PrivateKey -> IO Keypair
fromPrivateKey (PrivateKey privBs) = runCIO $ do
  (privBuf, _) <- withBSLen privBs
  keypairFromScalar privBuf

-- | The signature of a series of blocks (raw bytestrings)
data Signature
  = Signature
  { parameters :: [ByteString]
  -- ^ the list of parameters used to sign each block
  , z          :: ByteString
  -- ^ the aggregated signature
  } deriving (Eq, Show)

type Scalar = Ptr CUChar
type Point = Ptr CUChar

-- | Pointer allocations are written in a continuation passing style,
-- this type alias allows to use monadic notation instead of nesting
-- callbacks
type CIO a = ContT a IO

-- | Run a continuation to get back an IO value.
runCIO :: ContT a IO a -> IO a
runCIO = (`runContT` pure)

voidIO :: IO a -> CIO b ()
voidIO = void . liftIO

scalarToByteString :: MonadIO m => Ptr CUChar -> m ByteString
scalarToByteString ptr =
  let scalarIntSize = cs2int crypto_core_ristretto255_scalarbytes
   in liftIO $ packCStringLen (castPtr ptr, scalarIntSize)

pointToByteString :: MonadIO m => Ptr CUChar -> m ByteString
pointToByteString ptr =
  let pointIntSize = cs2int crypto_core_ristretto255_bytes
   in liftIO $ packCStringLen (castPtr ptr, pointIntSize)

randomScalar :: CIO a Scalar
randomScalar = do
  scalarBuf <- withScalar
  liftIO $ crypto_core_ristretto255_scalar_random scalarBuf
  pure scalarBuf

withScalar :: CIO a Scalar
withScalar =
  let intScalarSize = cs2int crypto_core_ristretto255_scalarbytes
   in ContT $ allocaBytes intScalarSize

withPoint :: CIO a Point
withPoint =
  let intPointSize = cs2int crypto_core_ristretto255_bytes
   in ContT $ allocaBytes intPointSize

scalarToPoint :: Scalar
              -> CIO a Point
scalarToPoint scalar = do
  pointBuf <- withPoint
  voidIO $ crypto_scalarmult_ristretto255_base pointBuf scalar
  pure pointBuf

withBSLen :: ByteString
          -> ContT a IO (Ptr CUChar, CULLong)
withBSLen bs = do
  (buf, int) <- ContT $ useAsCStringLen bs
  pure (castPtr buf, toEnum int)

scalarAdd :: Scalar -> Scalar -> CIO a Scalar
scalarAdd x y = do
  z <- withScalar
  liftIO $ crypto_core_ristretto255_scalar_add z x y
  pure z

scalarAddBs :: ByteString -> ByteString -> CIO a ByteString
scalarAddBs xBs yBs = do
  (x, _) <- withBSLen xBs
  (y, _) <- withBSLen yBs
  z <- scalarAdd x y
  scalarToByteString z

scalarMul :: Scalar -> Scalar -> CIO a Scalar
scalarMul x y = do
  z <- withScalar
  z <$ liftIO (crypto_core_ristretto255_scalar_mul z x y)

scalarSub :: Scalar -> Scalar -> CIO a Scalar
scalarSub x y = do
  z <- withScalar
  z <$ liftIO (crypto_core_ristretto255_scalar_sub z x y)

scalarReduce :: Ptr CUChar -> CIO a Scalar
scalarReduce bytes = do
  z <- withScalar
  z <$ liftIO (crypto_core_ristretto255_scalar_reduce z bytes)

scalarMulPoint :: Scalar -> Point -> CIO a Point
scalarMulPoint p q = do
  n <- withScalar
  n <$ liftIO (crypto_scalarmult_ristretto255 n p q)

pointAdd :: Point -> Point -> CIO a Point
pointAdd p q = do
  r <- withPoint
  r <$ liftIO (crypto_core_ristretto255_add r p q)

pointSub :: Point -> Point -> CIO a Point
pointSub p q = do
  r <- withPoint
  r <$ liftIO (crypto_core_ristretto255_sub r p q)

zeroPoint :: CIO a Point
zeroPoint = do
  p <- withPoint
  p <$ zeroizePoint p

zeroizePoint :: MonadIO m => Point -> m ()
zeroizePoint p = liftIO $ sodium_memzero p crypto_core_ristretto255_bytes

isZeroPoint :: MonadIO m => Point -> m Bool
isZeroPoint p = liftIO $
  (== 1) <$> sodium_is_zero p crypto_core_ristretto255_scalarbytes

-- | Hash a bytestring with SHA256
hashBytes :: ByteString
          -> IO ByteString
hashBytes message = runCIO $ do
  out <- ContT $ allocaBytes $ cs2int crypto_hash_sha256_bytes
  (buf, len) <- withBSLen message
  voidIO $ crypto_hash_sha256 out buf len
  liftIO $ packCStringLen (castPtr out, cs2int crypto_hash_sha256_bytes)

hashPoint :: Point
           -> ContT a IO Scalar
hashPoint point = do
  hash   <- ContT $ allocaBytes (cs2int crypto_hash_sha512_bytes)
  voidIO $ crypto_hash_sha512 hash point (fromInteger $ toInteger crypto_core_ristretto255_bytes)
  scalarReduce hash

copyPointFrom :: Point -> Point -> IO ()
copyPointFrom to from = copyPtr to from (cs2int crypto_core_ristretto255_bytes)

hashMessage :: ByteString
            -> ByteString
            -> CIO a Scalar
hashMessage publicKey message = do
  (kpBuf, kpLen) <- withBSLen publicKey
  (msgBuf, msgLen) <- withBSLen message
  state <- liftIO crypto_hash_sha512_state'malloc
  statePtr <- ContT $ crypto_hash_sha512_state'ptr state
  voidIO $ crypto_hash_sha512_init statePtr
  voidIO $ crypto_hash_sha512_update statePtr kpBuf kpLen
  voidIO $ crypto_hash_sha512_update statePtr msgBuf msgLen
  hash <- ContT $ allocaBytes (cs2int crypto_hash_sha512_bytes)
  voidIO $ crypto_hash_sha512_final statePtr hash
  scalar <- withScalar
  voidIO $ crypto_core_ristretto255_scalar_reduce scalar hash
  pure scalar

-- | Sign a single block with the given keypair
signBlock :: Keypair -> ByteString -> IO Signature
signBlock Keypair{publicKey,privateKey} message = do
  let PublicKey pubBs = publicKey
      PrivateKey prvBs = privateKey
  (`runContT` pure) $ do
     (pk, _) <- withBSLen prvBs

     r   <- randomScalar
     aa  <- scalarToPoint r
     d   <- hashPoint aa
     e   <- hashMessage pubBs message
     rd  <- scalarMul r d
     epk <- scalarMul e pk
     z   <- scalarSub rd epk
     aaBs <- pointToByteString aa
     zBs  <- scalarToByteString z
     pure Signature { parameters = [aaBs]
                    , z = zBs
                    }

-- | Aggregate two signatures into a single one
aggregate :: Signature -> Signature -> IO Signature
aggregate first second = runCIO $ do
  z <- scalarAddBs (z first) (z second)
  pure Signature
    { parameters = parameters first <> parameters second
    , z
    }

-- | Verify a signature, given a list of messages and associated
-- public keys
verifySignature :: NonEmpty (PublicKey, ByteString)
                -> Signature
                -> IO Bool
verifySignature messagesAndPks Signature{parameters,z} = runCIO $ do
  zP      <- scalarToPoint . fst  =<< withBSLen z
  eiXiRes <- computeHashMSums messagesAndPks
  diAiRes <- computeHashPSums parameters
  resTmp  <- pointAdd zP eiXiRes
  res     <- pointSub resTmp diAiRes
  isZeroPoint res

computeHashMSums :: NonEmpty (PublicKey, ByteString)
                 -> ContT a IO Point
computeHashMSums messagesAndPks = do
  eiXiRes <- zeroPoint
  for_ messagesAndPks $ \(PublicKey publicKey, message) -> do
    ei         <- hashMessage publicKey message
    eiXi       <- scalarMulPoint ei . fst =<< withBSLen publicKey
    eiXiResTmp <- pointAdd eiXiRes eiXi
    liftIO $ copyPointFrom eiXiRes eiXiResTmp
  pure eiXiRes

computeHashPSums :: [ByteString] -- parameters
                 -> ContT a IO Point
computeHashPSums parameters = do
  diAiRes <- zeroPoint
  for_ parameters $ \aa -> do
    (aaBuf, _) <- withBSLen aa
    di         <- hashPoint aaBuf
    diAi       <- scalarMulPoint di aaBuf
    diAiResTmp <- pointAdd diAiRes diAi
    liftIO $ copyPointFrom diAiRes diAiResTmp
  pure diAiRes

cs2int :: CSize -> Int
cs2int = fromInteger . toInteger
