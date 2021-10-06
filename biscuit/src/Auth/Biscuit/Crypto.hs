module Auth.Biscuit.Crypto
  ( SignedBlock
  , Blocks
  , signBlock
  , verifyBlocks
  , verifySecretProof
  , verifySignatureProof
  , getSignatureProof

  -- Ed25519 reexports
  , PublicKey
  , SecretKey
  , Signature
  , convert
  , publicKey
  , secretKey
  , signature
  , eitherCryptoError
  , maybeCryptoError
  , generateSecretKey
  , toPublic
  ) where

import           Control.Arrow         ((&&&))
import           Crypto.Error          (eitherCryptoError, maybeCryptoError)
import           Crypto.PubKey.Ed25519
import           Data.ByteArray        (convert)
import           Data.ByteString       (ByteString)
import           Data.Int              (Int32)
import           Data.List.NonEmpty    (NonEmpty (..))
import qualified Data.List.NonEmpty    as NE

import qualified Auth.Biscuit.Proto    as PB
import qualified Data.Serialize        as PB

type SignedBlock = (ByteString, Signature, PublicKey)
type Blocks = NonEmpty SignedBlock

-- | Biscuit 2.0 allows multiple signature algorithms.
-- For now this lib only supports Ed25519, but the spec mandates flagging
-- each publicKey with an algorithm identifier when serializing it. The
-- serializing itself is handled by protobuf, but we still need to manually
-- serialize keys when we include them in something we want sign (block
-- signatures, and the final signature for sealed tokens).
serializePublicKey :: PublicKey -> ByteString
serializePublicKey pk =
  let keyBytes = convert pk
      algId :: Int32
      algId = fromIntegral $ fromEnum PB.Ed25519
      -- The spec mandates that we serialize the algorithm id as a little-endian int32
      algBytes = PB.runPut $ PB.putInt32le algId
   in algBytes <> keyBytes

signBlock :: SecretKey
          -> ByteString
          -> IO (SignedBlock, SecretKey)
signBlock sk payload = do
  let pk = toPublic sk
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let toSign = payload <> serializePublicKey nextPk
      sig = sign sk pk toSign
  pure ((payload, sig, nextPk), nextSk)

getSignatureProof :: SignedBlock -> SecretKey -> Signature
getSignatureProof (lastPayload, lastSig, lastPk) nextSecret =
  let sk = nextSecret
      pk = toPublic nextSecret
      toSign = lastPayload <> serializePublicKey lastPk <> convert lastSig
   in sign sk pk toSign

getToSig :: (ByteString, a, PublicKey) -> ByteString
getToSig (p, _, nextPk) =
    p <> serializePublicKey nextPk

getSignature :: SignedBlock -> Signature
getSignature (_, sig, _) = sig

getPublicKey :: SignedBlock -> PublicKey
getPublicKey (_, _, pk) = pk

verifyBlocks :: Blocks
             -> PublicKey
             -> Bool
verifyBlocks blocks rootPk =
  let attachKey pk (payload, sig) = (pk, payload, sig)
      uncurry3 f (a, b, c) = f a b c
      sigs = getSignature <$> blocks
      toSigs = getToSig <$> blocks
      -- key for block 0 is the root key
      -- key for block n is the key from block (n - 1)
      keys = rootPk :| NE.init (getPublicKey <$> blocks)
      keysPayloadsSigs = NE.zipWith attachKey keys (NE.zip toSigs sigs)
   in all (uncurry3 verify) keysPayloadsSigs

verifySecretProof :: SecretKey
                  -> SignedBlock
                  -> Bool
verifySecretProof nextSecret (_, _, lastPk) =
  lastPk == toPublic nextSecret

verifySignatureProof :: Signature
                     -> SignedBlock
                     -> Bool
verifySignatureProof extraSig (lastPayload, lastSig, lastPk) =
  let toSign = lastPayload <> serializePublicKey lastPk <> convert lastSig
   in verify lastPk toSign extraSig
