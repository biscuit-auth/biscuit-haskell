module Auth.Biscuit.Crypto
  ( SignedBlock
  , Blocks
  , signBlock
  , signExternalBlock
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
import           Data.Maybe            (catMaybes)

import qualified Auth.Biscuit.Proto    as PB
import qualified Data.Serialize        as PB

type SignedBlock = (ByteString, Signature, PublicKey, Maybe (Signature, PublicKey))
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
  pure ((payload, sig, nextPk, Nothing), nextSk)

signExternalBlock :: SecretKey
                  -> SecretKey
                  -> PublicKey
                  -> ByteString
                  -> IO (SignedBlock, SecretKey)
signExternalBlock sk eSk pk payload = do
  (block, nextSk) <- signBlock sk payload
  pure (addExternalSignature eSk pk block, nextSk)

addExternalSignature :: SecretKey
                     -> PublicKey
                     -> SignedBlock
                     -> SignedBlock
addExternalSignature eSk pk (payload, sig, nextPk, _) =
  let toSign = payload <> convert pk
      ePk = toPublic eSk
      eSig = sign eSk ePk toSign
   in (payload, sig, nextPk, Just (eSig, ePk))

getSignatureProof :: SignedBlock -> SecretKey -> Signature
getSignatureProof (lastPayload, lastSig, lastPk, _todo) nextSecret =
  let sk = nextSecret
      pk = toPublic nextSecret
      toSign = lastPayload <> serializePublicKey lastPk <> convert lastSig
   in sign sk pk toSign

getToSig :: (ByteString, a, PublicKey, Maybe (Signature, PublicKey)) -> ByteString
getToSig (p, _, nextPk, _) =
    p <> serializePublicKey nextPk

getSignature :: SignedBlock -> Signature
getSignature (_, sig, _, _) = sig

getPublicKey :: SignedBlock -> PublicKey
getPublicKey (_, _, pk, _) = pk

-- | The data signed by the external key is the payload for the current block + the public key from
-- the previous block: this prevents signature reuse (the external signature cannot be used on another
-- token)
getExternalSigPayload :: PublicKey -> SignedBlock -> Maybe (PublicKey, ByteString, Signature)
getExternalSigPayload pkN (payload, _, _, Just (eSig, ePk)) = Just (ePk, payload <> convert pkN, eSig)
getExternalSigPayload _ _ = Nothing

-- ToDo verify optional signatures as well
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
      keys = pure rootPk <> (getPublicKey <$> blocks)
      keysPayloadsSigs = NE.zipWith attachKey keys (NE.zip toSigs sigs)

      -- external_signature(block_n) = sign(external_key_n, payload_n <> public_key_n-1)
      -- so we need to pair each block with the public key carried by the previous block
      -- (the authority block can't have an external signature)
      previousKeys = getPublicKey <$> NE.init blocks
      blocksAfterAuthority = NE.tail blocks
      eKeysPayloadsESigs = catMaybes $ zipWith getExternalSigPayload previousKeys blocksAfterAuthority
   in  all (uncurry3 verify) keysPayloadsSigs
    && all (uncurry3 verify) eKeysPayloadsESigs

verifySecretProof :: SecretKey
                  -> SignedBlock
                  -> Bool
verifySecretProof nextSecret (_, _, lastPk, _) =
  lastPk == toPublic nextSecret

verifySignatureProof :: Signature
                     -> SignedBlock
                     -> Bool
verifySignatureProof extraSig (lastPayload, lastSig, lastPk, _) =
  let toSign = lastPayload <> serializePublicKey lastPk <> convert lastSig
   in verify lastPk toSign extraSig
