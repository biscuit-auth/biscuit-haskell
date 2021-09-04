{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns        #-}
module Auth.Biscuit.Crypto
  ( SignedBlock
  , signBlock
  , verifyBlocks
  , verifySecretProof
  , verifySignatureProof

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

  -- High-level helpers used in tests
  , Token (..)
  , SealedToken (..)
  , Blocks
  , signToken
  , append
  , seal
  , verifyToken
  , verifySealedToken
  ) where

import           Control.Arrow         ((&&&))
import           Crypto.Error          (eitherCryptoError, maybeCryptoError)
import           Crypto.PubKey.Ed25519
import           Data.ByteArray        (convert)
import           Data.ByteString       (ByteString)
import           Data.List.NonEmpty    (NonEmpty (..))
import qualified Data.List.NonEmpty    as NE

type SignedBlock = (ByteString, Signature, PublicKey)
type Blocks = NonEmpty SignedBlock

data Token = Token
  { payload :: Blocks
  , privKey :: SecretKey
  }

data SealedToken = SealedToken
  { payload :: Blocks
  , sig     :: Signature
  }

signBlock :: SecretKey
          -> ByteString
          -> IO (SignedBlock, SecretKey)
signBlock sk payload = do
  let pk = toPublic sk
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let toSign = payload <> convert nextPk
      sig = sign sk pk toSign
  pure ((payload, sig, nextPk), nextSk)

signToken :: ByteString -> SecretKey -> IO Token
signToken p sk = do
  (signedBlock, privKey) <- signBlock sk p
  pure Token
    { payload = pure signedBlock
    , privKey
    }

append :: Token -> ByteString -> IO Token
append t@Token{payload} p = do
  (signedBlock, privKey) <- signBlock (privKey t) p
  pure Token
    { payload = pure signedBlock <> payload
    , privKey
    }

getSignatureProof :: SignedBlock -> SecretKey -> Signature
getSignatureProof (lastPayload, lastSig, lastPk) nextSecret =
  let sk = nextSecret
      pk = toPublic nextSecret
      toSign = lastPayload <> convert lastSig <> convert lastPk
   in sign sk pk toSign

seal :: Token -> SealedToken
seal Token{payload,privKey} =
  let lastBlock = NE.head payload
   in SealedToken
        { sig = getSignatureProof lastBlock privKey
        , payload
        }

snocNE :: [a] -> a -> NonEmpty a
snocNE (h : t) l = h :| (t <> [l])
snocNE [] l      = l :| []

snd' :: (a,b,c) -> b
snd' (_, b, _) = b
trd' :: (a,b,c) -> c
trd' (_, _, c) = c

uncurry3 :: (a -> b -> c -> d)
         -> (a, b, c) -> d
uncurry3 f (a, b, c) = f a b c

getToSig :: (ByteString, a, PublicKey) -> ByteString
getToSig (p, _, nextPk) =
    p <> convert nextPk

verifyBlocks :: Blocks
             -> PublicKey
             -> Bool
verifyBlocks blocks rootPk =
  let sigs = snd' <$> blocks
      toSigs = getToSig <$> blocks
      keys = snocNE (NE.tail $ trd' <$> blocks) rootPk
      to3t a (b, c) = (a, b, c)
      pkps = NE.zipWith to3t keys (NE.zip toSigs sigs)
   in all (uncurry3 verify) pkps

verifySecretProof :: SecretKey
                  -> SignedBlock
                  -> Bool
verifySecretProof nextSecret (_, _, lastPk) =
  lastPk == toPublic nextSecret

verifyToken :: Token
            -> PublicKey
            -> Bool
verifyToken Token{payload, privKey} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      lastCheck = verifySecretProof privKey (NE.head payload)
  in sigChecks && lastCheck

verifySignatureProof :: Signature
                     -> SignedBlock
                     -> Bool
verifySignatureProof extraSig (lastPayload, lastSig, lastPk) =
  let toSign = lastPayload <> convert lastSig <> convert lastPk
   in verify lastPk toSign extraSig

verifySealedToken :: SealedToken
                  -> PublicKey
                  -> Bool
verifySealedToken SealedToken{payload, sig} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      lastCheck = verifySignatureProof sig (NE.head payload)
  in sigChecks && lastCheck
