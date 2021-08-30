{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns        #-}
module Auth.Biscuit.Crypto where

import           Control.Arrow         ((&&&))
import           Crypto.PubKey.Ed25519
import           Data.ByteArray        (convert)
import           Data.ByteString       (ByteString)
import           Data.List.NonEmpty    (NonEmpty (..))
import qualified Data.List.NonEmpty    as NE

type Blocks = NonEmpty (ByteString, Signature, PublicKey)

data Token = Token
  { payload :: Blocks
  , privKey :: SecretKey
  }

data SealedToken = SealedToken
  { payload :: Blocks
  , sig     :: Signature
  }

signToken :: ByteString -> SecretKey -> IO Token
signToken p sk = do
  let pk = toPublic sk
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let toSign = p <> convert nextPk
  let sig = sign sk pk toSign
  pure Token
    { payload = pure (p, sig, nextPk)
    , privKey = nextSk
    }

append :: Token -> ByteString -> IO Token
append t@Token{payload} p = do
  (nextPk, nextSk) <- (toPublic &&& id) <$> generateSecretKey
  let sk = privKey t
      pk = toPublic sk
      toSign = p <> convert nextPk
      sig = sign sk pk toSign
  pure Token
    { payload = pure (p, sig, nextPk) <> payload
    , privKey = nextSk
    }

seal :: Token -> SealedToken
seal Token{payload,privKey} =
  let (lastPayload, lastSig, lastPk) = NE.head payload
      toSign = lastPayload <> convert lastSig <> convert lastPk
      sk = privKey
      pk = toPublic sk
   in SealedToken
        { sig = sign sk pk toSign
        , payload
        }

snocNE :: [a] -> a -> NonEmpty a
snocNE (h : t) l = h :| (t <> [l])
snocNE [] l      = l :| []

fst' :: (a,b,c) -> a
fst' (a, _, _) = a
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

verifyToken :: Token
            -> PublicKey
            -> Bool
verifyToken t@Token{payload} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      lastCheck = toPublic (privKey t) == trd' (NE.head blocks)
  in sigChecks && lastCheck

verifySealedToken :: SealedToken
                  -> PublicKey
                  -> Bool
verifySealedToken SealedToken{payload, sig} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      (lastPayload, lastSig, lastPk) = NE.head payload
      toSign = lastPayload <> convert lastSig <> convert lastPk
      lastCheck = verify lastPk toSign sig
  in sigChecks && lastCheck
