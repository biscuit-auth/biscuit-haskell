{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{- HLINT ignore "Reduce duplication" -}
module Spec.NewCrypto (specs) where

import           Data.ByteString       (ByteString)
import           Data.List.NonEmpty    (NonEmpty ((:|)))
import qualified Data.List.NonEmpty    as NE
import           Data.Maybe            (isJust)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Crypto
import           Crypto.PubKey.Ed25519

-- This test module is only there to test the crypto layer of biscuits,
-- so we define a custom token type that only cares about the envelope,
-- not the actual payload
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
  (signedBlock, privKey) <- signBlock sk p
  pure Token
    { payload = pure signedBlock
    , privKey
    }

snocNE :: NonEmpty a -> a -> NonEmpty a
snocNE (h :| t) e = h :| (t <> [e])

append :: Token -> ByteString -> IO Token
append t@Token{payload} p = do
  (signedBlock, privKey) <- signBlock (privKey t) p
  pure Token
    { payload = snocNE payload signedBlock
    , privKey
    }

seal :: Token -> SealedToken
seal Token{payload,privKey} =
  let lastBlock = NE.last payload
   in SealedToken
        { sig = getSignatureProof lastBlock privKey
        , payload
        }

verifyToken :: Token
            -> PublicKey
            -> Bool
verifyToken Token{payload, privKey} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      lastCheck = verifySecretProof privKey (NE.last payload)
  in sigChecks && lastCheck

verifySealedToken :: SealedToken
                  -> PublicKey
                  -> Bool
verifySealedToken SealedToken{payload, sig} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      lastCheck = verifySignatureProof sig (NE.last payload)
  in sigChecks && lastCheck

specs :: TestTree
specs = testGroup "new biscuit crypto"
  [ testGroup "signature algorithm - normal"
      [ singleBlockRoundtrip
      , multiBlockRoundtrip
      , tamperedAuthority
      , tamperedBlock
      , removedBlock
      ]
  , testGroup "signature algorithm - sealed"
      [ singleBlockRoundtripSealed
      , multiBlockRoundtripSealed
      , tamperedAuthoritySealed
      , tamperedBlockSealed
      , removedBlockSealed
      ]
  ]

singleBlockRoundtrip :: TestTree
singleBlockRoundtrip = testCase "Single block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  let res = verifyToken token pk
  res @?= True

multiBlockRoundtrip :: TestTree
multiBlockRoundtrip = testCase "Multi block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let res = verifyToken attenuated pk
  res @?= True

alterPayload :: (Blocks -> Blocks)
             -> Token
             -> Token
alterPayload f Token{..} = Token { payload = f payload, ..}

tamperedAuthority :: TestTree
tamperedAuthority = testCase "Tampered authority" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let tamper ((_, s, pk) :| o) = ("tampered", s, pk) :| o
      tampered = alterPayload tamper attenuated
  let res = verifyToken tampered pk
  res @?= False

tamperedBlock :: TestTree
tamperedBlock = testCase "Tampered block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let tamper (h :| ((_, s, pk): t)) = h :| (("tampered", s, pk) : t)
      tampered = alterPayload tamper attenuated
  let res = verifyToken tampered pk
  res @?= False

removedBlock :: TestTree
removedBlock = testCase "Removed block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let tamper (h :| _) = h :| []
      tampered = alterPayload tamper attenuated
  let res = verifyToken tampered pk
  res @?= False

singleBlockRoundtripSealed :: TestTree
singleBlockRoundtripSealed = testCase "Single block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- seal <$> signToken content sk
  let res = verifySealedToken token pk
  res @?= True

multiBlockRoundtripSealed :: TestTree
multiBlockRoundtripSealed = testCase "Multi block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let res = verifySealedToken attenuated pk
  res @?= True

alterPayloadSealed :: (Blocks -> Blocks)
                   -> SealedToken
                   -> SealedToken
alterPayloadSealed f SealedToken{..} = SealedToken { payload = f payload, ..}

tamperedAuthoritySealed :: TestTree
tamperedAuthoritySealed = testCase "Tampered authority" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let tamper ((_, s, pk) :| o) = ("tampered", s, pk) :| o
      tampered = alterPayloadSealed tamper attenuated
  let res = verifySealedToken tampered pk
  res @?= False

tamperedBlockSealed :: TestTree
tamperedBlockSealed = testCase "Tampered block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let tamper (h :| ((_, s, pk): t)) = h :| (("tampered", s, pk) : t)
      tampered = alterPayloadSealed tamper attenuated
  let res = verifySealedToken tampered pk
  res @?= False

removedBlockSealed :: TestTree
removedBlockSealed = testCase "Removed block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let tamper (h :| _) = h :| []
      tampered = alterPayloadSealed tamper attenuated
  let res = verifySealedToken tampered pk
  res @?= False
