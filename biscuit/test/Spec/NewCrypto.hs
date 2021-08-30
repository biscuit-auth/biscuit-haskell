{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{- HLINT ignore "Reduce duplication" -}
module Spec.NewCrypto (specs) where

import           Data.ByteString       (ByteString)
import           Data.List.NonEmpty    (NonEmpty ((:|)))
import           Data.Maybe            (isJust)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Crypto
import           Crypto.PubKey.Ed25519

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
