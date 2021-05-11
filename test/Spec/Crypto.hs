{-# LANGUAGE OverloadedStrings #-}
{- HLINT ignore "Reduce duplication" -}
module Spec.Crypto (specs) where

import           Data.List.NonEmpty (NonEmpty ((:|)))
import           Test.Tasty
import           Test.Tasty.HUnit

import           Sel

specs :: TestTree
specs = testGroup "biscuit crypto"
  [ singleBlockRoundtrip
  , multiBlockRoundtrip
  , tamperedAuthority
  , tamperedBlock
  ]

singleBlockRoundtrip :: TestTree
singleBlockRoundtrip = testCase "Single block roundtrip" $ do
  rootKp <- newKeypair
  let pub = publicKey rootKp
      content = "content"
      token = (pub, content) :| []
  sig <- signBlock rootKp content
  result <- verifySignature token sig
  result @?= True

multiBlockRoundtrip :: TestTree
multiBlockRoundtrip = testCase "Multi block roundtrip" $ do
  kp' <- newKeypair
  kp <- newKeypair
  let pub = publicKey kp
      pub' = publicKey kp'
      content = "content"
      content' = "block"
      token = (pub, content) :| [(pub', content')]
  sig    <- signBlock kp content
  sig'   <- aggregate sig =<< signBlock kp' content'
  result <- verifySignature token sig'
  result @?= True

tamperedAuthority :: TestTree
tamperedAuthority = testCase "Tampered authority" $ do
  kp' <- newKeypair
  kp <- newKeypair
  let pub = publicKey kp
      pub' = publicKey kp'
      content = "content"
      content' = "block"
      token  = (pub, "modified") :| []
      token' = (pub, "modified") :| [(pub', content')]
  sig    <- signBlock kp content
  sig'   <- aggregate sig =<< signBlock kp' content'
  result <- verifySignature token sig'
  result @?= False
  result' <- verifySignature token' sig'
  result' @?= False

tamperedBlock :: TestTree
tamperedBlock = testCase "Tampered block" $ do
  kp' <- newKeypair
  kp <- newKeypair
  let pub = publicKey kp
      pub' = publicKey kp'
      content = "content"
      content' = "block"
      token = (pub, content) :| [(pub', "modified")]
  sig    <- signBlock kp content
  sig'   <- aggregate sig =<< signBlock kp' content'
  result <- verifySignature token sig'
  result @?= False
