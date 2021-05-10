{-# LANGUAGE OverloadedStrings #-}
{- HLINT ignore "Reduce duplication" -}
module Spec.Crypto (specs) where

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
  signed <- new "content" rootKp
  result <- check signed
  result @?= True

multiBlockRoundtrip :: TestTree
multiBlockRoundtrip = testCase "Multi block roundtrip" $ do
  rootKp <- newKeypair
  blockKp <- newKeypair
  init' <- new "content" rootKp
  withBlock <- append "block" blockKp init'
  result <- check withBlock
  result @?= True

tamperedAuthority :: TestTree
tamperedAuthority = testCase "Tampered authority" $ do
  rootKp <- newKeypair
  blockKp <- newKeypair
  init' <- new "content" rootKp
  result <- check $ init' { messages = ["modified"] }
  result @?= False
  withBlock <- append "block" blockKp init'
  result' <- check $ withBlock { messages = ["modified", "block"] }
  result' @?= False

tamperedBlock :: TestTree
tamperedBlock = testCase "Tampered block" $ do
  rootKp <- newKeypair
  blockKp <- newKeypair
  init' <- new "content" rootKp
  withBlock <- append "block" blockKp init'
  result <- check $ withBlock { messages = ["content", "modified"] }
  result @?= False
