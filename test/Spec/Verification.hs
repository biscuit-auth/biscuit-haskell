{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
module Spec.Verification
  ( specs
  ) where

import           Test.Tasty
import           Test.Tasty.HUnit

import           Biscuit
import           Datalog.Parser   (block, verifier)

specs :: TestTree
specs = testGroup "Serde roundtrips"
  [ singleBlock
  , unboundVarRule
  , symbolRestrictions
  ]

singleBlock :: TestTree
singleBlock = testCase "Single block" $ do
  keypair <- newKeypair
  biscuit <- mkBiscuit keypair [block|right(#authority, "file1", #read);|]
  res <- verifyBiscuit biscuit [verifier|check if right(#authority, "file1", #read);|] (publicKey keypair)
  res @?= Right ()

unboundVarRule :: TestTree
unboundVarRule = testCase "Rule with unbound variable" $ do
  keypair <- newKeypair
  b1 <- mkBiscuit keypair [block|check if operation(#ambient, #read);|]
  b2 <- addBlock [block|operation($unbound, #read) <- operation($any1, $any2);|] b1
  res <- verifyBiscuit b2 [verifier|operation(#ambient,#write);allow if true;|] (publicKey keypair)
  res @?= Left DatalogError

symbolRestrictions :: TestTree
symbolRestrictions = testCase "Symbol restrictions" $ do
  keypair <- newKeypair
  b1 <- mkBiscuit keypair [block|check if operation(#ambient, #read);|]
  b2 <- addBlock [block|operation($ambient, #read) <- operation($ambient, $any);|] b1
  res <- verifyBiscuit b2 [verifier|operation(#ambient,#write);allow if true;|] (publicKey keypair)
  res @?= Left DatalogError
