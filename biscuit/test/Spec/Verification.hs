{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
module Spec.Verification
  ( specs
  ) where

import           Data.List.NonEmpty            (NonEmpty ((:|)))
import qualified Data.Set                      as Set
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Datalog.AST      (Expression' (..), Query,
                                                QueryItem' (..), Term' (..))
import           Auth.Biscuit.Datalog.Executor (MatchedQuery (..),
                                                ResultError (..))
import qualified Auth.Biscuit.Datalog.Executor as Executor
import           Auth.Biscuit.Datalog.Parser   (check, fact, query)

specs :: TestTree
specs = testGroup "Datalog checks"
  [ singleBlock
  , errorAccumulation
  , unboundVarRule
  , symbolRestrictions
  , factsRestrictions
  ]

ifTrue :: MatchedQuery
ifTrue = MatchedQuery
  { matchedQuery = [query|true|]
  , bindings = Set.singleton mempty
  }

ifFalse :: MatchedQuery
ifFalse = MatchedQuery
  { matchedQuery = [query|false|]
  , bindings = Set.singleton mempty
  }

ifFalse' :: Query
ifFalse' = matchedQuery ifFalse

singleBlock :: TestTree
singleBlock = testCase "Single block" $ do
  secret <- newSecret
  biscuit <- mkBiscuit secret [block|right("file1", "read");|]
  res <- authorizeBiscuit biscuit [authorizer|check if right("file1", "read");allow if true;|]
  matchedAllowQuery <$> res @?= Right ifTrue

errorAccumulation :: TestTree
errorAccumulation = testGroup "Error accumulation"
  [ testCase "Only checks" $ do
      secret <- newSecret
      biscuit <- mkBiscuit secret[block|check if false; check if false;|]
      res <- authorizeBiscuit biscuit [authorizer|allow if true;|]
      res @?= Left (ResultError $ FailedChecks $ ifFalse' :| [ifFalse'])
  , testCase "Checks and deny policies" $ do
      secret <- newSecret
      biscuit <- mkBiscuit secret [block|check if false; check if false;|]
      res <- authorizeBiscuit biscuit [authorizer|deny if true;|]
      res @?= Left(ResultError $ DenyRuleMatched [ifFalse', ifFalse'] ifTrue)
  , testCase "Checks and no policies matched" $ do
      secret <- newSecret
      biscuit <- mkBiscuit secret [block|check if false; check if false;|]
      res <- authorizeBiscuit biscuit [authorizer|allow if false;|]
      res @?= Left (ResultError $ NoPoliciesMatched [ifFalse', ifFalse'])
  ]

unboundVarRule :: TestTree
unboundVarRule = testCase "Rule with unbound variable" $ do
  secret <- newSecret
  b1 <- mkBiscuit secret [block|check if operation("read");|]
  b2 <- addBlock [block|operation($unbound, "read") <- operation($any1, $any2);|] b1
  res <- authorizeBiscuit b2 [authorizer|operation("write");allow if true;|]
  res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])

symbolRestrictions :: TestTree
symbolRestrictions = testGroup "Restricted symbols in blocks"
  [ testCase "In facts" $ do
      secret <- newSecret
      b1 <- mkBiscuit secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation("read");|] b1
      res <- authorizeBiscuit b2 [authorizer|allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  , testCase "In rules" $ do
      secret <- newSecret
      b1 <- mkBiscuit secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation($ambient, "read") <- operation($ambient, $any);|] b1
      res <- authorizeBiscuit b2 [authorizer|operation("write");allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  ]

factsRestrictions :: TestTree
factsRestrictions =
  let limits = defaultLimits { allowBlockFacts = False }
   in testGroup "No facts or rules in blocks"
        [ testCase "No facts" $ do
            secret <- newSecret
            b1 <- mkBiscuit secret [block|right("read");|]
            b2 <- addBlock [block|right("write");|] b1
            res <- authorizeBiscuitWithLimits limits b2 [authorizer|allow if right("write");|]
            res @?= Left (Executor.ResultError $ Executor.NoPoliciesMatched [])
        , testCase "No rules" $ do
            secret <- newSecret
            b1 <- mkBiscuit secret [block|right("read");|]
            b2 <- addBlock [block|right("write") <- right("read");|] b1
            res <- authorizeBiscuitWithLimits limits b2 [authorizer|allow if right("write");|]
            res @?= Left (Executor.ResultError $ Executor.NoPoliciesMatched [])
        ]
