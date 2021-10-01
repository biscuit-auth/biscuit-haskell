{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{- HLINT ignore "Reduce duplication" -}
module Spec.ScopedExecutor (specs) where

import           Data.Attoparsec.Text                (parseOnly)
import           Data.Map.Strict                     as Map
import           Data.Set                            as Set
import           Data.Text                           (Text, unpack)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Executor       (ExecutionError (..),
                                                      Limits (..),
                                                      ResultError (..),
                                                      defaultLimits)
import           Auth.Biscuit.Datalog.Parser         (block, check, authorizer)
import           Auth.Biscuit.Datalog.ScopedExecutor

specs :: TestTree
specs = testGroup "Block-scoped Datalog Evaluation"
  [ authorizerOnlySeesAuthority
  , authorityOnlySeesItselfAndAuthorizer
  , block1OnlySeesAuthorityAndAuthorizer
  , block1SeesAuthorityAndAuthorizer
  , iterationCountWorks
  , maxFactsCountWorks
  , allChecksAreCollected
  , revocationIdsAreInjected
  ]

authorizerOnlySeesAuthority :: TestTree
authorizerOnlySeesAuthority = testCase "Authorizer only accesses facts from authority" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed(1234, "file1", "write");
       |]
      verif =
       [authorizer|
         allow if is_allowed(1234, "file1", "write");
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "") [(block1, "")] verif @?= Left (ResultError (NoPoliciesMatched []))

authorityOnlySeesItselfAndAuthorizer :: TestTree
authorityOnlySeesItselfAndAuthorizer = testCase "Authority rules only see authority and authorizer facts" $ do
  let authority =
       [block|
         user(1234);
         is_allowed($user, $resource) <- right($user, $resource, "read");
       |]
      block1 =
       [block|
         right(1234, "file1", "read");
       |]
      verif =
       [authorizer|
         allow if is_allowed(1234, "file1");
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "") [(block1, "")] verif @?= Left (ResultError (NoPoliciesMatched []))

block1OnlySeesAuthorityAndAuthorizer :: TestTree
block1OnlySeesAuthorityAndAuthorizer = testCase "Arbitrary blocks only see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed($user, $resource) <- right($user, $resource, "read");
         check if is_allowed(1234, "file1");
       |]
      block2 =
       [block|
         right(1234, "file1", "read");
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "") [(block1, ""), (block2, "")] verif @?= Left (ResultError (FailedChecks $ pure [check|check if is_allowed(1234, "file1") |]))

block1SeesAuthorityAndAuthorizer :: TestTree
block1SeesAuthorityAndAuthorizer = testCase "Arbitrary blocks see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed($user, $resource) <- user($user), right($user, $resource, "read");
         right(1234, "file1", "read");
         check if is_allowed(1234, "file1");
       |]
      verif =
       [authorizer| allow if false;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "") [(block1, "")] verif @?= Left (ResultError $ NoPoliciesMatched [])


iterationCountWorks :: TestTree
iterationCountWorks = testCase "ScopedExecutions stops when hitting the iterations threshold" $ do
  let limits = defaultLimits { maxIterations = 8 }
      authority =
       [block|
         a("yolo");
         b($a) <- a($a);
         c($b) <- b($b);
         d($c) <- c($c);
         e($d) <- d($d);
         f($e) <- e($e);
         g($f) <- f($f);
       |]
      block1 =
       [block|
         h($g) <- g($g);
         i($h) <- h($h);
         j($i) <- i($i);
         k($j) <- j($j);
         l($k) <- k($k);
         m($l) <- l($l);
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout limits (authority, "") [(block1, "")] verif @?= Left TooManyIterations

maxFactsCountWorks :: TestTree
maxFactsCountWorks = testCase "ScopedExecutions stops when hitting the facts threshold" $ do
  let limits = defaultLimits { maxFacts = 8 }
      authority =
       [block|
         a("yolo");
         b($a) <- a($a);
         c($b) <- b($b);
         d($c) <- c($c);
         e($d) <- d($d);
         f($e) <- e($e);
         g($f) <- f($f);
       |]
      block1 =
       [block|
         h($g) <- g($g);
         i($h) <- h($h);
         j($i) <- i($i);
         k($j) <- j($j);
         l($k) <- k($k);
         m($l) <- l($l);
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout limits (authority, "") [(block1, "")] verif @?= Left TooManyFacts

allChecksAreCollected :: TestTree
allChecksAreCollected = testCase "ScopedExecutions collects all facts results even after a failure" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         check if false;
       |]
      block2 =
       [block|
         check if false;
       |]
      verif =
       [authorizer|
         allow if user(4567);
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "") [(block1, ""), (block2, "")] verif @?= Left (ResultError $ NoPoliciesMatched [[check|check if false|], [check|check if false|]])

revocationIdsAreInjected :: TestTree
revocationIdsAreInjected = testCase "ScopedExecutions injects revocation ids" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|yolo("block1");|]
      block2 =
       [block|yolo("block2");|]
      verif =
       [authorizer|
         check if revocation_id(0, hex:61),
                  revocation_id(1, hex:62),
                  revocation_id(2, hex:63);
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "a") [(block1, "b"), (block2, "c")] verif @?= Left (ResultError $ NoPoliciesMatched [])
