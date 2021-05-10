{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Spec.Quasiquoter (specs) where

import           Data.Text        (Text)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Datalog.AST
import           Datalog.Parser   (fact, rule)

specs :: TestTree
specs = testGroup "Datalog quasiquoter"
  [ basicFact
  , basicRule
  , antiquotedFact
  , antiquotedRule
  ]

basicFact :: TestTree
basicFact = testCase "Basic fact" $
  let actual :: Fact
      actual = [fact|right(#authority, "file1", #read)|]
   in actual @?=
    Predicate "right" [ Symbol "authority"
                      , LString "file1"
                      , Symbol "read"
                      ]

basicRule :: TestTree
basicRule = testCase "Basic rule" $
  let actual :: Rule
      actual = [rule|right(#authority, $0, #read) <- resource( #ambient, $0), operation(#ambient, #read)|]
   in actual @?=
    Rule (Predicate "right" [Symbol "authority", Variable "0", Symbol "read"])
         [ Predicate "resource" [Symbol "ambient", Variable "0"]
         , Predicate "operation" [Symbol "ambient", Symbol "read"]
         ] []

antiquotedFact :: TestTree
antiquotedFact = testCase "Sliced fact" $
  let toto :: Text
      toto = "test"
      actual :: Fact
      actual = [fact|right(#authority, ${toto}, #read)|]
   in actual @?=
    Predicate "right" [ Symbol "authority"
                      , LString "test"
                      , Symbol "read"
                      ]

antiquotedRule :: TestTree
antiquotedRule = testCase "Sliced rule" $
  let toto :: Text
      toto = "test"
      actual :: Rule
      actual = [rule|right(#authority, $0, #read) <- resource( #ambient, $0), operation(#ambient, #read, ${toto})|]
   in actual @?=
    Rule (Predicate "right" [Symbol "authority", Variable "0", Symbol "read"])
         [ Predicate "resource" [Symbol "ambient", Variable "0"]
         , Predicate "operation" [Symbol "ambient", Symbol "read", LString "test"]
         ] []
