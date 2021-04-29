{-# LANGUAGE OverloadedStrings #-}
module Spec.Parser (specs) where

import           Data.Attoparsec.Text (parseOnly)
import           Data.Text            (Text)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Datalog.AST
import           Datalog.Parser       (predicateParser, ruleParser, termParser)

parseTerm :: Text -> Either String ID
parseTerm = parseOnly termParser

parsePredicate :: Text -> Either String Predicate
parsePredicate = parseOnly predicateParser

parseRule :: Text -> Either String Rule
parseRule = parseOnly ruleParser

specs :: TestTree
specs = testGroup "datalog parser"
  [ factWithDate
  , simpleFact
  , simpleRule
  , termsGroup
  ]

termsGroup :: TestTree
termsGroup = testGroup "Parse terms" $
  [ testCase "Symbol" $ parseTerm "#ambient" @?= Right (Symbol "ambient")
  , testCase "String" $ parseTerm "\"file1 a hello - 123_\"" @?= Right (LString "file1 a hello - 123_")
  , testCase "Positive integer" $ parseTerm "123" @?= Right (LInteger 123)
  , testCase "Negative integer" $ parseTerm "-42" @?= Right (LInteger (-42))
  , testCase "Date" $ parseTerm "2019-12-02T13:49:53Z" @?=
        Right (LDate $ read "2019-12-02 13:49:53 UTC")
  , testCase "Variable" $ parseTerm "$1" @?= Right (Variable "1")
  ]

simpleFact :: TestTree
simpleFact = testCase "Parse simple fact" $
  parsePredicate "right(#authority, \"file1\", #read)" @?=
    Right (Predicate "right" [Symbol "authority", LString "file1", Symbol "read"])

factWithDate :: TestTree
factWithDate = testCase "Parse fact containing a date" $
  parsePredicate "date(#ambient,2019-12-02T13:49:53Z)" @?=
    Right (Predicate "date" [Symbol "ambient", LDate $ read "2019-12-02 13:49:53 UTC"])

simpleRule :: TestTree
simpleRule = testCase "Parse simple rule" $
  parseRule "right(#authority, $0, #read) <- resource( #ambient, $0), operation(#ambient, #read)" @?=
    Right (Rule (Predicate "right" [Symbol "authority", Variable "0", Symbol "read"])
                [ Predicate "resource" [Symbol "ambient", Variable "0"]
                , Predicate "operation" [Symbol "ambient", Symbol "read"]
                ])
