{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
module Spec.Parser (specs) where

import           Data.Attoparsec.Text (parseOnly)
import qualified Data.Set             as Set
import           Data.Text            (Text)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Datalog.AST
import           Datalog.Parser       (expressionParser, predicateParser,
                                       ruleParser, termParser)

parseTerm :: Text -> Either String ID
parseTerm = parseOnly termParser

parseTermQQ :: Text -> Either String QQID
parseTermQQ = parseOnly termParser

parsePredicate :: Text -> Either String Predicate
parsePredicate = parseOnly predicateParser

parseRule :: Text -> Either String Rule
parseRule = parseOnly ruleParser

parseExpression :: Text -> Either String Expression
parseExpression = parseOnly expressionParser

specs :: TestTree
specs = testGroup "datalog parser"
  [ factWithDate
  , simpleFact
  , simpleRule
  , termsGroup
  , termsGroupQQ
  , constraints
  , constrainedRule
  , constrainedRuleOrdering
  ]

termsGroup :: TestTree
termsGroup = testGroup "Parse terms"
  [ testCase "Symbol" $ parseTerm "#ambient" @?= Right (Symbol "ambient")
  , testCase "String" $ parseTerm "\"file1 a hello - 123_\"" @?= Right (LString "file1 a hello - 123_")
  , testCase "Positive integer" $ parseTerm "123" @?= Right (LInteger 123)
  , testCase "Negative integer" $ parseTerm "-42" @?= Right (LInteger (-42))
  , testCase "Date" $ parseTerm "2019-12-02T13:49:53Z" @?=
        Right (LDate $ read "2019-12-02 13:49:53 UTC")
  , testCase "Variable" $ parseTerm "$1" @?= Right (Variable "1")
  , testCase "Antiquote" $ parseTerm "${toto}" @?= Left "Failed reading: empty"
  ]

termsGroupQQ :: TestTree
termsGroupQQ = testGroup "Parse terms (in a QQ setting)"
  [ testCase "Symbol" $ parseTermQQ "#ambient" @?= Right (Symbol "ambient")
  , testCase "String" $ parseTermQQ "\"file1 a hello - 123_\"" @?= Right (LString "file1 a hello - 123_")
  , testCase "Positive integer" $ parseTermQQ "123" @?= Right (LInteger 123)
  , testCase "Negative integer" $ parseTermQQ "-42" @?= Right (LInteger (-42))
  , testCase "Date" $ parseTermQQ "2019-12-02T13:49:53Z" @?=
        Right (LDate $ read "2019-12-02 13:49:53 UTC")
  , testCase "Variable" $ parseTermQQ "$1" @?= Right (Variable "1")
  , testCase "Antiquote" $ parseTermQQ "${toto}" @?= Right (Antiquote "toto")
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
                ] [])

constrainedRule :: TestTree
constrainedRule = testCase "Parse constained rule" $
  parseRule "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\"), $0 <= 2019-12-04T09:46:41+00:00" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Symbol "ambient", Variable "0"]
                , Predicate "resource" [Symbol "ambient", LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ])

constrainedRuleOrdering :: TestTree
constrainedRuleOrdering = testCase "Parse constained rule (interleaved)" $
  parseRule "valid_date(\"file1\") <- time(#ambient, $0), $0 <= 2019-12-04T09:46:41+00:00, resource(#ambient, \"file1\")" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Symbol "ambient", Variable "0"]
                , Predicate "resource" [Symbol "ambient", LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ])

constraints :: TestTree
constraints = testGroup "Parse expressions"
  [ testCase "date comparison (LTE)" $
      parseExpression "$0 <= 2030-12-31T12:59:59+00:00" @?=
        Right (EBinary LessOrEqual
                 (EValue (Variable "0"))
                 (EValue (LDate $ read "2030-12-31 12:59:59 UTC"))
                 )
  , testCase "date comparison (GTE)" $
      parseExpression "$0 >= 2030-12-31T12:59:59+00:00" @?=
        Right (EBinary GreaterOrEqual
                 (EValue (Variable "0"))
                 (EValue (LDate $ read "2030-12-31 12:59:59 UTC"))
                 )
  , testCase "int comparison (LT)" $
      parseExpression "$0 < 1234" @?=
        Right (EBinary LessThan
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (GT)" $
      parseExpression "$0 > 1234" @?=
        Right (EBinary GreaterThan
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (LTE)" $
      parseExpression "$0 <= 1234" @?=
        Right (EBinary LessOrEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (EQ)" $
      parseExpression "$0 == 1" @?=
        Right (EBinary Equal
                 (EValue (Variable "0"))
                 (EValue (LInteger 1))
                 )
  , testCase "negative int comparison (GTE)" $
      parseExpression "$0 >= -1234" @?=
        Right (EBinary GreaterOrEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger (-1234)))
                 )
  , testCase "string comparison" $
      parseExpression "$0 == \"abc\"" @?=
        Right (EBinary Equal
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (starts_with)" $
      parseExpression "$0.starts_with(\"abc\")" @?=
        Right (EBinary Prefix
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (ends_with)" $
      parseExpression "$0.ends_with(\"abc\")" @?=
        Right (EBinary Suffix
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (matches)" $
      parseExpression "$0.matches(\"abc\")" @?=
        Right (EBinary Regex
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "int set operation" $
      parseExpression "[1, 2].contains($0)" @?=
        Right (EBinary Contains
                 (EValue (TermSet $ Set.fromList [LInteger 1, LInteger 2]))
                 (EValue (Variable "0"))
                 )
  , testCase "negated int set operation" $
      parseExpression "![1, 2].contains($0)" @?=
        Right (EUnary Negate
                 (EBinary Contains
                    (EValue (TermSet $ Set.fromList [LInteger 1, LInteger 2]))
                    (EValue (Variable "0"))
                    ))
  , testCase "string set operation" $
      parseExpression "[\"abc\", \"def\"].contains($0)" @?=
        Right (EBinary Contains
                 (EValue (TermSet $ Set.fromList [LString "abc", LString "def"]))
                 (EValue (Variable "0"))
                 )
  , testCase "negated string set operation" $
      parseExpression "![\"abc\", \"def\"].contains($0)" @?=
        Right (EUnary Negate
                 (EBinary Contains
                    (EValue (TermSet $ Set.fromList [LString "abc", LString "def"]))
                    (EValue (Variable "0"))
                    ))
  , testCase "symbol set operation" $
      parseExpression "[#abc, #def].contains($0)" @?=
        Right (EBinary Contains
                 (EValue (TermSet $ Set.fromList [Symbol "abc", Symbol "def"]))
                 (EValue (Variable "0"))
                 )
  , testCase "negated symbol set operation" $
      parseExpression "![#abc, #def].contains($0)" @?=
        Right (EUnary Negate
                 (EBinary Contains
                    (EValue (TermSet $ Set.fromList [Symbol "abc", Symbol "def"]))
                    (EValue (Variable "0"))
                    ))
  , operatorPrecedences
  ]

operatorPrecedences :: TestTree
operatorPrecedences = testGroup "mixed-precedence operators"
  [ testCase "< +" $
      parseExpression " 1 < $test + 2 " @?=
        Right (EBinary LessThan
                 (EValue $ LInteger 1)
                 (EBinary Add
                    (EValue $ Variable "test")
                    (EValue $ LInteger 2)
                 )
              )
  , testCase "< && starts_with" $
      parseExpression " 2 < $test && $var2.starts_with(\"test\") && true " @?=
        Right (EBinary And
                 (EBinary And
                    (EBinary LessThan
                       (EValue $ LInteger 2)
                       (EValue $ Variable "test")
                    )
                    (EBinary Prefix
                       (EValue $ Variable "var2")
                       (EValue $ LString "test")
                    )
                 )
                 (EValue $ LBool True)
              )
  , testCase "+ *" $
      parseExpression "1 + 2 * 3" @?=
        Right (EBinary Add
                 (EValue $ LInteger 1)
                 (EBinary Mul
                    (EValue $ LInteger 2)
                    (EValue $ LInteger 3)
                 )
              )
  , testCase "+ * parens" $
      parseExpression "(1 + 2) * 3" @?=
        Right (EBinary Mul
                 (EUnary Parens
                    (EBinary Add
                       (EValue $ LInteger 1)
                       (EValue $ LInteger 2)
                    )
                 )
                 (EValue $ LInteger 3)
              )
  ]
