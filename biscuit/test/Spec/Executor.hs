{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Spec.Executor (specs) where

import           Data.Attoparsec.Text                (parseOnly)
import           Data.Map.Strict                     as Map
import           Data.Set                            as Set
import           Data.Text                           (Text, unpack)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Executor       (ExecutionError (..),
                                                      Limits (..),
                                                      defaultLimits,
                                                      evaluateExpression)
import           Auth.Biscuit.Datalog.Parser         (expressionParser, fact,
                                                      rule)
import           Auth.Biscuit.Datalog.ScopedExecutor

specs :: TestTree
specs = testGroup "Datalog evaluation"
  [ grandparent
  , exprEval
  , exprEvalError
  , rulesWithConstraints
  , ruleHeadWithNoVars
  , limits
  ]

grandparent :: TestTree
grandparent = testCase "Basic grandparent rule" $
  let world = World
        { rules = Set.fromList
                   [ [rule|grandparent($a,$b) <- parent($a,$c), parent($c,$b)|]
                   ]
        , facts = Set.fromList
                   [ [fact|parent("alice", "bob")|]
                   , [fact|parent("bob", "jean-pierre")|]
                   , [fact|parent("alice", "toto")|]
                   ]
        }
   in runFactGeneration defaultLimits world @?= Right (Set.fromList
        [ [fact|parent("alice", "bob")|]
        , [fact|parent("bob", "jean-pierre")|]
        , [fact|parent("alice", "toto")|]
        , [fact|grandparent("alice", "jean-pierre")|]
        ])

expr :: Text -> Expression
expr = either error id . parseOnly expressionParser

exprEval :: TestTree
exprEval = do
  let bindings = Map.fromList
        [ ("var1", LInteger 0)
        ]
      eval (e, r) = testCase (unpack e) $
        evaluateExpression defaultLimits bindings (expr e) @?= Right r

   --   ("1 / 0") @?= Left "Divide by 0"
  testGroup "Expressions evaluation" $ eval <$>
    [ ("!(1 < $var1)", LBool True)
    , ("[0].contains($var1)", LBool True)
    , ("1 + 2 * 3", LInteger 7)
    , ("!(1 + 2 * 3 > 4)", LBool False)
    , ("!true", LBool False)
    , ("!false", LBool True)
    , ("(true)", LBool True)
    , ("\"test\".length()", LInteger 4)
    , ("hex:ababab.length()", LInteger 3)
    , ("[].length()", LInteger 0)
    , ("[#test, #test].length()", LInteger 1)
    , ("#toto == #toto", LBool True)
    , ("#toto == #truc", LBool False)
    , ("1 == 1", LBool True)
    , ("2 == 1", LBool False)
    , ("\"toto\" == \"toto\"", LBool True)
    , ("\"toto\" == \"truc\"", LBool False)
    , ("\"toto\".matches(\"to(to)?\")", LBool True)
    , ("\"toto\".matches(\"^to$\")", LBool False)
    , ("2021-05-07T18:00:00Z == 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z == 2021-05-07T19:00:00Z", LBool False)
    , ("hex:ababab == hex:ababab", LBool True)
    , ("hex:ababab == hex:ababac", LBool False)
    , ("true == true", LBool True)
    , ("true == false", LBool False)
    , ("[1,2,3] == [1,2,3]", LBool True)
    , ("[1,2,3] == [1,2,4]", LBool False)
    , ("1 < 2", LBool True)
    , ("2 < 1", LBool False)
    , ("2021-05-07T18:00:00Z < 2021-05-07T19:00:00Z", LBool True)
    , ("2021-05-07T19:00:00Z < 2021-05-07T18:00:00Z", LBool False)
    , ("2 > 1", LBool True)
    , ("1 > 2", LBool False)
    , ("2021-05-07T19:00:00Z > 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z > 2021-05-07T19:00:00Z", LBool False)
    , ("1 <= 2", LBool True)
    , ("1 <= 1", LBool True)
    , ("2 <= 1", LBool False)
    , ("2021-05-07T18:00:00Z <= 2021-05-07T19:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z <= 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T19:00:00Z <= 2021-05-07T18:00:00Z", LBool False)
    , ("2 >= 1", LBool True)
    , ("2 >= 2", LBool True)
    , ("1 >= 2", LBool False)
    , ("2021-05-07T19:00:00Z >= 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z >= 2021-05-07T18:00:00Z", LBool True)
    , ("2021-05-07T18:00:00Z >= 2021-05-07T19:00:00Z", LBool False)
    , ("\"my string\".starts_with(\"my\")", LBool True)
    , ("\"my string\".starts_with(\"string\")", LBool False)
    , ("\"my string\".ends_with(\"string\")", LBool True)
    , ("\"my string\".ends_with(\"my\")", LBool False)
    , ("2 + 1", LInteger 3)
    , ("2 - 1", LInteger 1)
    , ("5 / 2", LInteger 2)
    , ("2 * 1", LInteger 2)
    , ("true && true", LBool True)
    , ("true && false", LBool False)
    , ("false && true", LBool False)
    , ("false && false", LBool False)
    , ("true || true", LBool True)
    , ("true || false", LBool True)
    , ("false || true", LBool True)
    , ("false || false", LBool False)
    , ("[#test].contains([#test])", LBool True)
    , ("[#test].contains(#test)", LBool True)
    , ("[].contains(#test)", LBool False)
    , ("[\"test\"].contains(#test)", LBool False)
    , ("[#test].intersection([#test])", TermSet (Set.fromList [Symbol "test"]))
    , ("[#test].intersection([\"test\"])", TermSet (Set.fromList []))
    , ("[#test].union([#test])", TermSet (Set.fromList [Symbol "test"]))
    , ("[#test].union([\"test\"])", TermSet (Set.fromList [Symbol "test", LString "test"]))
    ]

exprEvalError :: TestTree
exprEvalError = do
  let bindings = Map.fromList
        [ ("var1", LInteger 0)
        ]
      l = defaultLimits { allowRegexes = False }
      evalFail (e, r) = testCase (unpack e) $
        evaluateExpression l bindings (expr e) @?= Left r

  testGroup "Expressions evaluation (expected errors)" $ evalFail <$>
    [ ("1 / 0", "Divide by 0")
    , ("\"toto\".matches(\"to\")", "Regex evaluation is disabled")
    ]

rulesWithConstraints :: TestTree
rulesWithConstraints = testCase "Rule with constraints" $
  let world = World
        { rules = Set.fromList
                   [ [rule|valid_date("file1") <- time(#ambient, $0), resource(#ambient, "file1"), $0 <= 2019-12-04T09:46:41+00:00|]
                   , [rule|valid_date("file2") <- time(#ambient, $0), resource(#ambient, "file2"), $0 <= 2010-12-04T09:46:41+00:00|]
                   ]
        , facts = Set.fromList
                   [ [fact|time(#ambient, 2019-12-04T01:00:00Z)|]
                   , [fact|resource(#ambient, "file1")|]
                   , [fact|resource(#ambient, "file2")|]
                   ]
        }
   in runFactGeneration defaultLimits world @?= Right (Set.fromList
        [ [fact|time(#ambient, 2019-12-04T01:00:00Z)|]
        , [fact|resource(#ambient, "file1")|]
        , [fact|resource(#ambient, "file2")|]
        , [fact|valid_date("file1")|]
        ])

ruleHeadWithNoVars :: TestTree
ruleHeadWithNoVars = testCase "Rule head with no variables" $
  let world = World
        { rules = Set.fromList
                   [ [rule|operation(#authority,#read) <- test($yolo, #nothing)|]
                   ]
        , facts = Set.fromList
                   [ [fact|test(#whatever, #notNothing)|]
                   ]
        }
   in runFactGeneration defaultLimits world @?= Right (Set.fromList
        [ [fact|test(#whatever, #notNothing)|]
        ])

limits :: TestTree
limits =
  let world = World
        { rules = Set.fromList
                   [ [rule|ancestor($a,$b) <- parent($a,$c), ancestor($c,$b)|]
                   , [rule|ancestor($a,$b) <- parent($a,$b)|]
                   ]
        , facts = Set.fromList
                   [ [fact|parent("alice", "bob")|]
                   , [fact|parent("bob", "jean-pierre")|]
                   , [fact|parent("bob", "marielle")|]
                   , [fact|parent("alice", "toto")|]
                   ]
        }
      factLimits = defaultLimits { maxFacts = 10 }
      iterLimits = defaultLimits { maxIterations = 2 }
   in testGroup "Facts generation limits"
        [ testCase "max facts" $
            runFactGeneration factLimits world @?= Left Facts
        , testCase "max iterations" $
            runFactGeneration iterLimits world @?= Left Iterations
        ]
