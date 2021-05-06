{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Spec.Executor (specs) where


import           Data.Set         as Set
import           Test.Tasty
import           Test.Tasty.HUnit

import           Datalog.Executor
import           Datalog.Parser   (predicate, rule)

specs :: TestTree
specs = testGroup "Datalog evaluation"
  [ grandparent
  ]

grandparent :: TestTree
grandparent = testCase "Basic grandparent rule" $
  let world = World
        { rules = Set.fromList
                   [ [rule|grandparent($a,$b) <- parent($a,$c), parent($c,$b)|]
                   ]
        , facts = Set.fromList
                   [ [predicate|parent("alice", "bob")|]
                   , [predicate|parent("bob", "jean-pierre")|]
                   , [predicate|parent("alice", "toto")|]
                   ]
        }
   in computeAllFacts world @?= Set.fromList
        [ [predicate|parent("alice", "bob")|]
        , [predicate|parent("bob", "jean-pierre")|]
        , [predicate|parent("alice", "toto")|]
        , [predicate|grandparent("alice", "jean-pierre")|]
        ]
