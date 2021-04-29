{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Datalog.Executor where

import           Debug.Trace

import           Control.Monad      (mfilter)
import           Control.Monad      (join)
import qualified Data.List.NonEmpty as NE
import           Data.Map.Strict    (Map)
import qualified Data.Map.Strict    as Map
import           Data.Maybe         (mapMaybe)
import           Data.Set           (Set)
import qualified Data.Set           as Set
import           Data.Text          (Text, intercalate, unpack)
import           Datalog.AST
import           Datalog.Parser     (predicate, rule)

type Value = ID -- a term that is *not* a variable
type Name = Text -- a variable name

myWorld :: World
myWorld = World
  { rules = Set.fromList
             [ [rule|grandparent($a,$b) <- parent($a,$c), parent($c,$b)|]
             ]
  , facts = Set.fromList
             [ [predicate|parent("alice", "bob")|]
             , [predicate|parent("bob", "jean-pierre")|]
             , [predicate|parent("alice", "toto")|]
             ]
  }

data World
 = World
 { rules :: Set Rule
 , facts :: Set Fact
 }

instance Show World where
  show World{rules,facts} = unpack $ intercalate "\n" $ join $
    [ [ "Rules" ]
    , renderRule <$> (Set.toList rules)
    , [ "Facts" ]
    , renderPredicate <$> (Set.toList facts)
    ]

rF :: Set Fact -> IO ()
rF = putStrLn . unpack . intercalate "\n" . fmap renderPredicate . Set.toList

computeAllFacts :: World -> Set Fact
computeAllFacts w@World{facts} =
  let newFacts = extend w
   in if null newFacts
      then facts
      else computeAllFacts (w { facts = facts <> newFacts })

extend :: World -> Set Fact
extend World{rules, facts} =
  let allNewFacts = foldMap (getFactsForRule facts) rules
   in Set.difference allNewFacts facts

getFactsForRule :: Set Fact -> Rule -> Set Fact
getFactsForRule facts Rule{rhead, body} =
  let candidateBindings = getCandidateBindings facts body
      allVariables = extractVariables body
      legalBindings = reduceCandidateBindings allVariables candidateBindings
      newFacts = mapMaybe (applyBindings rhead) $ Set.toList legalBindings
   in Set.fromList newFacts

extractVariables :: [Predicate] -> Set Name
extractVariables predicates =
  let keepVariable = \case
        Variable name -> Just name
        _ -> Nothing
      extractVariables' Predicate{terms} = mapMaybe keepVariable terms
   in Set.fromList $ extractVariables' =<< predicates


applyBindings :: Predicate -> Map Name Value -> Maybe Fact
applyBindings p@Predicate{terms} bindings =
  let newTerms = traverse replaceTerm terms
      replaceTerm :: ID -> Maybe ID
      replaceTerm (Variable n) = Map.lookup n bindings
      replaceTerm t            = Just t
   in (\nt -> p { terms = nt}) <$> newTerms

{-
-- pred 1
[ {(a => "toto", b => "tutu"), (a => "titi", b => "tutu")}
-- pred 2
, {(b => "tutu", c => "toto"), (b => "toto", c => "tata")}
-- pred 3
, {(c => "toto", d => "tata"), (c => "toto", d => "tyty")}
]

res
{ (a => "toto", b => "tutu", c => "toto")
, (a => "titi", b => "tutu", c => "toto")
}
-}

getCombinations :: [[a]] -> [[a]]
getCombinations (x:xs) = do
  y <- x
  (y:) <$> getCombinations xs
getCombinations []     = [[]]

traceBindings :: Map Name ID -> Map Name ID
traceBindings m =
  let out = unpack $ intercalate "," $ outB <$> Map.toList m
      outB (n, v) = n <> " => " <> renderId v
   in trace ("==\n" <> out <> "\n==") m

mergeBindings :: [Map Name ID] -> Map Name ID
mergeBindings =
  -- group all the values unified with each variable
  let combinations = Map.unionsWith (<>) . fmap (fmap pure)
      sameValues = fmap NE.head . mfilter ((== 1) . length) . Just . NE.nub
  -- only keep
      keepConsistent = Map.mapMaybe sameValues
   in keepConsistent . combinations

reduceCandidateBindings :: Set Name
                        -> [Set (Map Name ID)]
                        -> Set (Map Name ID)
reduceCandidateBindings allVariables matches =
  let allCombinations :: [[Map Name ID]]
      allCombinations = getCombinations $ Set.toList <$> matches
      isPartial :: Map Name ID -> Bool
      isPartial = (== allVariables) . Set.fromList . Map.keys
   in Set.fromList $ filter isPartial $ mergeBindings <$> allCombinations

getCandidateBindings :: Set Fact
                     -> [Predicate]
                     -> [Set (Map Name ID)]
getCandidateBindings facts predicates =
   let keepFacts p = Set.map (factMatchesPredicate p) facts
    in keepFacts <$> predicates

factMatchesPredicate :: Predicate -> Fact -> Map Name ID
factMatchesPredicate Predicate{name = predicateName, terms = predicateTerms }
                     Predicate{name = factName, terms = factTerms } =
  let namesMatch = predicateName == factName
      lengthsMatch = length predicateTerms == length factTerms
      allMatches = sequenceA $ zipWith yolo predicateTerms factTerms
      yolo (Variable vname) value = Just (Map.singleton vname value)
      yolo t t' | t == t'   = Just mempty
                | otherwise = Nothing
   in if namesMatch && lengthsMatch
      then foldMap mergeBindings allMatches
      else mempty
