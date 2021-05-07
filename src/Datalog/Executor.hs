{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Datalog.Executor where

import           Debug.Trace

import           Control.Monad           (mfilter)
import           Control.Monad           (join)
import           Data.Bitraversable      (bitraverse)
import qualified Data.ByteString         as ByteString
import           Data.Either.Combinators (maybeToRight)
import qualified Data.List.NonEmpty      as NE
import           Data.Map.Strict         (Map, (!?))
import qualified Data.Map.Strict         as Map
import           Data.Maybe              (mapMaybe)
import           Data.Set                (Set)
import qualified Data.Set                as Set
import           Data.Text               (Text, intercalate, unpack)
import qualified Data.Text               as Text
import           Datalog.AST

type Value = ID -- a term that is *not* a variable
type Name = Text -- a variable name

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
getFactsForRule facts Rule{rhead, body, expressions} =
  let candidateBindings = getCandidateBindings facts body
      allVariables = extractVariables body
      legalBindingsForFacts = reduceCandidateBindings allVariables candidateBindings
      legalBindings = Set.filter (\b -> all (satisfies b) expressions) legalBindingsForFacts
      newFacts = mapMaybe (applyBindings rhead) $ Set.toList legalBindings
   in Set.fromList newFacts

satisfies :: Map Name ID
          -> Expression
          -> Bool
satisfies b e = evaluateExpression b e == Right (LBool True)

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

applyVariable :: Map Name ID
              -> ID
              -> Either String ID
applyVariable bindings = \case
  Variable n -> maybeToRight "Unbound variable" $ bindings !? n
  t          -> Right t

evalUnary :: Unary -> ID -> Either String ID
evalUnary Parens t = pure t
evalUnary Negate (LBool b) = pure (LBool $ not b)
evalUnary Negate _ = Left "Only booleans support negation"
evalUnary Length (LString t) = pure . LInteger $ Text.length t
evalUnary Length (LBytes bs) = pure . LInteger $ ByteString.length bs
evalUnary Length (TermSet s) = pure . LInteger $ Set.size s
evalUnary Length _ = Left "Only strings, bytes and sets support `.length()`"

evalBinary :: Binary -> ID -> ID -> Either String ID
-- eq / ord operations
evalBinary Equal (Symbol s) (Symbol s')     = pure $ LBool (s == s')
evalBinary Equal (LInteger i) (LInteger i') = pure $ LBool (i == i')
evalBinary Equal (LString t) (LString t')   = pure $ LBool (t == t')
evalBinary Equal (LDate t) (LDate t')       = pure $ LBool (t == t')
evalBinary Equal (LBytes t) (LBytes t')     = pure $ LBool (t == t')
evalBinary Equal (LBool t) (LBool t')       = pure $ LBool (t == t')
evalBinary Equal (TermSet t) (TermSet t')   = pure $ LBool (t == t')
evalBinary Equal _ _                        = Left "Equality mismatch"
evalBinary LessThan (LInteger i) (LInteger i') = pure $ LBool (i < i')
evalBinary LessThan (LDate t) (LDate t')       = pure $ LBool (t < t')
evalBinary LessThan _ _                        = Left "< mismatch"
evalBinary GreaterThan (LInteger i) (LInteger i') = pure $ LBool (i > i')
evalBinary GreaterThan (LDate t) (LDate t')       = pure $ LBool (t > t')
evalBinary GreaterThan _ _                        = Left "> mismatch"
evalBinary LessOrEqual (LInteger i) (LInteger i') = pure $ LBool (i <= i')
evalBinary LessOrEqual (LDate t) (LDate t')       = pure $ LBool (t <= t')
evalBinary LessOrEqual _ _                        = Left "<= mismatch"
evalBinary GreaterOrEqual (LInteger i) (LInteger i') = pure $ LBool (i >= i')
evalBinary GreaterOrEqual (LDate t) (LDate t')       = pure $ LBool (t >= t')
evalBinary GreaterOrEqual _ _                        = Left ">= mismatch"
-- string-related operations
evalBinary Prefix (LString t) (LString t') = pure $ LBool (t' `Text.isPrefixOf` t)
evalBinary Prefix _ _                      = Left "Only strings support `.starts_with()`"
evalBinary Suffix (LString t) (LString t') = pure $ LBool (t' `Text.isSuffixOf` t)
evalBinary Suffix _ _                      = Left "Only strings support `.ends_with()`"
evalBinary Regex  _ _                      = Left "Rexeges are not supported"
-- num operations
evalBinary Add (LInteger i) (LInteger i') = pure $ LInteger (i + i')
evalBinary Add _ _ = Left "Only integers support addition"
evalBinary Sub (LInteger i) (LInteger i') = pure $ LInteger (i - i')
evalBinary Sub _ _ = Left "Only integers support subtraction"
evalBinary Mul (LInteger i) (LInteger i') = pure $ LInteger (i * i')
evalBinary Mul _ _ = Left "Only integers support multiplication"
evalBinary Div (LInteger _) (LInteger 0) = Left "Divide by 0"
evalBinary Div (LInteger i) (LInteger i') = pure $ LInteger (i `div` i')
evalBinary Div _ _ = Left "Only integers support division"
-- boolean operations
evalBinary And (LBool b) (LBool b') = pure $ LBool (b && b')
evalBinary And _ _ = Left "Only booleans support &&"
evalBinary Or (LBool b) (LBool b') = pure $ LBool (b || b')
evalBinary Or _ _ = Left "Only booleans support ||"
-- set operations
evalBinary Contains (TermSet t) (TermSet t') = pure $ LBool (Set.isSubsetOf t' t)
evalBinary Contains (TermSet t) t' = case toSetTerm t' of
    Just t'' -> pure $ LBool (Set.member t'' t)
    Nothing  -> Left "Sets cannot contain nested sets nor variables"
evalBinary Contains _ _ = Left "Only sets support `.contains()`"
evalBinary Intersection (TermSet t) (TermSet t') = pure $ TermSet (Set.intersection t t')
evalBinary Intersection _ _ = Left "Only sets support `.intersection()`"
evalBinary Union (TermSet t) (TermSet t') = pure $ TermSet (Set.union t t')
evalBinary Union _ _ = Left "Only sets support `.union()`"

evaluateExpression :: Map Name ID
                   -> Expression
                   -> Either String ID
evaluateExpression b = \case
    EValue term -> applyVariable b term
    EUnary op e' -> evalUnary op =<< evaluateExpression b e'
    EBinary op e' e'' -> uncurry (evalBinary op) =<< join bitraverse (evaluateExpression b) (e', e'')
