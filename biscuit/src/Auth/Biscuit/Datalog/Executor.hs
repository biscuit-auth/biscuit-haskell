{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-|
  Module      : Auth.Biscuit.Datalog.Executor
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  The Datalog engine, tasked with deriving new facts from existing facts and rules, as well as matching available facts against checks and policies
-}
module Auth.Biscuit.Datalog.Executor
  ( ExecutionError (..)
  , Limits (..)
  , ResultError (..)
  , Bindings
  , Name
  , defaultLimits
  , evaluateExpression

  --
  , getFactsForRule
  , checkCheck
  , checkPolicy
  , getBindingsForRuleBody
  ) where

import           Control.Monad            (join, mfilter, zipWithM)
import           Data.Bitraversable       (bitraverse)
import qualified Data.ByteString          as ByteString
import           Data.List.NonEmpty       (NonEmpty)
import qualified Data.List.NonEmpty       as NE
import           Data.Map.Strict          (Map, (!?))
import qualified Data.Map.Strict          as Map
import           Data.Maybe               (isJust, mapMaybe)
import           Data.Set                 (Set)
import qualified Data.Set                 as Set
import           Data.Text                (Text)
import qualified Data.Text                as Text
import           Data.Void                (absurd)
import qualified Text.Regex.TDFA          as Regex
import qualified Text.Regex.TDFA.Text     as Regex
import           Validation               (Validation (..), failure)

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Utils       (maybeToRight)

-- | A variable name
type Name = Text

-- | A list of bound variables, with the associated value
type Bindings  = Map Name Value

-- | The result of matching the checks and policies against all the available
-- facts.
data ResultError
  = NoPoliciesMatched [Check]
  -- ^ No policy matched. additionally some checks may have failed
  | FailedChecks      (NonEmpty Check)
  -- ^ An allow rule matched, but at least one check failed
  | DenyRuleMatched   [Check] Query
  -- ^ A deny rule matched. additionally some checks may have failed
  deriving (Eq, Show)

-- | An error that can happen while running a datalog verification.
-- The datalog computation itself can be aborted by runtime failsafe
-- mechanisms, or it can run to completion but fail to fullfil checks
-- and policies ('ResultError').
data ExecutionError
  = Timeout
  -- ^ Verification took too much time
  | TooManyFacts
  -- ^ Too many facts were generated during evaluation
  | TooManyIterations
  -- ^ Evaluation did not converge in the alloted number of iterations
  | FactsInBlocks
  -- ^ Some blocks contained either rules or facts while it was forbidden
  | ResultError ResultError
  -- ^ The evaluation ran to completion, but checks and policies were not
  -- fulfilled.
  deriving (Eq, Show)

-- | Settings for the executor runtime restrictions.
-- See `defaultLimits` for default values.
data Limits
  = Limits
  { maxFacts        :: Int
  -- ^ maximum number of facts that can be produced before throwing `TooManyFacts`
  , maxIterations   :: Int
  -- ^ maximum number of iterations before throwing `TooManyIterations`
  , maxTime         :: Int
  -- ^ maximum duration the verification can take (in μs)
  , allowRegexes    :: Bool
  -- ^ whether or not allowing `.matches()` during verification (untrusted regex computation
  -- can enable DoS attacks). This security risk is mitigated by the 'maxTime' setting.
  , allowBlockFacts :: Bool
  -- ^ whether or not accept facts and rules in blocks
  }
  deriving (Eq, Show)

-- | Default settings for the executor restrictions.
--   - 1000 facts
--   - 100 iterations
--   - 1000μs max
--   - regexes are allowed
--   - facts and rules are allowed in blocks
defaultLimits :: Limits
defaultLimits = Limits
  { maxFacts = 1000
  , maxIterations = 100
  , maxTime = 1000
  , allowRegexes = True
  , allowBlockFacts = True
  }

checkCheck :: Limits -> Set Fact -> Check -> Validation (NonEmpty Check) ()
checkCheck l facts items =
  if any (isQueryItemSatisfied l facts) items
  then Success ()
  else failure items

checkPolicy :: Limits -> Set Fact -> Policy -> Maybe (Either Query Query)
checkPolicy l facts (pType, items) =
  if any (isQueryItemSatisfied l facts) items
  then Just $ case pType of
    Allow -> Right items
    Deny  -> Left items
  else Nothing

isQueryItemSatisfied :: Limits -> Set Fact -> QueryItem' 'RegularString -> Bool
isQueryItemSatisfied l facts QueryItem{qBody, qExpressions} =
  let bindings = getBindingsForRuleBody l facts qBody qExpressions
   in Set.size bindings > 0

getFactsForRule :: Limits -> Set Fact -> Rule -> Set Fact
getFactsForRule l facts Rule{rhead, body, expressions} =
  let legalBindings = getBindingsForRuleBody l facts body expressions
      newFacts = mapMaybe (applyBindings rhead) $ Set.toList legalBindings
   in Set.fromList newFacts

getBindingsForRuleBody :: Limits -> Set Fact -> [Predicate] -> [Expression] -> Set Bindings
getBindingsForRuleBody l facts body expressions =
  let candidateBindings = getCandidateBindings facts body
      allVariables = extractVariables body
      legalBindingsForFacts = reduceCandidateBindings allVariables candidateBindings
   in Set.filter (\b -> all (satisfies l b) expressions) legalBindingsForFacts

satisfies :: Limits
          -> Bindings
          -> Expression
          -> Bool
satisfies l b e = evaluateExpression l b e == Right (LBool True)

extractVariables :: [Predicate] -> Set Name
extractVariables predicates =
  let keepVariable = \case
        Variable name -> Just name
        _             -> Nothing
      extractVariables' Predicate{terms} = mapMaybe keepVariable terms
   in Set.fromList $ extractVariables' =<< predicates


applyBindings :: Predicate -> Bindings -> Maybe Fact
applyBindings p@Predicate{terms} bindings =
  let newTerms = traverse replaceTerm terms
      replaceTerm :: Term -> Maybe Value
      replaceTerm (Variable n)  = Map.lookup n bindings
      replaceTerm (LInteger t)  = Just $ LInteger t
      replaceTerm (LString t)   = Just $ LString t
      replaceTerm (LDate t)     = Just $ LDate t
      replaceTerm (LBytes t)    = Just $ LBytes t
      replaceTerm (LBool t)     = Just $ LBool t
      replaceTerm (TermSet t)   = Just $ TermSet t
      replaceTerm (Antiquote t) = absurd t
   in (\nt -> p { terms = nt}) <$> newTerms

getCombinations :: [[a]] -> [[a]]
getCombinations (x:xs) = do
  y <- x
  (y:) <$> getCombinations xs
getCombinations []     = [[]]

mergeBindings :: [Bindings] -> Bindings
mergeBindings =
  -- group all the values unified with each variable
  let combinations = Map.unionsWith (<>) . fmap (fmap pure)
      sameValues = fmap NE.head . mfilter ((== 1) . length) . Just . NE.nub
  -- only keep
      keepConsistent = Map.mapMaybe sameValues
   in keepConsistent . combinations

reduceCandidateBindings :: Set Name
                        -> [Set Bindings]
                        -> Set Bindings
reduceCandidateBindings allVariables matches =
  let allCombinations :: [[Bindings]]
      allCombinations = getCombinations $ Set.toList <$> matches
      isComplete :: Bindings -> Bool
      isComplete = (== allVariables) . Set.fromList . Map.keys
   in Set.fromList $ filter isComplete $ mergeBindings <$> allCombinations

getCandidateBindings :: Set Fact
                     -> [Predicate]
                     -> [Set Bindings]
getCandidateBindings facts predicates =
   let mapMaybeS f = foldMap (foldMap Set.singleton . f)
       keepFacts p = mapMaybeS (factMatchesPredicate p) facts
    in keepFacts <$> predicates

isSame :: Term -> Value -> Bool
isSame (LInteger t) (LInteger t') = t == t'
isSame (LString t)  (LString t')  = t == t'
isSame (LDate t)    (LDate t')    = t == t'
isSame (LBytes t)   (LBytes t')   = t == t'
isSame (LBool t)    (LBool t')    = t == t'
isSame (TermSet t)  (TermSet t')  = t == t'
isSame _ _                        = False

factMatchesPredicate :: Predicate -> Fact -> Maybe Bindings
factMatchesPredicate Predicate{name = predicateName, terms = predicateTerms }
                     Predicate{name = factName, terms = factTerms } =
  let namesMatch = predicateName == factName
      lengthsMatch = length predicateTerms == length factTerms
      allMatches = zipWithM yolo predicateTerms factTerms
      yolo :: Term -> Value -> Maybe Bindings
      yolo (Variable vname) value = Just (Map.singleton vname value)
      yolo t t' | isSame t t' = Just mempty
                | otherwise   = Nothing
   in if namesMatch && lengthsMatch
      then mergeBindings <$> allMatches
      else Nothing

applyVariable :: Bindings
              -> Term
              -> Either String Value
applyVariable bindings = \case
  Variable n  -> maybeToRight "Unbound variable" $ bindings !? n
  LInteger t  -> Right $ LInteger t
  LString t   -> Right $ LString t
  LDate t     -> Right $ LDate t
  LBytes t    -> Right $ LBytes t
  LBool t     -> Right $ LBool t
  TermSet t   -> Right $ TermSet t
  Antiquote v -> absurd v

evalUnary :: Unary -> Value -> Either String Value
evalUnary Parens t = pure t
evalUnary Negate (LBool b) = pure (LBool $ not b)
evalUnary Negate _ = Left "Only booleans support negation"
evalUnary Length (LString t) = pure . LInteger $ Text.length t
evalUnary Length (LBytes bs) = pure . LInteger $ ByteString.length bs
evalUnary Length (TermSet s) = pure . LInteger $ Set.size s
evalUnary Length _ = Left "Only strings, bytes and sets support `.length()`"

evalBinary :: Limits -> Binary -> Value -> Value -> Either String Value
-- eq / ord operations
evalBinary _ Equal (LInteger i) (LInteger i') = pure $ LBool (i == i')
evalBinary _ Equal (LString t) (LString t')   = pure $ LBool (t == t')
evalBinary _ Equal (LDate t) (LDate t')       = pure $ LBool (t == t')
evalBinary _ Equal (LBytes t) (LBytes t')     = pure $ LBool (t == t')
evalBinary _ Equal (LBool t) (LBool t')       = pure $ LBool (t == t')
evalBinary _ Equal (TermSet t) (TermSet t')   = pure $ LBool (t == t')
evalBinary _ Equal _ _                        = Left "Equality mismatch"
evalBinary _ LessThan (LInteger i) (LInteger i') = pure $ LBool (i < i')
evalBinary _ LessThan (LDate t) (LDate t')       = pure $ LBool (t < t')
evalBinary _ LessThan _ _                        = Left "< mismatch"
evalBinary _ GreaterThan (LInteger i) (LInteger i') = pure $ LBool (i > i')
evalBinary _ GreaterThan (LDate t) (LDate t')       = pure $ LBool (t > t')
evalBinary _ GreaterThan _ _                        = Left "> mismatch"
evalBinary _ LessOrEqual (LInteger i) (LInteger i') = pure $ LBool (i <= i')
evalBinary _ LessOrEqual (LDate t) (LDate t')       = pure $ LBool (t <= t')
evalBinary _ LessOrEqual _ _                        = Left "<= mismatch"
evalBinary _ GreaterOrEqual (LInteger i) (LInteger i') = pure $ LBool (i >= i')
evalBinary _ GreaterOrEqual (LDate t) (LDate t')       = pure $ LBool (t >= t')
evalBinary _ GreaterOrEqual _ _                        = Left ">= mismatch"
-- string-related operations
evalBinary _ Prefix (LString t) (LString t') = pure $ LBool (t' `Text.isPrefixOf` t)
evalBinary _ Prefix _ _                      = Left "Only strings support `.starts_with()`"
evalBinary _ Suffix (LString t) (LString t') = pure $ LBool (t' `Text.isSuffixOf` t)
evalBinary _ Suffix _ _                      = Left "Only strings support `.ends_with()`"
evalBinary Limits{allowRegexes} Regex  (LString t) (LString r) | allowRegexes = regexMatch t r
                                                               | otherwise    = Left "Regex evaluation is disabled"
evalBinary _ Regex _ _                       = Left "Only strings support `.matches()`"
-- num operations
evalBinary _ Add (LInteger i) (LInteger i') = pure $ LInteger (i + i')
evalBinary _ Add _ _ = Left "Only integers support addition"
evalBinary _ Sub (LInteger i) (LInteger i') = pure $ LInteger (i - i')
evalBinary _ Sub _ _ = Left "Only integers support subtraction"
evalBinary _ Mul (LInteger i) (LInteger i') = pure $ LInteger (i * i')
evalBinary _ Mul _ _ = Left "Only integers support multiplication"
evalBinary _ Div (LInteger _) (LInteger 0) = Left "Divide by 0"
evalBinary _ Div (LInteger i) (LInteger i') = pure $ LInteger (i `div` i')
evalBinary _ Div _ _ = Left "Only integers support division"
-- boolean operations
evalBinary _ And (LBool b) (LBool b') = pure $ LBool (b && b')
evalBinary _ And _ _ = Left "Only booleans support &&"
evalBinary _ Or (LBool b) (LBool b') = pure $ LBool (b || b')
evalBinary _ Or _ _ = Left "Only booleans support ||"
-- set operations
evalBinary _ Contains (TermSet t) (TermSet t') = pure $ LBool (Set.isSubsetOf t' t)
evalBinary _ Contains (TermSet t) t' = case toSetTerm t' of
    Just t'' -> pure $ LBool (Set.member t'' t)
    Nothing  -> Left "Sets cannot contain nested sets nor variables"
evalBinary _ Contains _ _ = Left "Only sets support `.contains()`"
evalBinary _ Intersection (TermSet t) (TermSet t') = pure $ TermSet (Set.intersection t t')
evalBinary _ Intersection _ _ = Left "Only sets support `.intersection()`"
evalBinary _ Union (TermSet t) (TermSet t') = pure $ TermSet (Set.union t t')
evalBinary _ Union _ _ = Left "Only sets support `.union()`"

regexMatch :: Text -> Text -> Either String Value
regexMatch text regexT = do
  regex  <- Regex.compile Regex.defaultCompOpt Regex.defaultExecOpt regexT
  result <- Regex.execute regex text
  pure . LBool $ isJust result

-- | Given bindings for variables, reduce an expression to a single
-- datalog value
evaluateExpression :: Limits
                   -> Bindings
                   -> Expression
                   -> Either String Value
evaluateExpression l b = \case
    EValue term -> applyVariable b term
    EUnary op e' -> evalUnary op =<< evaluateExpression l b e'
    EBinary op e' e'' -> uncurry (evalBinary l op) =<< join bitraverse (evaluateExpression l b) (e', e'')
