{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TupleSections              #-}
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
  , MatchedQuery (..)
  , Scoped
  , FactGroup (..)
  , countFacts
  , toScopedFacts
  , fromScopedFacts
  , keepAuthorized'
  , defaultLimits
  , evaluateExpression
  , extractVariables

  --
  , getFactsForRule
  , checkCheck
  , checkPolicy
  , getBindingsForRuleBody
  , getCombinations
  ) where

import           Control.Monad            (join, mfilter, zipWithM)
import           Data.Bitraversable       (bitraverse)
import qualified Data.ByteString          as ByteString
import           Data.Foldable            (fold)
import           Data.Functor.Compose     (Compose (..))
import           Data.List.NonEmpty       (NonEmpty)
import qualified Data.List.NonEmpty       as NE
import           Data.Map.Strict          (Map, (!?))
import qualified Data.Map.Strict          as Map
import           Data.Maybe               (fromMaybe, isJust, mapMaybe)
import           Data.Set                 (Set)
import qualified Data.Set                 as Set
import           Data.Text                (Text, isInfixOf, unpack)
import qualified Data.Text                as Text
import           Data.Void                (absurd)
import           Numeric.Natural          (Natural)
import qualified Text.Regex.TDFA          as Regex
import qualified Text.Regex.TDFA.Text     as Regex
import           Validation               (Validation (..), failure)

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Utils       (maybeToRight)

-- | A variable name
type Name = Text

-- | A list of bound variables, with the associated value
type Bindings  = Map Name Value

-- | A datalog query that was matched, along with the values
-- that matched
data MatchedQuery
  = MatchedQuery
  { matchedQuery :: Query
  , bindings     :: Set Bindings
  }
  deriving (Eq, Show)

-- | The result of matching the checks and policies against all the available
-- facts.
data ResultError
  = NoPoliciesMatched [Check]
  -- ^ No policy matched. additionally some checks may have failed
  | FailedChecks      (NonEmpty Check)
  -- ^ An allow rule matched, but at least one check failed
  | DenyRuleMatched   [Check] MatchedQuery
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
  | InvalidRule
  -- ^ Some rules were malformed: every variable present in their head must
  -- appear in their body
  | ResultError ResultError
  -- ^ The evaluation ran to completion, but checks and policies were not
  -- fulfilled.
  deriving (Eq, Show)

-- | Settings for the executor runtime restrictions.
-- See `defaultLimits` for default values.
data Limits
  = Limits
  { maxFacts      :: Int
  -- ^ maximum number of facts that can be produced before throwing `TooManyFacts`
  , maxIterations :: Int
  -- ^ maximum number of iterations before throwing `TooManyIterations`
  , maxTime       :: Int
  -- ^ maximum duration the verification can take (in μs)
  , allowRegexes  :: Bool
  -- ^ whether or not allowing `.matches()` during verification (untrusted regex computation
  -- can enable DoS attacks). This security risk is mitigated by the 'maxTime' setting.
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
  }

type Scoped a = (Set Natural, a)

newtype FactGroup = FactGroup { getFactGroup :: Map (Set Natural) (Set Fact) }
  deriving newtype (Eq)

instance Show FactGroup where
  show (FactGroup groups) =
    let showGroup (origin, facts) = unlines
          [ "For origin: " <> show (Set.toList origin)
          , "Facts: \n" <> unlines (unpack . renderFact <$> Set.toList facts)
          ]
     in unlines $ showGroup <$> Map.toList groups

instance Semigroup FactGroup where
  FactGroup f1 <> FactGroup f2 = FactGroup $ Map.unionWith (<>) f1 f2
instance Monoid FactGroup where
  mempty = FactGroup mempty

keepAuthorized :: FactGroup -> Set Natural -> FactGroup
keepAuthorized (FactGroup facts) authorizedOrigins =
  let isAuthorized k _ = k `Set.isSubsetOf` authorizedOrigins
   in FactGroup $ Map.filterWithKey isAuthorized facts

keepAuthorized' :: FactGroup -> Maybe RuleScope -> Natural -> FactGroup
keepAuthorized' factGroup mScope currentBlockId =
  let scope = fromMaybe OnlyAuthority mScope
   in case scope of
        OnlyAuthority  -> keepAuthorized factGroup (Set.fromList [0, currentBlockId])
        Previous       -> keepAuthorized factGroup (Set.fromList [0..currentBlockId])
        UnsafeAny      -> factGroup
        OnlyBlocks ids -> keepAuthorized factGroup (Set.insert currentBlockId ids)

toScopedFacts :: FactGroup -> Set (Scoped Fact)
toScopedFacts (FactGroup factGroups) =
  let distributeScope scope facts = Set.map (scope,) facts
   in foldMap (uncurry distributeScope) $ Map.toList factGroups

fromScopedFacts :: Set (Scoped Fact) -> FactGroup
fromScopedFacts = FactGroup . Map.fromListWith (<>) . Set.toList . Set.map (fmap Set.singleton)

countFacts :: FactGroup -> Int
countFacts (FactGroup facts) = sum $ Set.size <$> Map.elems facts

checkCheck :: Limits -> Natural -> FactGroup -> Check -> Validation (NonEmpty Check) ()
checkCheck l checkBlockId facts items =
  if any (isJust . isQueryItemSatisfied l checkBlockId facts) items
  then Success ()
  else failure items

checkPolicy :: Limits -> FactGroup -> Policy -> Maybe (Either MatchedQuery MatchedQuery)
checkPolicy l facts (pType, query) =
  let bindings = fold $ mapMaybe (isQueryItemSatisfied l 0 facts) query
   in if not (null bindings)
      then Just $ case pType of
        Allow -> Right $ MatchedQuery{matchedQuery = query, bindings}
        Deny  -> Left $ MatchedQuery{matchedQuery = query, bindings}
      else Nothing

isQueryItemSatisfied :: Limits -> Natural -> FactGroup -> QueryItem' 'RegularString -> Maybe (Set Bindings)
isQueryItemSatisfied l blockId allFacts QueryItem{qBody, qExpressions, qScope} =
  let removeScope = Set.map snd
      facts = toScopedFacts $ keepAuthorized' allFacts qScope blockId
      bindings = removeScope $ getBindingsForRuleBody l facts qBody qExpressions
   in if Set.size bindings > 0
      then Just bindings
      else Nothing

-- | Given a rule and a set of available (scoped) facts, we find all fact
-- combinations that match the rule body, and generate new facts by applying
-- the bindings to the rule head (while keeping track of the facts origins)
getFactsForRule :: Limits -> Set (Scoped Fact) -> Rule -> Set (Scoped Fact)
getFactsForRule l facts Rule{rhead, body, expressions} =
  let legalBindings :: Set (Scoped Bindings)
      legalBindings = getBindingsForRuleBody l facts body expressions
      newFacts = mapMaybe (applyBindings rhead) $ Set.toList legalBindings
   in Set.fromList newFacts

-- | Given a set of scoped facts and a rule body, we generate a set of variable
-- bindings that satisfy the rule clauses (predicates match, and expression constraints
-- are fulfilled)
getBindingsForRuleBody :: Limits -> Set (Scoped Fact) -> [Predicate] -> [Expression] -> Set (Scoped Bindings)
getBindingsForRuleBody l facts body expressions =
  let -- gather bindings from all the facts that match the query's predicates
      candidateBindings = getCandidateBindings facts body
      allVariables = extractVariables body
      -- only keep bindings combinations where each variable has a single possible match
      legalBindingsForFacts = reduceCandidateBindings allVariables candidateBindings
      -- only keep bindings that satisfy the query expressions
   in Set.filter (\b -> all (satisfies l b) expressions) legalBindingsForFacts

satisfies :: Limits
          -> Scoped Bindings
          -> Expression
          -> Bool
satisfies l b e = evaluateExpression l (snd b) e == Right (LBool True)

extractVariables :: [Predicate] -> Set Name
extractVariables predicates =
  let keepVariable = \case
        Variable name -> Just name
        _             -> Nothing
      extractVariables' Predicate{terms} = mapMaybe keepVariable terms
   in Set.fromList $ extractVariables' =<< predicates


applyBindings :: Predicate -> Scoped Bindings -> Maybe (Scoped Fact)
applyBindings p@Predicate{terms} (origins, bindings) =
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
   in (\nt -> (origins, p { terms = nt})) <$> newTerms

-- | Given a list of possible matches for each predicate,
-- give all the combinations of one match per predicate,
-- keeping track of the origin of each match
getCombinations :: [[Scoped Bindings]] -> [Scoped [Bindings]]
getCombinations = getCompose . traverse Compose

-- | merge a list of bindings, only keeping variables where
-- bindings are consistent
mergeBindings :: [Bindings] -> Bindings
mergeBindings =
  -- group all the values unified with each variable
  let combinations :: [Bindings] -> Map Name (NonEmpty Value)
      combinations = Map.unionsWith (<>) . fmap (fmap pure)
      sameValues = fmap NE.head . mfilter ((== 1) . length) . Just . NE.nub
  -- only keep consistent matches, where each variable takes a single value
      keepConsistent = Map.mapMaybe sameValues
   in keepConsistent . combinations

-- | given a set of bindings for each predicate of a query,
-- only keep combinations where every variable matches exactly
-- one value. This rejects both inconsitent bindings (where the
-- same variable
reduceCandidateBindings :: Set Name
                        -> [Set (Scoped Bindings)]
                        -> Set (Scoped Bindings)
reduceCandidateBindings allVariables matches =
  let allCombinations :: [(Set Natural, [Bindings])]
      allCombinations = getCombinations $ Set.toList <$> matches
      isComplete :: Scoped Bindings -> Bool
      isComplete = (== allVariables) . Set.fromList . Map.keys . snd
   in Set.fromList $ filter isComplete $ fmap mergeBindings <$> allCombinations

-- | Given a set of facts and a series of predicates, return, for each fact,
-- a set of bindings corresponding to matched facts
getCandidateBindings :: Set (Scoped Fact)
                     -> [Predicate]
                     -> [Set (Scoped Bindings)]
getCandidateBindings facts predicates =
   let mapMaybeS :: (Ord a, Ord b) => (a -> Maybe b) -> Set a -> Set b
       mapMaybeS f = foldMap (foldMap Set.singleton . f)
       keepFacts :: Predicate -> Set (Scoped Bindings)
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

-- | Given a predicate and a fact, try to match the fact to the predicate,
-- and, in case of success, return the corresponding bindings
factMatchesPredicate :: Predicate -> Scoped Fact -> Maybe (Scoped Bindings)
factMatchesPredicate Predicate{name = predicateName, terms = predicateTerms }
                     ( factOrigins
                     , Predicate{name = factName, terms = factTerms }
                     ) =
  let namesMatch = predicateName == factName
      lengthsMatch = length predicateTerms == length factTerms
      allMatches = zipWithM compatibleMatch predicateTerms factTerms
      -- given a term and a value, generate (possibly empty) bindings if
      -- they can be unified:
      --   - if the term is a variable, then it can be unified with the value,
      --     generating a new binding pair
      --   - if the term is equal to the value then it can be unified, but no bindings
      --     are generated
      --   - if the term is a different value, then they can't be unified
      compatibleMatch :: Term -> Value -> Maybe Bindings
      compatibleMatch (Variable vname) value = Just (Map.singleton vname value)
      compatibleMatch t t' | isSame t t' = Just mempty
                | otherwise   = Nothing
   in if namesMatch && lengthsMatch
      then (factOrigins,) . mergeBindings <$> allMatches
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
evalBinary _ Add (LString t) (LString t') = pure $ LString (t <> t')
evalBinary _ Add _ _ = Left "Only integers and strings support addition"
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
evalBinary _ Contains (LString t) (LString t') = pure $ LBool (t' `isInfixOf` t)
evalBinary _ Contains _ _ = Left "Only sets and strings support `.contains()`"
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
