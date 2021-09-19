{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
module Auth.Biscuit.Datalog.ScopedExecutor
  ( BlockWithRevocationId
  , runVerifier
  , runVerifierWithLimits
  , runVerifierNoTimeout
  , World (..)
  , computeAllFacts
  , runFactGeneration
  , PureExecError (..)
  , VerificationSuccess (..)
  ) where

import           Control.Monad                 (join, when)
import           Control.Monad.State           (StateT (..), get, lift, modify,
                                                put, runStateT)
import           Data.Bifunctor                (first)
import           Data.ByteString               (ByteString)
import           Data.Foldable                 (traverse_)
import           Data.List.NonEmpty            (NonEmpty, nonEmpty)
import qualified Data.List.NonEmpty            as NE
import           Data.Maybe                    (mapMaybe)
import           Data.Set                      (Set)
import qualified Data.Set                      as Set
import           Data.Text                     (intercalate, unpack)
import           Validation                    (Validation (..), validation)

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Executor (ExecutionError (..),
                                                Limits (..), ResultError (..),
                                                checkCheck, checkPolicy,
                                                defaultLimits, getFactsForRule)
import           Auth.Biscuit.Datalog.Parser   (fact)
import           Auth.Biscuit.Timer            (timer)

type BlockWithRevocationId = (Block, ByteString)

data PureExecError = Facts | Iterations
  deriving (Eq, Show)

data ComputeState
  = ComputeState
  { sFacts          :: Set Fact
  , sAuthorityFacts :: Set Fact
  , sIterations     :: Int
  , sLimits         :: Limits
  , sFailedChecks   :: [Check]
  , sPolicyResult   :: Either (Maybe Query) Query
  }

mkInitState :: Limits -> ComputeState
mkInitState sLimits = ComputeState
  { sFacts = Set.empty -- no facts have been generated yet
  , sAuthorityFacts = Set.empty -- no authority facts have been generated yet
  , sIterations = 0    -- no evaluation iteration has taken place yet
  , sLimits            -- this field is read-only
  , sFailedChecks = [] -- no checks have failed yet
  , sPolicyResult = Left Nothing -- no policies have matched yet
  }

data World
  = World
  { facts :: Set Fact
  , rules :: Set Rule
  }

instance Semigroup World where
  w1 <> w2 = World
               { rules = rules w1 <> rules w2
               , facts = facts w1 <> facts w2
               }

instance Monoid World where
  mempty = World mempty mempty

instance Show World where
  show World{..} = unpack . intercalate "\n" $ join
    [ [ "Block Rules" ]
    , renderRule <$> Set.toList rules
    , [ "Facts" ]
    , renderFact <$> Set.toList facts
    ]

data VerificationSuccess
  = VerificationSuccess
  { matchedAllowQuery :: Query
  , authorityFacts    :: Set Fact
  , allGeneratedFacts :: Set Fact
  }
  deriving (Eq, Show)

withFacts :: World -> Set Fact -> World
withFacts w@World{facts} newFacts = w { facts = newFacts <> facts }

-- | Given a series of blocks and a verifier, ensure that all
-- the checks and policies match
runVerifier :: BlockWithRevocationId
            -- ^ The authority block
            -> [BlockWithRevocationId]
            -- ^ The extra blocks
            -> Verifier
            -- ^ A verifier
            -> IO (Either ExecutionError VerificationSuccess)
runVerifier = runVerifierWithLimits defaultLimits

-- | Given a series of blocks and a verifier, ensure that all
-- the checks and policies match, with provided execution
-- constraints
runVerifierWithLimits :: Limits
                      -- ^ custom limits
                      -> BlockWithRevocationId
                      -- ^ The authority block
                      -> [BlockWithRevocationId]
                      -- ^ The extra blocks
                      -> Verifier
                      -- ^ A verifier
                      -> IO (Either ExecutionError VerificationSuccess)
runVerifierWithLimits l@Limits{..} authority blocks v = do
  resultOrTimeout <- timer maxTime $ pure $ runVerifierNoTimeout l authority blocks v
  pure $ case resultOrTimeout of
    Nothing -> Left Timeout
    Just r  -> r


runAllBlocks :: BlockWithRevocationId
             -> [BlockWithRevocationId]
             -> Verifier
             -> StateT ComputeState (Either PureExecError) ()
runAllBlocks authority blocks verifier = do
  modify $ \state -> state { sFacts = mkRevocationIdFacts authority blocks }
  runAuthority authority verifier
  traverse_ runBlock blocks

mkRevocationIdFacts :: BlockWithRevocationId -> [BlockWithRevocationId]
                    -> Set Fact
mkRevocationIdFacts authority blocks =
  let allIds :: [(Int, ByteString)]
      allIds = zip [0..] $ snd <$> authority : blocks
      mkFact (index, rid) = [fact|revocation_id(${index}, ${rid})|]
   in Set.fromList $ mkFact <$> allIds

runVerifierNoTimeout :: Limits
                     -> BlockWithRevocationId
                     -> [BlockWithRevocationId]
                     -> Verifier
                     -> Either ExecutionError VerificationSuccess
runVerifierNoTimeout limits authority blocks verifier = do
  let result = (`runStateT` mkInitState limits) $ runAllBlocks authority blocks verifier
  case result of
    Left Facts      -> Left TooManyFacts
    Left Iterations -> Left TooManyIterations
    Right ((), ComputeState{..}) -> case (nonEmpty sFailedChecks, sPolicyResult) of
      (Nothing, Right p)       -> Right $ VerificationSuccess { matchedAllowQuery = p
                                                              , authorityFacts = sAuthorityFacts
                                                              , allGeneratedFacts = sFacts
                                                              }
      (Nothing, Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched []
      (Nothing, Left (Just p)) -> Left $ ResultError $ DenyRuleMatched [] p
      (Just cs, Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched (NE.toList cs)
      (Just cs, Left (Just p)) -> Left $ ResultError $ DenyRuleMatched (NE.toList cs) p
      (Just cs, Right _)       -> Left $ ResultError $ FailedChecks cs


runFactGeneration :: Limits -> World -> Either PureExecError (Set Fact)
runFactGeneration limits w =
  let getFacts = sFacts . snd
   in getFacts <$> runStateT (computeAllFacts w) (mkInitState limits)

runAuthority :: BlockWithRevocationId
             -> Verifier
             -> StateT ComputeState (Either PureExecError) ()
runAuthority (block, _rid) Verifier{..} = do
  let world = collectWorld block <> collectWorld vBlock
  computeAllFacts world
  -- store the facts generated by the authority block (and the verifier)
  -- in a dedicated `sAuthorityFacts` so that they can be queried independently
  -- later: we trust the authority facts, not the block facts
  modify $ \c@ComputeState{sFacts} -> c { sAuthorityFacts = sFacts }
  state@ComputeState{sFacts, sLimits} <- get
  let checkResults = checkChecks sLimits (bChecks block <> bChecks vBlock) sFacts
  let policyResult = checkPolicies sLimits vPolicies sFacts
  put state { sPolicyResult = policyResult
            , sFailedChecks = validation NE.toList mempty checkResults
            }

runBlock :: BlockWithRevocationId
         -> StateT ComputeState (Either PureExecError) ()
runBlock (block@Block{bChecks}, _rid) = do
  let world = collectWorld block
  computeAllFacts world
  state@ComputeState{sFacts, sLimits, sFailedChecks} <- get
  let checkResults = checkChecks sLimits bChecks sFacts
  put state { sFailedChecks = validation NE.toList mempty checkResults <> sFailedChecks
            }

checkChecks :: Limits -> [Check] -> Set Fact -> Validation (NonEmpty Check) ()
checkChecks limits checks facts = traverse_ (checkCheck limits facts) checks

checkPolicies :: Limits -> [Policy] -> Set Fact -> Either (Maybe Query) Query
checkPolicies limits policies facts =
  let results = mapMaybe (checkPolicy limits facts) policies
   in case results of
        p : _ -> first Just p
        []    -> Left Nothing

computeAllFacts :: World
                -> StateT ComputeState (Either PureExecError) ()
computeAllFacts world = do
  state@ComputeState{..} <- get
  let Limits{..} = sLimits
  let newFacts = extend sLimits (world `withFacts` sFacts)
      allFacts = sFacts <> facts world <> newFacts
  when (Set.size allFacts >= maxFacts) $ lift $ Left Facts
  when (sIterations >= maxIterations)  $ lift $ Left Iterations
  put $ state { sIterations = sIterations + 1
              , sFacts = allFacts
              }
  if null newFacts
  then pure ()
  else computeAllFacts world

extend :: Limits -> World -> Set Fact
extend l World{..} =
  let buildFacts = foldMap (getFactsForRule l facts)
      allNewFacts = buildFacts rules
   in Set.difference allNewFacts facts

collectWorld :: Block -> World
collectWorld Block{..} = World
  { facts = Set.fromList bFacts
  , rules = Set.fromList bRules
  }
