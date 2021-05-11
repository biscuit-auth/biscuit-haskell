{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module ProtoBufAdapter
  ( pbToBlock
  , extractSymbols
  , Symbols
  ) where

import           Data.Either.Combinators (maybeToRight)
import           Data.Int                (Int32, Int64)
import           Data.Map.Strict         (Map)
import qualified Data.Map.Strict         as Map
import qualified Data.Set                as Set
import           Data.Text               (Text)
import           Data.Time               (UTCTime)
import           Data.Time.Clock.POSIX   (posixSecondsToUTCTime)
import           Datalog.AST
import qualified Proto                   as PB

type Symbols = Map Int32 Text

extractSymbols :: [PB.Block] -> Symbols
extractSymbols blocks =
    let defaultSymbols =
          [ "authority"
          , "ambient"
          , "resource"
          , "operation"
          , "right"
          , "time"
          , "revocation_id"
          ]
        blocksSymbols = PB.getField . PB.symbols =<< blocks
     in Map.fromList $ zip [0..] $ defaultSymbols <> blocksSymbols

pbToBlock :: Symbols -> PB.Block -> Either String Block
pbToBlock s PB.Block{..} = do
  let bContext = PB.getField context
  bFacts <- traverse (pbToFact s) $ PB.getField facts_v1
  bRules <- traverse (pbToRule s) $ PB.getField rules_v1
  bChecks <- traverse (pbToCheck s) $ PB.getField checks_v1
  pure Block{ ..
            }

pbToFact :: Symbols -> PB.FactV1 -> Either String Fact
pbToFact s PB.FactV1{predicate} = do
  let pbName = PB.getField $ PB.name $ PB.getField predicate
      pbIds  = PB.getField $ PB.ids  $ PB.getField predicate
  name <- getSymbol s pbName
  terms <- traverse (pbToValue s) pbIds
  pure Predicate{..}

pbToRule :: Symbols -> PB.RuleV1 -> Either String Rule
pbToRule s pbRule = do
  let pbHead = PB.getField $ PB.head pbRule
      pbBody = PB.getField $ PB.body pbRule
      pbExpressions = PB.getField $ PB.expressions pbRule
  rhead       <- pbToPredicate s pbHead
  body        <- traverse (pbToPredicate s) pbBody
  expressions <- traverse (pbToExpression s) pbExpressions
  pure Rule {..}

pbToCheck :: Symbols -> PB.CheckV1 -> Either String Check
pbToCheck s PB.CheckV1{queries} = do
  let toCheck Rule{body,expressions} = QueryItem{qBody = body, qExpressions = expressions }
  rules <- traverse (pbToRule s) $ PB.getField queries
  pure $ toCheck <$> rules

getSymbol :: (Show i, Integral i) => Symbols -> i -> Either String Text
getSymbol s i = maybeToRight ("Missing symbol at id " <> show i) $ Map.lookup (fromIntegral i) s
--getSymbol _ = Right . pack . show

pbToPredicate :: Symbols -> PB.PredicateV1 -> Either String (Predicate' 'InPredicate 'RegularString)
pbToPredicate s pbPredicate = do
  let pbName = PB.getField $ PB.name pbPredicate
      pbIds  = PB.getField $ PB.ids  pbPredicate
  name <- getSymbol s pbName
  terms <- traverse (pbToTerm s) pbIds
  pure Predicate{..}

pbTimeToUtcTime :: Int64 -> UTCTime
pbTimeToUtcTime = posixSecondsToUTCTime . fromIntegral

pbToTerm :: Symbols -> PB.IDV1 -> Either String (ID' 'NotWithinSet 'InPredicate 'RegularString)
pbToTerm s = \case
  PB.IDSymbol   f ->        Symbol  <$> getSymbol s (PB.getField f)
  PB.IDInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.IDString   f -> pure $ LString  $ PB.getField f
  PB.IDDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.IDBytes    f -> pure $ LBytes   $ PB.getField f
  PB.IDBool     f -> pure $ LBool    $ PB.getField f
  PB.IDVariable f -> Variable <$> getSymbol s (PB.getField f)
  PB.IDIDSet    f -> TermSet . Set.fromList <$> (traverse (pbToSetValue s) $ PB.getField $ PB.set $ PB.getField f)

pbToValue :: Symbols -> PB.IDV1 -> Either String (ID' 'NotWithinSet 'InFact 'RegularString)
pbToValue s = \case
  PB.IDSymbol   f ->        Symbol  <$> getSymbol s (PB.getField f)
  PB.IDInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.IDString   f -> pure $ LString  $ PB.getField f
  PB.IDDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.IDBytes    f -> pure $ LBytes   $ PB.getField f
  PB.IDBool     f -> pure $ LBool    $ PB.getField f
  PB.IDVariable _ -> Left "Variables can't appear in facts"
  PB.IDIDSet    f -> TermSet . Set.fromList <$> (traverse (pbToSetValue s) $ PB.getField $ PB.set $ PB.getField f)

pbToSetValue :: Symbols -> PB.IDV1 -> Either String (ID' 'WithinSet 'InFact 'RegularString)
pbToSetValue s = \case
  PB.IDSymbol   f ->        Symbol   <$> getSymbol s (PB.getField f)
  PB.IDInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.IDString   f -> pure $ LString  $ PB.getField f
  PB.IDDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.IDBytes    f -> pure $ LBytes   $ PB.getField f
  PB.IDBool     f -> pure $ LBool    $ PB.getField f
  PB.IDVariable _ -> Left "Variables can't appear in facts or sets"
  PB.IDIDSet    _ -> Left "Sets can't be nested"

pbToExpression :: Symbols -> PB.ExpressionV1 -> Either String Expression
pbToExpression s PB.ExpressionV1{ops} = do
  parsedOps <- traverse (pbToOp s) $ PB.getField ops
  fromStack parsedOps

pbToOp :: Symbols -> PB.Op -> Either String Op
pbToOp s = \case
  PB.OpVValue v -> VOp <$> pbToTerm s (PB.getField v)
  PB.OpVUnary v -> pure . UOp . pbToUnary $ PB.getField v
  PB.OpVBinary v -> pure . BOp . pbToBinary $ PB.getField v

pbToUnary :: PB.OpUnary -> Unary
pbToUnary PB.OpUnary{kind} = case PB.getField kind of
  PB.Negate -> Negate
  PB.Parens -> Parens
  PB.Length -> Length

pbToBinary :: PB.OpBinary -> Binary
pbToBinary PB.OpBinary{kind} = case PB.getField kind of
  PB.LessThan       -> LessThan
  PB.GreaterThan    -> GreaterThan
  PB.LessOrEqual    -> LessOrEqual
  PB.GreaterOrEqual -> GreaterOrEqual
  PB.Equal          -> Equal
  PB.Contains       -> Contains
  PB.Prefix         -> Prefix
  PB.Suffix         -> Suffix
  PB.Regex          -> Regex
  PB.Add            -> Add
  PB.Sub            -> Sub
  PB.Mul            -> Mul
  PB.Div            -> Div
  PB.And            -> And
  PB.Or             -> Or
  PB.Intersection   -> Intersection
  PB.Union          -> Union
