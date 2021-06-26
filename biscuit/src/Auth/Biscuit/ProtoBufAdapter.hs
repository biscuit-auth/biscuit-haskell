{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-|
  Module      : Auth.Biscuit.Utils
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Conversion functions between biscuit components and protobuf-encoded components
-}
module Auth.Biscuit.ProtoBufAdapter
  ( Symbols
  , extractSymbols
  , commonSymbols
  , buildSymbolTable
  , pbToBlock
  , blockToPb
  ) where

import           Control.Monad            (when)
import           Data.Int                 (Int32, Int64)
import           Data.Map.Strict          (Map)
import qualified Data.Map.Strict          as Map
import qualified Data.Set                 as Set
import           Data.Text                (Text)
import           Data.Time                (UTCTime)
import           Data.Time.Clock.POSIX    (posixSecondsToUTCTime,
                                           utcTimeToPOSIXSeconds)
import           Data.Void                (absurd)

import           Auth.Biscuit.Datalog.AST
import qualified Auth.Biscuit.Proto       as PB
import           Auth.Biscuit.Utils       (maybeToRight)

-- | A map to get symbol names from symbol ids
type Symbols = Map Int32 Text
-- | A map to get symbol ids from symbol names
type ReverseSymbols = Map Text Int32

-- | The common symbols defined in the biscuit spec
commonSymbols :: Symbols
commonSymbols = Map.fromList $ zip [0..]
  [ "authority"
  , "ambient"
  , "resource"
  , "operation"
  , "right"
  , "time"
  , "revocation_id"
  ]

-- | Given existing symbols and a series of protobuf blocks,
-- compute the complete symbol mapping
extractSymbols :: Symbols -> [PB.Block] -> Symbols
extractSymbols existingSymbols blocks =
    let blocksSymbols  = PB.getField . PB.symbols =<< blocks
        startingIndex = fromIntegral $ length existingSymbols
     in existingSymbols <> Map.fromList (zip [startingIndex..] blocksSymbols)

-- | Given existing symbols and a biscuit block, compute the
-- symbol table for the given block. Already existing symbols
-- won't be included
buildSymbolTable :: Symbols -> Block -> Symbols
buildSymbolTable existingSymbols block =
  let allSymbols = listSymbolsInBlock block
      newSymbols = Set.difference allSymbols (Set.fromList $ Map.elems existingSymbols)
      newSymbolsWithIndices = zip (fromIntegral <$> [length existingSymbols..]) (Set.toList newSymbols)
   in Map.fromList newSymbolsWithIndices

reverseSymbols :: Symbols -> ReverseSymbols
reverseSymbols =
  let swap (a,b) = (b,a)
   in Map.fromList . fmap swap . Map.toList

getSymbolCode :: Integral i => ReverseSymbols -> Text -> i
getSymbolCode = (fromIntegral .) . (Map.!)

-- | Parse a protobuf block into a proper biscuit block
pbToBlock :: Symbols -> PB.Block -> Either String Block
pbToBlock s PB.Block{..} = do
  let bContext = PB.getField context
      bVersion = PB.getField version
  bFacts <- traverse (pbToFact s) $ PB.getField facts_v1
  bRules <- traverse (pbToRule s) $ PB.getField rules_v1
  bChecks <- traverse (pbToCheck s) $ PB.getField checks_v1
  when (bVersion /= Just 1) $ Left $ "Unsupported biscuit version: " <> maybe "0" show bVersion <> ". Only version 1 is supported"
  pure Block{ .. }

-- | Turn a biscuit block into a protobuf block, for serialization,
-- along with the newly defined symbols
blockToPb :: Symbols -> Int -> Block -> (Symbols, PB.Block)
blockToPb existingSymbols bIndex b@Block{..} =
  let
      bSymbols = buildSymbolTable existingSymbols b
      s = reverseSymbols $ existingSymbols <> bSymbols
      index     = PB.putField $ fromIntegral bIndex
      symbols   = PB.putField $ Map.elems bSymbols
      context   = PB.putField bContext
      version   = PB.putField $ Just 1
      facts_v1  = PB.putField $ factToPb s <$> bFacts
      rules_v1  = PB.putField $ ruleToPb s <$> bRules
      checks_v1 = PB.putField $ checkToPb s <$> bChecks
   in (bSymbols, PB.Block {..})

pbToFact :: Symbols -> PB.FactV1 -> Either String Fact
pbToFact s PB.FactV1{predicate} = do
  let pbName = PB.getField $ PB.name $ PB.getField predicate
      pbIds  = PB.getField $ PB.ids  $ PB.getField predicate
  name <- getSymbol s pbName
  terms <- traverse (pbToValue s) pbIds
  pure Predicate{..}

factToPb :: ReverseSymbols -> Fact -> PB.FactV1
factToPb s Predicate{..} =
  let
      predicate = PB.PredicateV1
        { name = PB.putField $ getSymbolCode s name
        , ids  = PB.putField $ valueToPb s <$> terms
        }
   in PB.FactV1{predicate = PB.putField predicate}

pbToRule :: Symbols -> PB.RuleV1 -> Either String Rule
pbToRule s pbRule = do
  let pbHead = PB.getField $ PB.head pbRule
      pbBody = PB.getField $ PB.body pbRule
      pbExpressions = PB.getField $ PB.expressions pbRule
  rhead       <- pbToPredicate s pbHead
  body        <- traverse (pbToPredicate s) pbBody
  expressions <- traverse (pbToExpression s) pbExpressions
  pure Rule {..}

ruleToPb :: ReverseSymbols -> Rule -> PB.RuleV1
ruleToPb s Rule{..} =
  PB.RuleV1
    { head = PB.putField $ predicateToPb s rhead
    , body = PB.putField $ predicateToPb s <$> body
    , expressions = PB.putField $ expressionToPb s <$> expressions
    }

pbToCheck :: Symbols -> PB.CheckV1 -> Either String Check
pbToCheck s PB.CheckV1{queries} = do
  let toCheck Rule{body,expressions} = QueryItem{qBody = body, qExpressions = expressions }
  rules <- traverse (pbToRule s) $ PB.getField queries
  pure $ toCheck <$> rules

checkToPb :: ReverseSymbols -> Check -> PB.CheckV1
checkToPb s items =
  let dummyHead = Predicate "query" []
      toQuery QueryItem{..} =
        ruleToPb s $ Rule dummyHead qBody qExpressions
   in PB.CheckV1 { queries = PB.putField $ toQuery <$> items }

getSymbol :: (Show i, Integral i) => Symbols -> i -> Either String Text
getSymbol s i = maybeToRight ("Missing symbol at id " <> show i) $ Map.lookup (fromIntegral i) s

pbToPredicate :: Symbols -> PB.PredicateV1 -> Either String (Predicate' 'InPredicate 'RegularString)
pbToPredicate s pbPredicate = do
  let pbName = PB.getField $ PB.name pbPredicate
      pbIds  = PB.getField $ PB.ids  pbPredicate
  name <- getSymbol s pbName
  terms <- traverse (pbToTerm s) pbIds
  pure Predicate{..}

predicateToPb :: ReverseSymbols -> Predicate -> PB.PredicateV1
predicateToPb s Predicate{..} =
  PB.PredicateV1
    { name = PB.putField $ getSymbolCode s name
    , ids  = PB.putField $ termToPb s <$> terms
    }

pbTimeToUtcTime :: Int64 -> UTCTime
pbTimeToUtcTime = posixSecondsToUTCTime . fromIntegral

pbToTerm :: Symbols -> PB.IDV1 -> Either String ID
pbToTerm s = \case
  PB.IDSymbol   f ->        Symbol  <$> getSymbol s (PB.getField f)
  PB.IDInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.IDString   f -> pure $ LString  $ PB.getField f
  PB.IDDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.IDBytes    f -> pure $ LBytes   $ PB.getField f
  PB.IDBool     f -> pure $ LBool    $ PB.getField f
  PB.IDVariable f -> Variable <$> getSymbol s (PB.getField f)
  PB.IDIDSet    f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

termToPb :: ReverseSymbols -> ID -> PB.IDV1
termToPb s = \case
  Variable n -> PB.IDVariable $ PB.putField $ getSymbolCode s n
  Symbol   n -> PB.IDSymbol   $ PB.putField $ getSymbolCode s n
  LInteger v -> PB.IDInteger  $ PB.putField $ fromIntegral v
  LString  v -> PB.IDString   $ PB.putField v
  LDate    v -> PB.IDDate     $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.IDBytes    $ PB.putField v
  LBool    v -> PB.IDBool     $ PB.putField v
  TermSet vs -> PB.IDIDSet    $ PB.putField $ PB.IDSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Antiquote v -> absurd v

pbToValue :: Symbols -> PB.IDV1 -> Either String Value
pbToValue s = \case
  PB.IDSymbol   f ->        Symbol  <$> getSymbol s (PB.getField f)
  PB.IDInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.IDString   f -> pure $ LString  $ PB.getField f
  PB.IDDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.IDBytes    f -> pure $ LBytes   $ PB.getField f
  PB.IDBool     f -> pure $ LBool    $ PB.getField f
  PB.IDVariable _ -> Left "Variables can't appear in facts"
  PB.IDIDSet    f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

valueToPb :: ReverseSymbols -> Value -> PB.IDV1
valueToPb s = \case
  Symbol   n -> PB.IDSymbol  $ PB.putField $ getSymbolCode s n
  LInteger v -> PB.IDInteger $ PB.putField $ fromIntegral v
  LString  v -> PB.IDString  $ PB.putField v
  LDate    v -> PB.IDDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.IDBytes   $ PB.putField v
  LBool    v -> PB.IDBool    $ PB.putField v
  TermSet vs -> PB.IDIDSet   $ PB.putField $ PB.IDSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Variable v  -> absurd v
  Antiquote v -> absurd v

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

setValueToPb :: ReverseSymbols -> ID' 'WithinSet 'InFact 'RegularString -> PB.IDV1
setValueToPb s = \case
  Symbol   n -> PB.IDSymbol  $ PB.putField $ getSymbolCode s n
  LInteger v -> PB.IDInteger $ PB.putField $ fromIntegral v
  LString  v -> PB.IDString  $ PB.putField v
  LDate    v -> PB.IDDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.IDBytes   $ PB.putField v
  LBool    v -> PB.IDBool    $ PB.putField v

  TermSet   v -> absurd v
  Variable  v -> absurd v
  Antiquote v -> absurd v

pbToExpression :: Symbols -> PB.ExpressionV1 -> Either String Expression
pbToExpression s PB.ExpressionV1{ops} = do
  parsedOps <- traverse (pbToOp s) $ PB.getField ops
  fromStack parsedOps

expressionToPb :: ReverseSymbols -> Expression -> PB.ExpressionV1
expressionToPb s e =
  let ops = opToPb s <$> toStack e
   in PB.ExpressionV1 { ops = PB.putField ops }

pbToOp :: Symbols -> PB.Op -> Either String Op
pbToOp s = \case
  PB.OpVValue v -> VOp <$> pbToTerm s (PB.getField v)
  PB.OpVUnary v -> pure . UOp . pbToUnary $ PB.getField v
  PB.OpVBinary v -> pure . BOp . pbToBinary $ PB.getField v

opToPb :: ReverseSymbols -> Op -> PB.Op
opToPb s = \case
  VOp t -> PB.OpVValue  $ PB.putField $ termToPb s t
  UOp o -> PB.OpVUnary  $ PB.putField $ unaryToPb o
  BOp o -> PB.OpVBinary $ PB.putField $ binaryToPb o

pbToUnary :: PB.OpUnary -> Unary
pbToUnary PB.OpUnary{kind} = case PB.getField kind of
  PB.Negate -> Negate
  PB.Parens -> Parens
  PB.Length -> Length

unaryToPb ::  Unary -> PB.OpUnary
unaryToPb = PB.OpUnary . PB.putField . \case
  Negate -> PB.Negate
  Parens -> PB.Parens
  Length -> PB.Length

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

binaryToPb :: Binary -> PB.OpBinary
binaryToPb = PB.OpBinary . PB.putField . \case
  LessThan       -> PB.LessThan
  GreaterThan    -> PB.GreaterThan
  LessOrEqual    -> PB.LessOrEqual
  GreaterOrEqual -> PB.GreaterOrEqual
  Equal          -> PB.Equal
  Contains       -> PB.Contains
  Prefix         -> PB.Prefix
  Suffix         -> PB.Suffix
  Regex          -> PB.Regex
  Add            -> PB.Add
  Sub            -> PB.Sub
  Mul            -> PB.Mul
  Div            -> PB.Div
  And            -> PB.And
  Or             -> PB.Or
  Intersection   -> PB.Intersection
  Union          -> PB.Union
