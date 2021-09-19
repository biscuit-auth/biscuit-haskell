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
  , pbToSignedBlock
  , signedBlockToPb
  , pbToProof
  ) where

import           Control.Monad            (when)
import           Data.Bifunctor           (first)
import           Data.Int                 (Int32, Int64)
import           Data.Map.Strict          (Map)
import qualified Data.Map.Strict          as Map
import qualified Data.Set                 as Set
import           Data.Text                (Text)
import           Data.Time                (UTCTime)
import           Data.Time.Clock.POSIX    (posixSecondsToUTCTime,
                                           utcTimeToPOSIXSeconds)
import           Data.Void                (absurd)

import qualified Auth.Biscuit.Crypto      as Crypto
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

-- | Parse a protobuf signed block into a signed biscuit block
pbToSignedBlock :: PB.SignedBlock -> Either String Crypto.SignedBlock
pbToSignedBlock PB.SignedBlock{..} = do
  sig <- first (const "Invalid signature") $ Crypto.eitherCryptoError $ Crypto.signature $ PB.getField signature
  pk  <- first (const "Invalid public key") $ Crypto.eitherCryptoError $ Crypto.publicKey $ PB.getField nextKey
  pure ( PB.getField block
       , sig
       , pk
       )

signedBlockToPb :: Crypto.SignedBlock -> PB.SignedBlock
signedBlockToPb (block, sig, pk) = PB.SignedBlock
  { block = PB.putField block
  , signature = PB.putField $ Crypto.convert sig
  , nextKey = PB.putField $ Crypto.convert pk
  }

pbToProof :: PB.Proof -> Either String (Either Crypto.Signature Crypto.SecretKey)
pbToProof (PB.ProofSignature rawSig) = Left  <$> first (const "Invalid signature proof") (Crypto.eitherCryptoError $ Crypto.signature $ PB.getField rawSig)
pbToProof (PB.ProofSecret    rawPk)  = Right <$> first (const "Invalid public key proof") (Crypto.eitherCryptoError $ Crypto.secretKey $ PB.getField rawPk)

-- | Parse a protobuf block into a proper biscuit block
pbToBlock :: Symbols -> PB.Block -> Either String Block
pbToBlock s PB.Block{..} = do
  let bContext = PB.getField context
      bVersion = PB.getField version
  bFacts <- traverse (pbToFact s) $ PB.getField facts_v2
  bRules <- traverse (pbToRule s) $ PB.getField rules_v2
  bChecks <- traverse (pbToCheck s) $ PB.getField checks_v2
  when (bVersion /= Just 2) $ Left $ "Unsupported biscuit version: " <> maybe "0" show bVersion <> ". Only version 2 is supported"
  pure Block{ .. }

-- | Turn a biscuit block into a protobuf block, for serialization,
-- along with the newly defined symbols
blockToPb :: Symbols -> Block -> (Symbols, PB.Block)
blockToPb existingSymbols b@Block{..} =
  let
      bSymbols = buildSymbolTable existingSymbols b
      s = reverseSymbols $ existingSymbols <> bSymbols
      symbols   = PB.putField $ Map.elems bSymbols
      context   = PB.putField bContext
      version   = PB.putField $ Just 2
      facts_v2  = PB.putField $ factToPb s <$> bFacts
      rules_v2  = PB.putField $ ruleToPb s <$> bRules
      checks_v2 = PB.putField $ checkToPb s <$> bChecks
   in (bSymbols, PB.Block {..})

pbToFact :: Symbols -> PB.FactV2 -> Either String Fact
pbToFact s PB.FactV2{predicate} = do
  let pbName  = PB.getField $ PB.name  $ PB.getField predicate
      pbTerms = PB.getField $ PB.terms $ PB.getField predicate
  name <- getSymbol s pbName
  terms <- traverse (pbToValue s) pbTerms
  pure Predicate{..}

factToPb :: ReverseSymbols -> Fact -> PB.FactV2
factToPb s Predicate{..} =
  let
      predicate = PB.PredicateV2
        { name  = PB.putField $ getSymbolCode s name
        , terms = PB.putField $ valueToPb s <$> terms
        }
   in PB.FactV2{predicate = PB.putField predicate}

pbToRule :: Symbols -> PB.RuleV2 -> Either String Rule
pbToRule s pbRule = do
  let pbHead = PB.getField $ PB.head pbRule
      pbBody = PB.getField $ PB.body pbRule
      pbExpressions = PB.getField $ PB.expressions pbRule
  rhead       <- pbToPredicate s pbHead
  body        <- traverse (pbToPredicate s) pbBody
  expressions <- traverse (pbToExpression s) pbExpressions
  pure Rule {..}

ruleToPb :: ReverseSymbols -> Rule -> PB.RuleV2
ruleToPb s Rule{..} =
  PB.RuleV2
    { head = PB.putField $ predicateToPb s rhead
    , body = PB.putField $ predicateToPb s <$> body
    , expressions = PB.putField $ expressionToPb s <$> expressions
    }

pbToCheck :: Symbols -> PB.CheckV2 -> Either String Check
pbToCheck s PB.CheckV2{queries} = do
  let toCheck Rule{body,expressions} = QueryItem{qBody = body, qExpressions = expressions }
  rules <- traverse (pbToRule s) $ PB.getField queries
  pure $ toCheck <$> rules

checkToPb :: ReverseSymbols -> Check -> PB.CheckV2
checkToPb s items =
  let dummyHead = Predicate "query" []
      toQuery QueryItem{..} =
        ruleToPb s $ Rule dummyHead qBody qExpressions
   in PB.CheckV2 { queries = PB.putField $ toQuery <$> items }

getSymbol :: (Show i, Integral i) => Symbols -> i -> Either String Text
getSymbol s i = maybeToRight ("Missing symbol at id " <> show i) $ Map.lookup (fromIntegral i) s

pbToPredicate :: Symbols -> PB.PredicateV2 -> Either String (Predicate' 'InPredicate 'RegularString)
pbToPredicate s pbPredicate = do
  let pbName  = PB.getField $ PB.name  pbPredicate
      pbTerms = PB.getField $ PB.terms pbPredicate
  name <- getSymbol s pbName
  terms <- traverse (pbToTerm s) pbTerms
  pure Predicate{..}

predicateToPb :: ReverseSymbols -> Predicate -> PB.PredicateV2
predicateToPb s Predicate{..} =
  PB.PredicateV2
    { name  = PB.putField $ getSymbolCode s name
    , terms = PB.putField $ termToPb s <$> terms
    }

pbTimeToUtcTime :: Int64 -> UTCTime
pbTimeToUtcTime = posixSecondsToUTCTime . fromIntegral

pbToTerm :: Symbols -> PB.TermV2 -> Either String Term
pbToTerm s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable f -> Variable <$> getSymbol s (PB.getField f)
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

termToPb :: ReverseSymbols -> Term -> PB.TermV2
termToPb s = \case
  Variable n -> PB.TermVariable $ PB.putField $ getSymbolCode s n
  LInteger v -> PB.TermInteger  $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString   $ PB.putField $ getSymbolCode s v
  LDate    v -> PB.TermDate     $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes    $ PB.putField v
  LBool    v -> PB.TermBool     $ PB.putField v
  TermSet vs -> PB.TermTermSet  $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Antiquote v -> absurd v

pbToValue :: Symbols -> PB.TermV2 -> Either String Value
pbToValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts"
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

valueToPb :: ReverseSymbols -> Value -> PB.TermV2
valueToPb s = \case
  LInteger v -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString  $ PB.putField $ getSymbolCode s v
  LDate    v -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes   $ PB.putField v
  LBool    v -> PB.TermBool    $ PB.putField v
  TermSet vs -> PB.TermTermSet $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Variable v  -> absurd v
  Antiquote v -> absurd v

pbToSetValue :: Symbols -> PB.TermV2 -> Either String (Term' 'WithinSet 'InFact 'RegularString)
pbToSetValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString  <$> getSymbol s (PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts or sets"
  PB.TermTermSet  _ -> Left "Sets can't be nested"

setValueToPb :: ReverseSymbols -> Term' 'WithinSet 'InFact 'RegularString -> PB.TermV2
setValueToPb s = \case
  LInteger v  -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v  -> PB.TermString  $ PB.putField $ getSymbolCode s v
  LDate    v  -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v  -> PB.TermBytes   $ PB.putField v
  LBool    v  -> PB.TermBool    $ PB.putField v

  TermSet   v -> absurd v
  Variable  v -> absurd v
  Antiquote v -> absurd v

pbToExpression :: Symbols -> PB.ExpressionV2 -> Either String Expression
pbToExpression s PB.ExpressionV2{ops} = do
  parsedOps <- traverse (pbToOp s) $ PB.getField ops
  fromStack parsedOps

expressionToPb :: ReverseSymbols -> Expression -> PB.ExpressionV2
expressionToPb s e =
  let ops = opToPb s <$> toStack e
   in PB.ExpressionV2 { ops = PB.putField ops }

pbToOp :: Symbols -> PB.Op -> Either String Op
pbToOp s = \case
  PB.OpVValue v  -> VOp <$> pbToTerm s (PB.getField v)
  PB.OpVUnary v  -> pure . UOp . pbToUnary $ PB.getField v
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
