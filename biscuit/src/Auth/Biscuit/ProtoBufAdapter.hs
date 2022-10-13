{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeApplications  #-}
{-|
  Module      : Auth.Biscuit.Utils
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Conversion functions between biscuit components and protobuf-encoded components
-}
module Auth.Biscuit.ProtoBufAdapter
  ( Symbols
  , buildSymbolTable
  , pbToBlock
  , blockToPb
  , pbToSignedBlock
  , signedBlockToPb
  , pbToProof
  , pbToThirdPartyBlockRequest
  , thirdPartyBlockRequestToPb
  , pbToThirdPartyBlockContents
  , thirdPartyBlockContentsToPb
  ) where

import           Control.Monad            (when)
import           Control.Monad.State      (StateT, get, lift, modify)
import           Data.Bitraversable       (bisequence)
import           Data.ByteString          (ByteString)
import           Data.Int                 (Int64)
import           Data.Maybe               (isNothing)
import qualified Data.Set                 as Set
import           Data.Time                (UTCTime)
import           Data.Time.Clock.POSIX    (posixSecondsToUTCTime,
                                           utcTimeToPOSIXSeconds)
import           Data.Void                (absurd)
import           GHC.Records              (getField)

import qualified Auth.Biscuit.Crypto      as Crypto
import           Auth.Biscuit.Datalog.AST
import qualified Auth.Biscuit.Proto       as PB
import           Auth.Biscuit.Symbols
import           Auth.Biscuit.Utils       (maybeToRight)

buildSymbolTable :: Symbols -> Block -> BlockSymbols
buildSymbolTable existingSymbols block =
  let allSymbols = listSymbolsInBlock block
      allKeys = listPublicKeysInBlock block
   in addSymbols existingSymbols allSymbols allKeys

pbToPublicKey :: PB.PublicKey -> Either String Crypto.PublicKey
pbToPublicKey PB.PublicKey{..} =
  let keyBytes = PB.getField key
   in case PB.getField algorithm of
        PB.Ed25519 -> maybeToRight "Invalid ed25519 public key" $ Crypto.readEd25519PublicKey keyBytes
        PB.P256    -> maybeToRight "Invalid P256 public key" $ Crypto.readECDSAP256PublicKey keyBytes

pbToOptionalSignature :: PB.ExternalSig -> Either String (Crypto.Signature, Crypto.PublicKey)
pbToOptionalSignature PB.ExternalSig{..} = do
  let sig = Crypto.signature $ PB.getField signature
  pk  <- pbToPublicKey $ PB.getField publicKey
  pure (sig, pk)

-- | Parse a protobuf signed block into a signed biscuit block
pbToSignedBlock :: PB.SignedBlock -> Either String Crypto.SignedBlock
pbToSignedBlock PB.SignedBlock{..} = do
  let sig = Crypto.signature $ PB.getField signature
  mSig <- traverse pbToOptionalSignature $ PB.getField externalSig
  pk  <- pbToPublicKey $ PB.getField nextKey
  pure ( PB.getField block
       , sig
       , pk
       , mSig
       )

publicKeyToPb :: Crypto.PublicKey -> PB.PublicKey
publicKeyToPb pk@(Crypto.Ed25519PublicKey _) = PB.PublicKey
  { algorithm = PB.putField PB.Ed25519
  , key = PB.putField $ Crypto.pkBytes pk
  }
publicKeyToPb pk@(Crypto.ECDSAP256PublicKey _) = PB.PublicKey
  { algorithm = PB.putField PB.P256
  , key = PB.putField $ Crypto.pkBytes pk
  }

externalSigToPb :: (Crypto.Signature, Crypto.PublicKey) -> PB.ExternalSig
externalSigToPb (sig, pk) = PB.ExternalSig
  { signature = PB.putField $ Crypto.sigBytes sig
  , publicKey = PB.putField $ publicKeyToPb pk
  }

signedBlockToPb :: Crypto.SignedBlock -> PB.SignedBlock
signedBlockToPb (block, sig, pk, eSig) = PB.SignedBlock
  { block = PB.putField block
  , signature = PB.putField $ Crypto.sigBytes sig
  , nextKey = PB.putField $ publicKeyToPb pk
  , externalSig = PB.putField $ externalSigToPb <$> eSig
  }

pbToProof :: Crypto.PublicKey -> PB.Proof -> Either String (Either Crypto.Signature Crypto.SecretKey)
pbToProof _ (PB.ProofSignature rawSig) = Left  <$> Right (Crypto.signature $ PB.getField rawSig)
pbToProof lastPublic (PB.ProofSecret    rawPk)  =
  let readSk = case lastPublic of
        Crypto.Ed25519PublicKey _   -> Crypto.readEd25519SecretKey
        Crypto.ECDSAP256PublicKey _ -> Crypto.readECDSAP256SecretKey
   in Right <$> maybeToRight "Invalid secret key proof" (readSk $ PB.getField rawPk)

pbToBlock :: Maybe Crypto.PublicKey -> PB.Block -> StateT Symbols (Either String) Block
pbToBlock ePk PB.Block{..} = do
  blockPks <- lift $ traverse pbToPublicKey $ PB.getField pksTable
  let blockSymbols = PB.getField symbols
  -- third party blocks use an isolated symbol table,
  -- but use the global public keys table:
  --   symbols defined in 3rd party blocks are not visible
  --   to following blocks, but public keys are
  when (isNothing ePk) $ modify (registerNewSymbols blockSymbols)
  modify (registerNewPublicKeys $ foldMap pure ePk <> blockPks)
  currentSymbols <- get

  let symbolsForCurrentBlock =
        -- third party blocks use an isolated symbol table,
        -- but use the global public keys table.
        --   3rd party blocks don't see previously defined
        --   symbols, but see previously defined public keys
        if isNothing ePk then currentSymbols
                         else registerNewSymbols blockSymbols $ forgetSymbols currentSymbols
  let bContext = PB.getField context
      bVersion = PB.getField version
  lift $ do
    let s = symbolsForCurrentBlock
    bFacts <- traverse (pbToFact s) $ PB.getField facts_v2
    bRules <- traverse (pbToRule s) $ PB.getField rules_v2
    bChecks <- traverse (pbToCheck s) $ PB.getField checks_v2
    bScope <- Set.fromList <$> traverse (pbToScope s) (PB.getField scope)
    let isV3 = isNothing ePk
            && Set.null bScope
            && all ruleHasNoScope bRules
            && all queryHasNoScope bChecks
    case (bVersion, isV3) of
      (Just 4, _) -> pure Block {..}
      (Just 3, True) -> pure Block {..}
      (Just 3, False) ->
        Left "Biscuit v4 fields are present, but the block version is 3."
      _ ->
        Left $ "Unsupported biscuit version: " <> maybe "0" show bVersion <> ". Only versions 3 and 4 are supported"

-- | Turn a biscuit block into a protobuf block, for serialization,
-- along with the newly defined symbols
blockToPb :: Bool -> Symbols -> Block -> (BlockSymbols, PB.Block)
blockToPb hasExternalPk existingSymbols b@Block{..} =
  let isV3 = not hasExternalPk
            && Set.null bScope
            && all ruleHasNoScope bRules
            && all queryHasNoScope bChecks
      bSymbols = buildSymbolTable existingSymbols b
      s = reverseSymbols $ addFromBlock existingSymbols bSymbols
      symbols   = PB.putField $ getSymbolList bSymbols
      context   = PB.putField bContext
      facts_v2  = PB.putField $ factToPb s <$> bFacts
      rules_v2  = PB.putField $ ruleToPb s <$> bRules
      checks_v2 = PB.putField $ checkToPb s <$> bChecks
      scope     = PB.putField $ scopeToPb s <$> Set.toList bScope
      pksTable   = PB.putField $ publicKeyToPb <$> getPkList bSymbols
      version   = PB.putField $ if isV3 then Just 3
                                        else Just 4
   in (bSymbols, PB.Block {..})

pbToFact :: Symbols -> PB.FactV2 -> Either String Fact
pbToFact s PB.FactV2{predicate} = do
  let pbName  = PB.getField $ PB.name  $ PB.getField predicate
      pbTerms = PB.getField $ PB.terms $ PB.getField predicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToValue s) pbTerms
  pure Predicate{..}

factToPb :: ReverseSymbols -> Fact -> PB.FactV2
factToPb s Predicate{..} =
  let
      predicate = PB.PredicateV2
        { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
        , terms = PB.putField $ valueToPb s <$> terms
        }
   in PB.FactV2{predicate = PB.putField predicate}

pbToRule :: Symbols -> PB.RuleV2 -> Either String Rule
pbToRule s pbRule = do
  let pbHead = PB.getField $ PB.head pbRule
      pbBody = PB.getField $ PB.body pbRule
      pbExpressions = PB.getField $ PB.expressions pbRule
      pbScope = PB.getField $ getField @"scope" pbRule
  rhead       <- pbToPredicate s pbHead
  body        <- traverse (pbToPredicate s) pbBody
  expressions <- traverse (pbToExpression s) pbExpressions
  scope       <- Set.fromList <$> traverse (pbToScope s) pbScope
  pure Rule {..}

ruleToPb :: ReverseSymbols -> Rule -> PB.RuleV2
ruleToPb s Rule{..} =
  PB.RuleV2
    { head = PB.putField $ predicateToPb s rhead
    , body = PB.putField $ predicateToPb s <$> body
    , expressions = PB.putField $ expressionToPb s <$> expressions
    , scope = PB.putField $ scopeToPb s <$> Set.toList scope
    }

pbToCheck :: Symbols -> PB.CheckV2 -> Either String Check
pbToCheck s PB.CheckV2{queries} = do
  let toCheck Rule{body,expressions,scope} = QueryItem{qBody = body, qExpressions = expressions, qScope = scope}
  rules <- traverse (pbToRule s) $ PB.getField queries
  pure $ toCheck <$> rules

checkToPb :: ReverseSymbols -> Check -> PB.CheckV2
checkToPb s items =
  let dummyHead = Predicate "query" []
      toQuery QueryItem{..} =
        ruleToPb s $ Rule { rhead = dummyHead
                          , body = qBody
                          , expressions = qExpressions
                          , scope = qScope
                          }
   in PB.CheckV2 { queries = PB.putField $ toQuery <$> items }

pbToScope :: Symbols -> PB.Scope -> Either String RuleScope
pbToScope s = \case
  PB.ScType e       -> case PB.getField e of
    PB.ScopeAuthority -> Right OnlyAuthority
    PB.ScopePrevious  -> Right Previous
  PB.ScBlock pkRef ->
    BlockId <$> getPublicKey' s (PublicKeyRef $ PB.getField pkRef)

scopeToPb :: ReverseSymbols -> RuleScope -> PB.Scope
scopeToPb s = \case
  OnlyAuthority -> PB.ScType $ PB.putField PB.ScopeAuthority
  Previous      -> PB.ScType $ PB.putField PB.ScopePrevious
  BlockId pk    -> PB.ScBlock $ PB.putField $ getPublicKeyCode s pk

pbToPredicate :: Symbols -> PB.PredicateV2 -> Either String (Predicate' 'InPredicate 'Representation)
pbToPredicate s pbPredicate = do
  let pbName  = PB.getField $ PB.name  pbPredicate
      pbTerms = PB.getField $ PB.terms pbPredicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToTerm s) pbTerms
  pure Predicate{..}

predicateToPb :: ReverseSymbols -> Predicate -> PB.PredicateV2
predicateToPb s Predicate{..} =
  PB.PredicateV2
    { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
    , terms = PB.putField $ termToPb s <$> terms
    }

pbTimeToUtcTime :: Int64 -> UTCTime
pbTimeToUtcTime = posixSecondsToUTCTime . fromIntegral

pbToTerm :: Symbols -> PB.TermV2 -> Either String Term
pbToTerm s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable f -> Variable <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

termToPb :: ReverseSymbols -> Term -> PB.TermV2
termToPb s = \case
  Variable n -> PB.TermVariable $ PB.putField $ getSymbolRef $ getSymbolCode s n
  LInteger v -> PB.TermInteger  $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString   $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v -> PB.TermDate     $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes    $ PB.putField v
  LBool    v -> PB.TermBool     $ PB.putField v
  TermSet vs -> PB.TermTermSet  $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Antiquote v -> absurd v

pbToValue :: Symbols -> PB.TermV2 -> Either String Value
pbToValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts"
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

valueToPb :: ReverseSymbols -> Value -> PB.TermV2
valueToPb s = \case
  LInteger v -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate    v -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes   v -> PB.TermBytes   $ PB.putField v
  LBool    v -> PB.TermBool    $ PB.putField v
  TermSet vs -> PB.TermTermSet $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs

  Variable v  -> absurd v
  Antiquote v -> absurd v

pbToSetValue :: Symbols -> PB.TermV2 -> Either String (Term' 'WithinSet 'InFact 'Representation)
pbToSetValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString  <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts or sets"
  PB.TermTermSet  _ -> Left "Sets can't be nested"

setValueToPb :: ReverseSymbols -> Term' 'WithinSet 'InFact 'Representation -> PB.TermV2
setValueToPb s = \case
  LInteger v  -> PB.TermInteger $ PB.putField $ fromIntegral v
  LString  v  -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
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


pbToThirdPartyBlockRequest :: PB.ThirdPartyBlockRequest -> Either String (Crypto.PublicKey, [Crypto.PublicKey])
pbToThirdPartyBlockRequest PB.ThirdPartyBlockRequest{previousPk, pkTable} = do
  bisequence
    ( pbToPublicKey $ PB.getField previousPk
    , traverse pbToPublicKey $ PB.getField pkTable
    )

thirdPartyBlockRequestToPb :: (Crypto.PublicKey, [Crypto.PublicKey]) -> PB.ThirdPartyBlockRequest
thirdPartyBlockRequestToPb (previousPk, pkTable) = PB.ThirdPartyBlockRequest
  { previousPk = PB.putField $ publicKeyToPb previousPk
  , pkTable = PB.putField $ publicKeyToPb <$> pkTable
  }

pbToThirdPartyBlockContents :: PB.ThirdPartyBlockContents -> Either String (ByteString, Crypto.Signature, Crypto.PublicKey)
pbToThirdPartyBlockContents PB.ThirdPartyBlockContents{payload,externalSig} = do
  (sig, pk) <- pbToOptionalSignature $ PB.getField externalSig
  pure ( PB.getField payload
       , sig
       , pk
       )

thirdPartyBlockContentsToPb :: (ByteString, Crypto.Signature, Crypto.PublicKey) -> PB.ThirdPartyBlockContents
thirdPartyBlockContentsToPb (payload, sig, pk) = PB.ThirdPartyBlockContents
  { PB.payload = PB.putField payload
  , PB.externalSig = PB.putField $ externalSigToPb (sig, pk)
  }

