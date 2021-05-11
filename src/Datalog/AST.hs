{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveLift                 #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}
module Datalog.AST where

import           Control.Applicative        ((<|>))
import           Control.Monad              ((<=<))
import           Data.ByteString            (ByteString)
import           Data.ByteString.Base16     as Hex
import           Data.Set                   (Set)
import qualified Data.Set                   as Set
import           Data.String                (IsString)
import           Data.Text                  (Text, intercalate, pack)
import           Data.Text.Encoding         (decodeUtf8)
import           Data.Time                  (UTCTime)
import           Data.Void                  (Void, absurd)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Syntax

data IsWithinSet = NotWithinSet | WithinSet
data ParsedAs = RegularString | QuasiQuote
data PredicateOrFact = InPredicate | InFact

type family VariableType (inSet :: IsWithinSet) (pof :: PredicateOrFact) where
  VariableType 'NotWithinSet 'InPredicate = Text
  VariableType inSet          pof         = Void

newtype Slice = Slice String
  deriving newtype (Eq, Show, Ord, IsString)

instance Lift Slice where
  lift (Slice name) = [| toLiteralId $(varE $ mkName name) |]
  liftTyped = unsafeTExpCoerce . lift

type family SliceType (ctx :: ParsedAs) where
  SliceType 'RegularString = Void
  SliceType 'QuasiQuote    = Slice

type family SetType (inSet :: IsWithinSet) (ctx :: ParsedAs) where
  SetType 'NotWithinSet ctx = Set (ID' 'WithinSet 'InFact ctx)
  SetType 'WithinSet    ctx = Void

data ID' (inSet :: IsWithinSet) (pof :: PredicateOrFact) (ctx :: ParsedAs) =
    Symbol Text
  | Variable (VariableType inSet pof)
  | LInteger Int
  | LString Text
  | LDate UTCTime
  | LBytes ByteString
  | LBool Bool
  | Antiquote (SliceType ctx)
  | TermSet (SetType inSet ctx)

deriving instance ( Eq (VariableType inSet pof)
                  , Eq (SliceType ctx)
                  , Eq (SetType inSet ctx)
                  ) => Eq (ID' inSet pof ctx)

deriving instance ( Ord (VariableType inSet pof)
                  , Ord (SliceType ctx)
                  , Ord (SetType inSet ctx)
                  ) => Ord (ID' inSet pof ctx)

deriving instance ( Show (VariableType inSet pof)
                  , Show (SliceType ctx)
                  , Show (SetType inSet ctx)
                  ) => Show (ID' inSet pof ctx)

-- In a regular AST, antiquotes have already been eliminated
type ID = ID' 'NotWithinSet 'InPredicate 'RegularString
-- In an AST parsed from a QuasiQuoter, there might be references to haskell variables
type QQID = ID' 'NotWithinSet 'InPredicate 'QuasiQuote
type Value = ID' 'NotWithinSet 'InFact 'RegularString -- a term that is *not* a variable

instance  ( Lift (VariableType inSet pof)
          , Lift (SetType inSet ctx)
          , Lift (SliceType ctx)
          )
         => Lift (ID' inSet pof ctx) where
  lift (Symbol n)      = [| Symbol n |]
  lift (Variable n)    = [| Variable n |]
  lift (LInteger i)    = [| LInteger i |]
  lift (LString s)     = [| LString s |]
  lift (LBytes bs)     = [| LBytes bs |]
  lift (LBool b)       = [| LBool  b |]
  lift (TermSet terms) = [| TermSet terms |]
  lift (LDate t)       = [| LDate (read $(lift $ show t)) |]
  lift (Antiquote s)   = [| s |]

  liftTyped = unsafeTExpCoerce . lift

class ToLiteralId t where
  toLiteralId :: t -> ID' inSet pof 'RegularString

instance ToLiteralId Text where
  toLiteralId = LString

instance ToLiteralId Bool where
  toLiteralId = LBool

instance ToLiteralId ByteString where
  toLiteralId = LBytes

instance ToLiteralId UTCTime where
  toLiteralId = LDate

toSetTerm :: Value
          -> Maybe (ID' 'WithinSet 'InFact 'RegularString)
toSetTerm = \case
  Symbol i -> Just $ Symbol i
  LInteger i -> Just $ LInteger i
  LString i -> Just $ LString i
  LDate i -> Just $ LDate i
  LBytes i -> Just $ LBytes i
  LBool i -> Just $ LBool i
  TermSet _ -> Nothing
  Variable v -> absurd v
  Antiquote v -> absurd v

renderId :: ID -> Text
renderId = \case
  Symbol name   -> "#" <> name
  Variable name -> "$" <> name
  LInteger int  -> pack $ show int
  LString str   -> pack $ show str
  LDate time    -> pack $ show time
  LBytes bs     -> "hex:" <> decodeUtf8 (Hex.encode bs)
  LBool True    -> "true"
  LBool False   -> "false"
  TermSet terms -> "[" <> intercalate "," (renderInnerId <$> Set.toList terms) <> "]"
  Antiquote v   -> absurd v

renderFactId :: ID' 'NotWithinSet 'InFact 'RegularString -> Text
renderFactId = \case
  Symbol name   -> "#" <> name
  LInteger int  -> pack $ show int
  LString str   -> pack $ show str
  LDate time    -> pack $ show time
  LBytes bs     -> "hex:" <> decodeUtf8 (Hex.encode bs)
  LBool True    -> "true"
  LBool False   -> "false"
  TermSet terms -> "[" <> intercalate "," (renderInnerId <$> Set.toList terms) <> "]"
  Variable v    -> absurd v
  Antiquote v   -> absurd v

renderInnerId :: ID' 'WithinSet 'InFact 'RegularString -> Text
renderInnerId = \case
  Symbol v    -> renderId (Symbol v)
  LInteger v  -> renderId (LInteger v)
  LString v   -> renderId (LString v)
  LDate v     -> renderId (LDate v)
  LBytes v    -> renderId (LBytes v)
  LBool v     -> renderId (LBool v)
  Antiquote v -> renderId (Antiquote v)
  Variable v  -> absurd v
  TermSet v   -> absurd v

data Predicate' (pof :: PredicateOrFact) (ctx :: ParsedAs) = Predicate
  { name  :: Text
  , terms :: [ID' 'NotWithinSet pof ctx]
  }

deriving instance ( Eq (ID' 'NotWithinSet pof ctx)
                  ) => Eq (Predicate' pof ctx)
deriving instance ( Ord (ID' 'NotWithinSet pof ctx)
                  ) => Ord (Predicate' pof ctx)
deriving instance ( Show (ID' 'NotWithinSet pof ctx)
                  ) => Show (Predicate' pof ctx)


deriving instance Lift (ID' 'NotWithinSet pof ctx) => Lift (Predicate' pof ctx)

type Predicate = Predicate' 'InPredicate 'RegularString
type Fact = Predicate' 'InFact 'RegularString

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderId terms) <> ")"

renderFact :: Fact -> Text
renderFact Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderFactId terms) <> ")"

data QueryItem' ctx = QueryItem
  { qBody        :: [Predicate' 'InPredicate ctx]
  , qExpressions :: [Expression' ctx]
  }

type Query' ctx = [QueryItem' ctx]
type Query = Query' 'RegularString

type Check' ctx = Query' ctx
type Check = Query
data PolicyType = Allow | Deny
  deriving (Eq, Show, Ord, Lift)
type Policy' ctx = (PolicyType, Query' ctx)
type Policy = (PolicyType, Query)

deriving instance ( Eq (Predicate' 'InPredicate ctx)
                  , Eq (Expression' ctx)
                  ) => Eq (QueryItem' ctx)
deriving instance ( Ord (Predicate' 'InPredicate ctx)
                  , Ord (Expression' ctx)
                  ) => Ord (QueryItem' ctx)
deriving instance ( Show (Predicate' 'InPredicate ctx)
                  , Show (Expression' ctx)
                  ) => Show (QueryItem' ctx)

deriving instance (Lift (Predicate' 'InPredicate ctx), Lift (Expression' ctx)) => Lift (QueryItem' ctx)

data Rule' ctx = Rule
  { rhead       :: Predicate' 'InPredicate ctx
  , body        :: [Predicate' 'InPredicate ctx]
  , expressions :: [Expression' ctx]
  }

deriving instance ( Eq (Predicate' 'InPredicate ctx)
                  , Eq (Expression' ctx)
                  ) => Eq (Rule' ctx)
deriving instance ( Ord (Predicate' 'InPredicate ctx)
                  , Ord (Expression' ctx)
                  ) => Ord (Rule' ctx)
deriving instance ( Show (Predicate' 'InPredicate ctx)
                  , Show (Expression' ctx)
                  ) => Show (Rule' ctx)

type Rule = Rule' 'RegularString

deriving instance (Lift (Predicate' 'InPredicate ctx), Lift (Expression' ctx)) => Lift (Rule' ctx)

renderRule :: Rule' 'RegularString -> Text
renderRule Rule{rhead,body} =
  renderPredicate rhead <> " <- " <> intercalate ", " (fmap renderPredicate body)

data Unary =
    Negate
  | Parens
  | Length
  deriving (Eq, Ord, Show, Lift)

data Binary =
    LessThan
  | GreaterThan
  | LessOrEqual
  | GreaterOrEqual
  | Equal
  | Contains
  | Prefix
  | Suffix
  | Regex
  | Add
  | Sub
  | Mul
  | Div
  | And
  | Or
  | Intersection
  | Union
  deriving (Eq, Ord, Show, Lift)

data Expression' (ctx :: ParsedAs) =
    EValue (ID' 'NotWithinSet 'InPredicate ctx)
  | EUnary Unary (Expression' ctx)
  | EBinary Binary (Expression' ctx) (Expression' ctx)

deriving instance Eq   (ID' 'NotWithinSet 'InPredicate ctx) => Eq (Expression' ctx)
deriving instance Ord  (ID' 'NotWithinSet 'InPredicate ctx) => Ord (Expression' ctx)
deriving instance Lift (ID' 'NotWithinSet 'InPredicate ctx) => Lift (Expression' ctx)
deriving instance Show (ID' 'NotWithinSet 'InPredicate ctx) => Show (Expression' ctx)

type Expression = Expression' 'RegularString

data Op =
    VOp ID
  | UOp Unary
  | BOp Binary

fromStack :: [Op] -> Either String Expression
fromStack =
  let go stack []                    = Right stack
      go stack        (VOp t : rest) = go (EValue t : stack) rest
      go (e:stack)    (UOp o : rest) = go (EUnary o e : stack) rest
      go []           (UOp _ : _)    = Left "Empty stack on unary op"
      go (e:e':stack) (BOp o : rest) = go (EBinary o e' e : stack) rest
      go [_]          (BOp _ : _)    = Left "Unary stack on binary op"
      go []           (BOp _ : _)    = Left "Empty stack on binary op"
      final []  = Left "Empty stack"
      final [x] = Right x
      final _   = Left "Stack containing more than one element"
   in final <=< go []

type Block = Block' 'RegularString
data Block' (ctx :: ParsedAs) = Block
  { bRules   :: [Rule' ctx]
  , bFacts   :: [Predicate' 'InFact ctx]
  , bChecks  :: [Check' ctx]
  , bContext :: Maybe Text
  }

deriving instance ( Eq (Predicate' 'InFact ctx)
                  , Eq (Rule' ctx)
                  , Eq (QueryItem' ctx)
                  ) => Eq (Block' ctx)

deriving instance ( Show (Predicate' 'InFact ctx)
                  , Show (Rule' ctx)
                  , Show (QueryItem' ctx)
                  ) => Show (Block' ctx)

deriving instance ( Lift (Predicate' 'InFact ctx)
                  , Lift (Rule' ctx)
                  , Lift (QueryItem' ctx)
                  ) => Lift (Block' ctx)

instance Semigroup (Block' ctx) where
  b1 <> b2 = Block { bRules = bRules b1 <> bRules b2
                   , bFacts = bFacts b1 <> bFacts b2
                   , bChecks = bChecks b1 <> bChecks b2
                   , bContext = bContext b2 <|> bContext b1
                   }

instance Monoid (Block' ctx) where
  mempty = Block { bRules = []
                 , bFacts = []
                 , bChecks = []
                 , bContext = Nothing
                 }

type Verifier = Verifier' 'RegularString
data Verifier' (ctx :: ParsedAs) = Verifier
  { vPolicies :: [Policy' ctx]
  , vBlock    :: Block' ctx
  }

instance Semigroup (Verifier' ctx) where
  v1 <> v2 = Verifier { vPolicies = vPolicies v1 <> vPolicies v2
                      , vBlock = vBlock v1 <> vBlock v2
                      }

instance Monoid (Verifier' ctx) where
  mempty = Verifier { vPolicies = []
                    , vBlock = mempty
                    }

deriving instance ( Eq (Block' ctx)
                  , Eq (QueryItem' ctx)
                  ) => Eq (Verifier' ctx)

deriving instance ( Show (Block' ctx)
                  , Show (QueryItem' ctx)
                  ) => Show (Verifier' ctx)

deriving instance ( Lift (Block' ctx)
                  , Lift (QueryItem' ctx)
                  ) => Lift (Verifier' ctx)

data BlockElement' ctx
  = BlockFact (Predicate' 'InFact ctx)
  | BlockRule (Rule' ctx)
  | BlockCheck (Check' ctx)
  | BlockComment

deriving instance ( Show (Predicate' 'InFact ctx)
                  , Show (Rule' ctx)
                  , Show (QueryItem' ctx)
                  ) => Show (BlockElement' ctx)

elementToBlock :: BlockElement' ctx -> Block' ctx
elementToBlock = \case
   BlockRule r  -> Block [r] [] [] Nothing
   BlockFact f  -> Block [] [f] [] Nothing
   BlockCheck c -> Block [] [] [c] Nothing
   BlockComment -> mempty

data VerifierElement' ctx
  = VerifierPolicy (Policy' ctx)
  | BlockElement (BlockElement' ctx)

deriving instance ( Show (Predicate' 'InFact ctx)
                  , Show (Rule' ctx)
                  , Show (QueryItem' ctx)
                  ) => Show (VerifierElement' ctx)

elementToVerifier :: VerifierElement' ctx -> Verifier' ctx
elementToVerifier = \case
  VerifierPolicy p -> Verifier [p] mempty
  BlockElement be  -> Verifier [] (elementToBlock be)
