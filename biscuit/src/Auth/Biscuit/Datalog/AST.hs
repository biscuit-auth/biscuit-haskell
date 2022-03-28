{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveLift                 #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}
{-|
  Module      : Auth.Biscuit.Datalog.AST
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  The Datalog elements
-}
module Auth.Biscuit.Datalog.AST
  (
    Binary (..)
  , Block
  , Block' (..)
  , BlockElement' (..)
  , Check
  , Check'
  , Expression
  , Expression' (..)
  , Fact
  , ToTerm (..)
  , FromValue (..)
  , Term
  , Term' (..)
  , IsWithinSet (..)
  , Op (..)
  , ParsedAs (..)
  , Policy
  , Policy'
  , PolicyType (..)
  , Predicate
  , Predicate' (..)
  , PredicateOrFact (..)
  , QQTerm
  , Query
  , Query'
  , QueryItem' (..)
  , Rule
  , Rule' (..)
  , RuleScope (..)
  , SetType
  , Slice (..)
  , SliceType
  , Unary (..)
  , Value
  , VariableType
  , Authorizer
  , Authorizer' (..)
  , AuthorizerElement' (..)
  , elementToBlock
  , elementToAuthorizer
  , fromStack
  , listSymbolsInBlock
  , renderBlock
  , renderFact
  , renderRule
  , toSetTerm
  , toStack
  ) where

import           Control.Applicative        ((<|>))
import           Control.Monad              ((<=<))
import           Data.ByteString            (ByteString)
import           Data.ByteString.Base16     as Hex
import           Data.Foldable              (fold)
import           Data.Set                   (Set)
import qualified Data.Set                   as Set
import           Data.String                (IsString)
import           Data.Text                  (Text, intercalate, pack, unpack)
import           Data.Text.Encoding         (decodeUtf8)
import           Data.Time                  (UTCTime)
import           Data.Void                  (Void, absurd)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Syntax
import           Numeric.Natural            (Natural)

data IsWithinSet = NotWithinSet | WithinSet
data ParsedAs = RegularString | QuasiQuote
data PredicateOrFact = InPredicate | InFact

type family VariableType (inSet :: IsWithinSet) (pof :: PredicateOrFact) where
  VariableType 'NotWithinSet 'InPredicate = Text
  VariableType inSet          pof         = Void

newtype Slice = Slice String
  deriving newtype (Eq, Show, Ord, IsString)

instance Lift Slice where
  lift (Slice name) = [| toTerm $(varE $ mkName name) |]
#if MIN_VERSION_template_haskell(2,17,0)
  liftTyped = liftCode . unsafeTExpCoerce . lift
#else
  liftTyped = unsafeTExpCoerce . lift
#endif

type family SliceType (ctx :: ParsedAs) where
  SliceType 'RegularString = Void
  SliceType 'QuasiQuote    = Slice

type family SetType (inSet :: IsWithinSet) (ctx :: ParsedAs) where
  SetType 'NotWithinSet ctx = Set (Term' 'WithinSet 'InFact ctx)
  SetType 'WithinSet    ctx = Void

-- | A single datalog item.
-- | This can be a value, a set of items, or a slice (a value that will be injected later),
-- | depending on the context
data Term' (inSet :: IsWithinSet) (pof :: PredicateOrFact) (ctx :: ParsedAs) =
    Variable (VariableType inSet pof)
  -- ^ A variable (eg. @$0@)
  | LInteger Int
  -- ^ An integer literal (eg. @42@)
  | LString Text
  -- ^ A string literal (eg. @"file1"@)
  | LDate UTCTime
  -- ^ A date literal (eg. @2021-05-26T18:00:00Z@)
  | LBytes ByteString
  -- ^ A hex literal (eg. @hex:ff9900@)
  | LBool Bool
  -- ^ A bool literal (eg. @true@)
  | Antiquote (SliceType ctx)
  -- ^ A slice (eg. @${name}@)
  | TermSet (SetType inSet ctx)
  -- ^ A set (eg. @[true, false]@)

deriving instance ( Eq (VariableType inSet pof)
                  , Eq (SliceType ctx)
                  , Eq (SetType inSet ctx)
                  ) => Eq (Term' inSet pof ctx)

deriving instance ( Ord (VariableType inSet pof)
                  , Ord (SliceType ctx)
                  , Ord (SetType inSet ctx)
                  ) => Ord (Term' inSet pof ctx)

deriving instance ( Show (VariableType inSet pof)
                  , Show (SliceType ctx)
                  , Show (SetType inSet ctx)
                  ) => Show (Term' inSet pof ctx)

-- | In a regular AST, slices have already been eliminated
type Term = Term' 'NotWithinSet 'InPredicate 'RegularString
-- | In an AST parsed from a QuasiQuoter, there might be references to haskell variables
type QQTerm = Term' 'NotWithinSet 'InPredicate 'QuasiQuote
-- | A term that is not a variable
type Value = Term' 'NotWithinSet 'InFact 'RegularString
-- | An element of a set
type SetValue = Term' 'WithinSet 'InFact 'RegularString

instance  ( Lift (VariableType inSet pof)
          , Lift (SetType inSet ctx)
          , Lift (SliceType ctx)
          )
         => Lift (Term' inSet pof ctx) where
  lift (Variable n)    = [| Variable n |]
  lift (LInteger i)    = [| LInteger i |]
  lift (LString s)     = [| LString s |]
  lift (LBytes bs)     = [| LBytes bs |]
  lift (LBool b)       = [| LBool  b |]
  lift (TermSet terms) = [| TermSet terms |]
  lift (LDate t)       = [| LDate (read $(lift $ show t)) |]
  lift (Antiquote s)   = [| s |]

#if MIN_VERSION_template_haskell(2,17,0)
  liftTyped = liftCode . unsafeTExpCoerce . lift
#else
  liftTyped = unsafeTExpCoerce . lift
#endif

-- | This class describes how to turn a haskell value into a datalog value.
-- | This is used when slicing a haskell variable in a datalog expression
class ToTerm t where
  -- | How to turn a value into a datalog item
  toTerm :: t -> Term' inSet pof 'RegularString

-- | This class describes how to turn a datalog value into a regular haskell value.
class FromValue t where
  fromValue :: Value -> Maybe t

instance ToTerm Int where
  toTerm = LInteger

instance FromValue Int where
  fromValue (LInteger v) = Just v
  fromValue _            = Nothing

instance ToTerm Integer where
  toTerm = LInteger . fromIntegral

instance FromValue Integer where
  fromValue (LInteger v) = Just (fromIntegral v)
  fromValue _            = Nothing

instance ToTerm Text where
  toTerm = LString

instance FromValue Text where
  fromValue (LString t) = Just t
  fromValue _           = Nothing

instance ToTerm Bool where
  toTerm = LBool

instance FromValue Bool where
  fromValue (LBool b) = Just b
  fromValue _         = Nothing

instance ToTerm ByteString where
  toTerm = LBytes

instance FromValue ByteString where
  fromValue (LBytes bs) = Just bs
  fromValue _           = Nothing

instance ToTerm UTCTime where
  toTerm = LDate

instance FromValue UTCTime where
  fromValue (LDate t) = Just t
  fromValue _         = Nothing

instance FromValue Value where
  fromValue = Just

toSetTerm :: Value
          -> Maybe (Term' 'WithinSet 'InFact 'RegularString)
toSetTerm = \case
  LInteger i  -> Just $ LInteger i
  LString i   -> Just $ LString i
  LDate i     -> Just $ LDate i
  LBytes i    -> Just $ LBytes i
  LBool i     -> Just $ LBool i
  TermSet _   -> Nothing
  Variable v  -> absurd v
  Antiquote v -> absurd v

renderId' :: (VariableType inSet pof -> Text)
          -> (SetType inSet ctx -> Text)
          -> (SliceType ctx -> Text)
          -> Term' inSet pof ctx -> Text
renderId' var set slice = \case
  Variable name -> var name
  LInteger int  -> pack $ show int
  LString str   -> pack $ show str
  LDate time    -> pack $ show time
  LBytes bs     -> "hex:" <> decodeUtf8 (Hex.encode bs)
  LBool True    -> "true"
  LBool False   -> "false"
  TermSet terms -> set terms -- "[" <> intercalate "," (renderInnerId <$> Set.toList terms) <> "]"
  Antiquote v   -> slice v

renderSet :: (SliceType ctx -> Text)
          -> Set (Term' 'WithinSet 'InFact ctx)
          -> Text
renderSet slice terms =
  "[" <> intercalate "," (renderId' absurd absurd slice <$> Set.toList terms) <> "]"

renderId :: Term -> Text
renderId = renderId' ("$" <>) (renderSet absurd) absurd

renderFactId :: Term' 'NotWithinSet 'InFact 'RegularString -> Text
renderFactId = renderId' absurd (renderSet absurd) absurd

listSymbolsInTerm :: Term -> Set.Set Text
listSymbolsInTerm = \case
  LString  v    -> Set.singleton v
  Variable name -> Set.singleton name
  TermSet terms -> foldMap listSymbolsInSetValue terms
  Antiquote v   -> absurd v
  _             -> mempty

listSymbolsInValue :: Value -> Set.Set Text
listSymbolsInValue = \case
  LString  v    -> Set.singleton v
  TermSet terms -> foldMap listSymbolsInSetValue terms
  Variable  v   -> absurd v
  Antiquote v   -> absurd v
  _             -> mempty

listSymbolsInSetValue :: SetValue -> Set.Set Text
listSymbolsInSetValue = \case
  LString  v  -> Set.singleton v
  TermSet   v -> absurd v
  Variable  v -> absurd v
  Antiquote v -> absurd v
  _           -> mempty

data Predicate' (pof :: PredicateOrFact) (ctx :: ParsedAs) = Predicate
  { name  :: Text
  , terms :: [Term' 'NotWithinSet pof ctx]
  }

deriving instance ( Eq (Term' 'NotWithinSet pof ctx)
                  ) => Eq (Predicate' pof ctx)
deriving instance ( Ord (Term' 'NotWithinSet pof ctx)
                  ) => Ord (Predicate' pof ctx)
deriving instance ( Show (Term' 'NotWithinSet pof ctx)
                  ) => Show (Predicate' pof ctx)

deriving instance Lift (Term' 'NotWithinSet pof ctx) => Lift (Predicate' pof ctx)

type Predicate = Predicate' 'InPredicate 'RegularString
type Fact = Predicate' 'InFact 'RegularString

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderId terms) <> ")"

renderFact :: Fact -> Text
renderFact Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderFactId terms) <> ")"

listSymbolsInFact :: Fact -> Set.Set Text
listSymbolsInFact Predicate{..} =
     Set.singleton name
  <> foldMap listSymbolsInValue terms

listSymbolsInPredicate :: Predicate -> Set.Set Text
listSymbolsInPredicate Predicate{..} =
     Set.singleton name
  <> foldMap listSymbolsInTerm terms

data QueryItem' ctx = QueryItem
  { qBody        :: [Predicate' 'InPredicate ctx]
  , qExpressions :: [Expression' ctx]
  , qScope       :: Maybe RuleScope
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

renderQueryItem :: QueryItem' 'RegularString -> Text
renderQueryItem QueryItem{..} =
  intercalate ",\n" $ fold
    [ renderPredicate <$> qBody
    , renderExpression <$> qExpressions
    ]

renderCheck :: Check -> Text
renderCheck is = "check if " <>
  intercalate "\n or " (renderQueryItem <$> is)

listSymbolsInQueryItem :: QueryItem' 'RegularString -> Set.Set Text
listSymbolsInQueryItem QueryItem{..} =
     Set.singleton "query" -- query items are serialized as `Rule`s
                           -- so an empty rule head is added: `query()`
                           -- It means that query items implicitly depend on
                           -- the `query` symbol being defined.
  <> foldMap listSymbolsInPredicate qBody
  <> foldMap listSymbolsInExpression qExpressions

listSymbolsInCheck :: Check -> Set.Set Text
listSymbolsInCheck =
  foldMap listSymbolsInQueryItem

data RuleScope  =
    OnlyAuthority
  | Previous
  | UnsafeAny
  | OnlyBlocks (Set Natural)
  deriving (Eq, Ord, Show, Lift)

data Rule' ctx = Rule
  { rhead       :: Predicate' 'InPredicate ctx
  , body        :: [Predicate' 'InPredicate ctx]
  , expressions :: [Expression' ctx]
  , scope       :: Maybe RuleScope
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
renderRule Rule{rhead,body,expressions} =
  renderPredicate rhead <> " <- " <> intercalate ", " (fmap renderPredicate body <> fmap renderExpression expressions)

listSymbolsInRule :: Rule -> Set.Set Text
listSymbolsInRule Rule{..} =
     listSymbolsInPredicate rhead
  <> foldMap listSymbolsInPredicate body
  <> foldMap listSymbolsInExpression expressions

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
    EValue (Term' 'NotWithinSet 'InPredicate ctx)
  | EUnary Unary (Expression' ctx)
  | EBinary Binary (Expression' ctx) (Expression' ctx)

deriving instance Eq   (Term' 'NotWithinSet 'InPredicate ctx) => Eq (Expression' ctx)
deriving instance Ord  (Term' 'NotWithinSet 'InPredicate ctx) => Ord (Expression' ctx)
deriving instance Lift (Term' 'NotWithinSet 'InPredicate ctx) => Lift (Expression' ctx)
deriving instance Show (Term' 'NotWithinSet 'InPredicate ctx) => Show (Expression' ctx)

type Expression = Expression' 'RegularString

listSymbolsInExpression :: Expression -> Set.Set Text
listSymbolsInExpression = \case
  EValue t       -> listSymbolsInTerm t
  EUnary _ e     -> listSymbolsInExpression e
  EBinary _ e e' -> foldMap listSymbolsInExpression [e, e']

data Op =
    VOp Term
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

toStack :: Expression -> [Op]
toStack expr =
  let go e s = case e of
        EValue t      -> VOp t : s
        EUnary o i    -> go i $ UOp o : s
        EBinary o l r -> go l $ go r $ BOp o : s
   in go expr []

renderExpression :: Expression -> Text
renderExpression =
  let rOp t e e' = renderExpression e
                <> " " <> t <> " "
                <> renderExpression e'
      rm m e e' = renderExpression e
               <> "." <> m <> "("
               <> renderExpression e'
               <> ")"
   in \case
        EValue t                    -> renderId t
        EUnary Negate e             -> "!" <> renderExpression e
        EUnary Parens e             -> "(" <> renderExpression e <> ")"
        EUnary Length e             -> renderExpression e <> ".length()"
        EBinary LessThan e e'       -> rOp "<" e e'
        EBinary GreaterThan e e'    -> rOp ">" e e'
        EBinary LessOrEqual e e'    -> rOp "<=" e e'
        EBinary GreaterOrEqual e e' -> rOp ">=" e e'
        EBinary Equal e e'          -> rOp "==" e e'
        EBinary Contains e e'       -> rm "contains" e e'
        EBinary Prefix e e'         -> rm "starts_with" e e'
        EBinary Suffix e e'         -> rm "ends_with" e e'
        EBinary Regex e e'          -> rm "matches" e e'
        EBinary Intersection e e'   -> rm "intersection" e e'
        EBinary Union e e'          -> rm "union" e e'
        EBinary Add e e'            -> rOp "+" e e'
        EBinary Sub e e'            -> rOp "-" e e'
        EBinary Mul e e'            -> rOp "*" e e'
        EBinary Div e e'            -> rOp "/" e e'
        EBinary And e e'            -> rOp "&&" e e'
        EBinary Or e e'             -> rOp "||" e e'

-- | A biscuit block, containing facts, rules and checks.
--
-- 'Block' has a 'Monoid' instance, which is the expected way
-- to build composite blocks (eg if you need to generate a list of facts):
--
-- > -- build a block from multiple variables v1, v2, v3
-- > [block| value(${v1}); |] <>
-- > [block| value(${v2}); |] <>
-- > [block| value(${v3}); |]
type Block = Block' 'RegularString

-- | A biscuit block, that may or may not contain slices referencing
-- haskell variables
data Block' (ctx :: ParsedAs) = Block
  { bRules   :: [Rule' ctx]
  , bFacts   :: [Predicate' 'InFact ctx]
  , bChecks  :: [Check' ctx]
  , bContext :: Maybe Text
  , bScope   :: Maybe RuleScope
  }

renderBlock :: Block -> Text
renderBlock Block{..} =
  intercalate ";\n" $ fold
    [ renderRule <$> bRules
    , renderFact <$> bFacts
    , renderCheck <$> bChecks
    ]

deriving instance ( Eq (Predicate' 'InFact ctx)
                  , Eq (Rule' ctx)
                  , Eq (QueryItem' ctx)
                  ) => Eq (Block' ctx)

-- deriving instance ( Show (Predicate' 'InFact ctx)
--                   , Show (Rule' ctx)
--                   , Show (QueryItem' ctx)
--                   ) => Show (Block' ctx)
instance Show Block where
  show = unpack . renderBlock

deriving instance ( Lift (Predicate' 'InFact ctx)
                  , Lift (Rule' ctx)
                  , Lift (QueryItem' ctx)
                  ) => Lift (Block' ctx)

instance Semigroup (Block' ctx) where
  b1 <> b2 = Block { bRules = bRules b1 <> bRules b2
                   , bFacts = bFacts b1 <> bFacts b2
                   , bChecks = bChecks b1 <> bChecks b2
                   , bContext = bContext b2 <|> bContext b1
                   , bScope = bScope b1 <|> bScope b2
                   }

instance Monoid (Block' ctx) where
  mempty = Block { bRules = []
                 , bFacts = []
                 , bChecks = []
                 , bContext = Nothing
                 , bScope = Nothing
                 }

listSymbolsInBlock :: Block' 'RegularString -> Set.Set Text
listSymbolsInBlock Block {..} = fold
  [ foldMap listSymbolsInRule bRules
  , foldMap listSymbolsInFact bFacts
  , foldMap listSymbolsInCheck bChecks
  ]

-- | A biscuit authorizer, containing, facts, rules, checks and policies
type Authorizer = Authorizer' 'RegularString

-- | The context in which a biscuit policies and checks are verified.
-- A authorizer may add policies (`deny if` / `allow if` conditions), as well as rules, facts, and checks.
-- A authorizer may or may not contain slices referencing haskell variables.
data Authorizer' (ctx :: ParsedAs) = Authorizer
  { vPolicies :: [Policy' ctx]
  -- ^ the allow / deny policies.
  , vBlock    :: Block' ctx
  -- ^ the facts, rules and checks
  }

instance Semigroup (Authorizer' ctx) where
  v1 <> v2 = Authorizer { vPolicies = vPolicies v1 <> vPolicies v2
                      , vBlock = vBlock v1 <> vBlock v2
                      }

instance Monoid (Authorizer' ctx) where
  mempty = Authorizer { vPolicies = []
                    , vBlock = mempty
                    }

deriving instance ( Eq (Block' ctx)
                  , Eq (QueryItem' ctx)
                  ) => Eq (Authorizer' ctx)

deriving instance ( Show (Block' ctx)
                  , Show (QueryItem' ctx)
                  ) => Show (Authorizer' ctx)

deriving instance ( Lift (Block' ctx)
                  , Lift (QueryItem' ctx)
                  ) => Lift (Authorizer' ctx)

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
   BlockRule r  -> Block [r] [] [] Nothing Nothing
   BlockFact f  -> Block [] [f] [] Nothing Nothing
   BlockCheck c -> Block [] [] [c] Nothing Nothing
   BlockComment -> mempty

data AuthorizerElement' ctx
  = AuthorizerPolicy (Policy' ctx)
  | BlockElement (BlockElement' ctx)

deriving instance ( Show (Predicate' 'InFact ctx)
                  , Show (Rule' ctx)
                  , Show (QueryItem' ctx)
                  ) => Show (AuthorizerElement' ctx)

elementToAuthorizer :: AuthorizerElement' ctx -> Authorizer' ctx
elementToAuthorizer = \case
  AuthorizerPolicy p -> Authorizer [p] mempty
  BlockElement be    -> Authorizer [] (elementToBlock be)
