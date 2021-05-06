{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE DeriveLift           #-}
{-# LANGUAGE DerivingStrategies   #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE LambdaCase           #-}
{-# LANGUAGE NamedFieldPuns       #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TemplateHaskell      #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE UndecidableInstances #-}
module Datalog.AST where

import           Data.ByteString            (ByteString)
import           Data.Hex                   (hex)
import           Data.Set                   (Set)
import qualified Data.Set                   as Set
import           Data.Text                  (Text, intercalate, pack)
import           Data.Text.Encoding         (decodeUtf8)
import           Data.Time                  (UTCTime)
import           Data.Void                  (Void, absurd)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Syntax

data IsWithinSet = NotWithinSet | WithinSet
data ParsedAs = RegularString | QuasiQuote

type family VariableType (inSet :: IsWithinSet) (ctx :: ParsedAs) where
  VariableType 'NotWithinSet p = Text
  VariableType 'WithinSet p    = Void

type family SliceType (inSet :: IsWithinSet) (ctx :: ParsedAs) where
  SliceType s 'RegularString = Void
  SliceType s 'QuasiQuote    = String

type family SetType (inSet :: IsWithinSet) (ctx :: ParsedAs) where
  SetType 'NotWithinSet m = Set (ID' 'WithinSet m)
  SetType 'WithinSet    m = Void

data ID' (inSet :: IsWithinSet) (ctx :: ParsedAs) =
    Symbol Text
  | Variable (VariableType inSet ctx)
  | LInteger Int
  | LString Text
  | LDate UTCTime
  | LBytes ByteString
  | LBool Bool
  | Antiquote (SliceType inSet ctx)
  | TermSet (SetType inSet ctx)

deriving instance ( Eq (VariableType inSet ctx)
                  , Eq (SliceType inSet ctx)
                  , Eq (SetType inSet ctx)
                  ) => Eq (ID' inSet ctx)

deriving instance ( Ord (VariableType inSet ctx)
                  , Ord (SliceType inSet ctx)
                  , Ord (SetType inSet ctx)
                  ) => Ord (ID' inSet ctx)

deriving instance ( Show (VariableType inSet ctx)
                  , Show (SliceType inSet ctx)
                  , Show (SetType inSet ctx)
                  ) => Show (ID' inSet ctx)

-- In a regular AST, antiquotes have already been eliminated
type ID = ID' 'NotWithinSet 'RegularString
-- In an AST parsed from a QuasiQuoter, there might be references to haskell variables
type QQID = ID' 'NotWithinSet 'QuasiQuote

instance Lift (ID' 'NotWithinSet 'QuasiQuote) where
  lift (Symbol n)      = [| Symbol n |]
  lift (Variable n)    = [| Variable n |]
  lift (LInteger i)    = [| LInteger i |]
  lift (LString s)     = [| LString s |]
  lift (LBytes bs)     = [| LBytes bs |]
  lift (LBool b)       = [| LBool  b |]
  lift (TermSet terms) = [| TermSet terms |]
  lift (LDate t)       = [| LDate (read $(lift $ show t)) |]
  lift (Antiquote n)   = [| toLiteralId $(varE $ mkName n) |]

instance Lift (ID' 'WithinSet 'QuasiQuote) where
  lift =
    let lift' = lift @(ID' 'NotWithinSet 'QuasiQuote)
    in \case
      Symbol i -> lift' (Symbol i)
      LInteger i -> lift' (LInteger i)
      LString i -> lift' (LString i)
      LDate i -> lift' (LDate i)
      LBytes i -> lift' (LBytes i)
      LBool i -> lift' (LBool i)
      Antiquote i -> lift' (Antiquote i)
      Variable v -> absurd v
      TermSet v -> absurd v

class ToLiteralId t where
  toLiteralId :: t -> ID

instance ToLiteralId Text where
  toLiteralId = LString

instance ToLiteralId Bool where
  toLiteralId = LBool

instance ToLiteralId ByteString where
  toLiteralId = LBytes

renderId :: ID -> Text
renderId = \case
  Symbol name   -> "#" <> name
  Variable name -> "$" <> name
  LInteger int  -> pack $ show int
  LString str   -> pack $ show str
  LDate time    -> pack $ show time
  LBytes bs     -> "hex:" <> decodeUtf8 (hex bs)
  LBool True    -> "true"
  LBool False   -> "false"
  TermSet terms -> "[" <> intercalate "," (renderInnerId <$> Set.toList terms) <> "]"
  Antiquote v   -> absurd v

renderInnerId :: ID' 'WithinSet 'RegularString -> Text
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

data Predicate' (ctx :: ParsedAs) = Predicate
  { name  :: Text
  , terms :: [ID' 'NotWithinSet ctx]
  }

deriving instance ( Eq (ID' 'NotWithinSet ctx)
                  ) => Eq (Predicate' ctx)
deriving instance ( Ord (ID' 'NotWithinSet ctx)
                  ) => Ord (Predicate' ctx)
deriving instance ( Show (ID' 'NotWithinSet ctx)
                  ) => Show (Predicate' ctx)


deriving instance Lift (ID' 'NotWithinSet ctx) => Lift (Predicate' ctx)

type Predicate = Predicate' 'RegularString
type Fact = Predicate' 'RegularString

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderId terms) <> ")"

data Rule' ctx = Rule
  { rhead       :: Predicate' ctx
  , body        :: [Predicate' ctx]
  , expressions :: [Expression' ctx]
  }

deriving instance ( Eq (Predicate' ctx)
                  , Eq (Expression' ctx)
                  ) => Eq (Rule' ctx)
deriving instance ( Ord (Predicate' ctx)
                  , Ord (Expression' ctx)
                  ) => Ord (Rule' ctx)
deriving instance ( Show (Predicate' ctx)
                  , Show (Expression' ctx)
                  ) => Show (Rule' ctx)

type Rule = Rule' 'RegularString

deriving instance (Lift (Predicate' ctx), Lift (Expression' ctx)) => Lift (Rule' ctx)

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
    EValue (ID' 'NotWithinSet ctx)
  | EUnary Unary (Expression' ctx)
  | EBinary Binary (Expression' ctx) (Expression' ctx)

deriving instance Eq (ID' 'NotWithinSet ctx) => Eq (Expression' ctx)
deriving instance Ord (ID' 'NotWithinSet ctx) => Ord (Expression' ctx)
deriving instance Lift (ID' 'NotWithinSet ctx) => Lift (Expression' ctx)
deriving instance Show (ID' 'NotWithinSet ctx) => Show (Expression' ctx)

type Expression = Expression' 'RegularString
