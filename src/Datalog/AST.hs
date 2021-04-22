{-# LANGUAGE DeriveLift           #-}
{-# LANGUAGE DerivingStrategies   #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE LambdaCase           #-}
{-# LANGUAGE NamedFieldPuns       #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TemplateHaskell      #-}
{-# LANGUAGE UndecidableInstances #-}
module Datalog.AST where

import           Data.ByteString            (ByteString)
import           Data.Hex                   (hex)
import           Data.String                (IsString (..))
import           Data.Text                  (Text, intercalate, pack, unpack)
import           Data.Text.Encoding         (decodeUtf8)
import           Data.Time                  (UTCTime)
import           Data.Void                  (Void)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote
import           Language.Haskell.TH.Syntax

instance Lift UTCTime where
  lift t = [| read $(lift (show t)) |]

data ID' antiquote =
    Symbol Text
  | Variable Text
  | LInteger Int
  | LString Text
  | LDate UTCTime
  | LBytes ByteString
  | LBool Bool
  | Antiquote antiquote
  -- todo set?
  deriving stock (Eq, Show)

-- In a regular AST, antiquotes have already been eliminated
type ID = ID' Void
-- In an AST parsed from a QuasiQuoter, there might be references to haskell variables
type QQID = ID' String

instance Lift (ID' String) where
  lift (Symbol n)    = apply 'Symbol [lift n]
  lift (Variable n)  = apply 'Variable [lift n]
  lift (LInteger i)  = apply 'LInteger [lift i]
  lift (LString s)   = apply 'LString [lift s]
  lift (LDate t)     = apply 'LDate [lift t]
  lift (LBytes bs)   = apply 'LBytes [lift bs]
  lift (LBool b)     = apply 'LBool [lift b]
  lift (Antiquote n) = appE (varE 'toLiteralId) (varE $ mkName n)

apply :: Name -> [Q Exp] -> Q Exp
apply n = foldl appE (conE n)

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
  Symbol name    -> "#" <> name
  Variable name  -> "$" <> name
  LInteger int   -> pack $ show int
  LString str    -> pack $ show str
  LDate time     -> pack $ show time
  LBytes bs      -> "hex:" <> decodeUtf8 (hex bs)
  LBool True     -> "true"
  LBool False    -> "false"

data Predicate' antiquote = Predicate
  { name  :: Text
  , terms :: [ID' antiquote]
  }
  deriving stock (Eq, Show)

deriving instance Lift (ID' antiquote) => Lift (Predicate' antiquote)

type Predicate = Predicate' Void

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderId terms) <> ")"

data Rule' antiquote = Rule
  { rhead :: Predicate' antiquote
  , body  :: [Predicate' antiquote]
  }
  deriving stock (Show)

deriving instance Lift (Predicate' antiquote) => Lift (Rule' antiquote)

data Expression' antiquote = Void
  deriving stock (Show, Lift)
