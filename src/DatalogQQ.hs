{-# LANGUAGE DeriveLift         #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE TemplateHaskell    #-}
module DatalogQQ where

import           Control.Applicative        ((<|>))
import           Data.Attoparsec.Text
import           Data.ByteString            (ByteString)
import           Data.Hex                   (hex)
import           Data.String                (IsString (..))
import           Data.Text                  (Text, intercalate, pack, unpack)
import           Data.Text.Encoding         (decodeUtf8)
import           Data.Time                  (UTCTime)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote
import           Language.Haskell.TH.Syntax

instance Lift UTCTime where

data Atom =
    Symbol Text
  | Variable Text
  | LInteger Int
  | LString Text
  | LDate UTCTime
  | LBytes ByteString
  | LBool Bool
  | Antiquote String

instance Lift Atom where
  lift (Symbol n)    = apply 'Symbol [lift n]
  lift (Variable n)  = apply 'Variable [lift n]
  lift (LInteger i)  = apply 'LInteger [lift i]
  lift (LString s)   = apply 'LString [lift s]
  lift (LDate t)     = apply 'LDate [lift t]
  lift (LBytes bs)   = apply 'LBytes [lift bs]
  lift (LBool b)     = apply 'LBool [lift b]
  lift (Antiquote n) = appE (varE 'toAtom) (varE $ mkName n)

apply :: Name -> [Q Exp] -> Q Exp
apply n = foldl appE (conE n)

class ToAtom t where
  toAtom :: t -> Atom

instance ToAtom Text where
  toAtom = LString

instance ToAtom Bool where
  toAtom = LBool

instance ToAtom ByteString where
  toAtom = LBytes

instance Show Atom where
  show = unpack . renderAtom

renderAtom :: Atom -> Text
renderAtom = \case
  Symbol name    -> "#" <> name
  Variable name  -> "$" <> name
  LInteger int   -> pack $ show int
  LString str    -> pack $ show str
  LDate time     -> pack $ show time
  LBytes bs      -> "hex:" <> decodeUtf8 (hex bs)
  LBool True     -> "true"
  LBool False    -> "false"
  Antiquote str  -> "${" <> pack str <> "}"

data Predicate = Predicate
  { name :: Text
  , ids  :: [Atom]
  }
  deriving stock (Lift)

instance Show Predicate where
  show = unpack . renderPredicate

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,ids} =
  name <> "(" <> intercalate ", " (fmap renderAtom ids) <> ")"

data Rule = Rule
  { head :: Predicate
  , body :: [Predicate]
  }
  deriving stock (Lift)

instance Show Rule where
  show = unpack . renderRule

renderRule :: Rule -> Text
renderRule Rule{head,body} =
  renderPredicate head <> " <- " <> intercalate ", " (fmap renderPredicate body)

atomParser :: Parser Atom
atomParser =
  let ap = Antiquote <$> (string "${" *> many1 letter <* char '}')
      sp = Symbol . pack <$> (char '#' *> many1 letter)
      vp = Variable . pack <$> (char '$' *> many1 letter)
      ip = LInteger <$> signed decimal
      bp = LBool <$> ((True <$ string "true") <|> (False <$ string "false"))
   in ap <|> sp <|> vp <|> ip

predicateParser :: Parser Predicate
predicateParser = do
  name <- pack <$> many1 letter
  char('(')
  ids <- atomParser `sepBy` string ", "
  char(')')
  pure Predicate{name, ids}

ruleParser :: Parser Rule
ruleParser = do
  head <- predicateParser
  string " <- "
  body <- predicateParser `sepBy` (char ',')
  pure Rule{head, body}

compileRule :: String -> Q Exp
compileRule str = case parseOnly ruleParser (pack str) of
  Right rule -> [| rule |]
  Left e     -> fail e

rule :: QuasiQuoter
rule = QuasiQuoter
  { quoteExp = compileRule
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }
