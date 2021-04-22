{-# LANGUAGE DeriveLift         #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE TemplateHaskell    #-}
{-# LANGUAGE TypeApplications   #-}
module Datalog.Parser where

import           Control.Applicative        (liftA2, many, optional, (<|>))
import           Data.Attoparsec.Text
import           Data.ByteString            (ByteString)
import qualified Data.ByteString.Char8      as C8
import           Data.Char
import           Data.Either                (partitionEithers)
import           Data.Foldable              (fold)
import           Data.Functor               (void, ($>))
import           Data.Hex                   (hex, unhex)
import           Data.List.NonEmpty         (NonEmpty)
import           Data.String                (IsString (..))
import           Data.Text                  (Text, intercalate, pack, unpack)
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)
import           Data.Time                  (UTCTime, defaultTimeLocale,
                                             parseTimeM)
import           Data.Void                  (Void)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote
import           Language.Haskell.TH.Syntax

import           Datalog.AST

class SliceParser antiquote where
  sliceParser :: Parser (ID' antiquote)

instance SliceParser String where
  sliceParser = Antiquote <$> (string "${" *> many1 letter <* char '}')

instance SliceParser Void where
  sliceParser = fail "antiquotes are not supported in this context"

-- | Parser for an identifier (predicate name, variable name, symbol name, …)
nameParser :: Parser Text
nameParser = takeWhile1 $ inClass "a-zA-Z0-9_"

delimited :: Parser x
          -> Parser y
          -> Parser a
          -> Parser a
delimited before after p = before *> p <* after

parens :: Parser a -> Parser a
parens = delimited (char '(') (skipSpace *> char ')')

commaList :: Parser a -> Parser [a]
commaList p =
  sepBy1 p (skipSpace *> char ',')

commaList0 :: Parser a -> Parser [a]
commaList0 p =
  sepBy p (skipSpace *> char ',')

predicateParser :: SliceParser antiquote => Parser (Predicate' antiquote)
predicateParser = do
  skipSpace
  name <- nameParser
  skipSpace
  terms <- parens (commaList termParser)
  pure Predicate{name,terms}

hexBsParser :: Parser ByteString
hexBsParser = do
  string "hex:"
  digits <- unhex . encodeUtf8 <$> takeWhile1 (inClass "0-9a-fA-F")
  either undefined pure digits

litStringParser :: Parser Text
litStringParser =
  let regularChars = takeTill (inClass "\"\\")
      escaped = choice
        [ string "\\n" $> "\n"
        , string "\\\"" $> "\""
        , string "\\\\"  $> "\\"
        ]
      str = do
        f <- regularChars
        r <- optional (liftA2 (<>) escaped str)
        pure $ f <> fold r
   in char '"' *> str <* char '"'

rfc3339DateParser :: Parser UTCTime
rfc3339DateParser =
  -- get all the chars until the end of the term
  -- a term can be terminated by
  --  - a space (before another delimiter)
  --  - a comma (before another term)
  --  - a closing paren (the end of a term list)
  --  - a closing bracket (the end of a set)
  let getDateInput = takeWhile1 (notInClass ", )]")
      parseDate = parseTimeM False defaultTimeLocale "%FT%T%Q%EZ"
   in parseDate . unpack =<< getDateInput

termParser :: SliceParser antiquote => Parser (ID' antiquote)
termParser = skipSpace *> choice
  [ sliceParser
  , Symbol <$> (char '#' *> nameParser)
  , Variable <$> (char '$' *> nameParser)
  , LBytes <$> hexBsParser
  , LDate <$> rfc3339DateParser
  , LInteger <$> signed decimal
  , LString <$> litStringParser
  , LBool <$> choice [ string "true"  $> True
                     , string "false" $> False
                     ]
  ]

-- | same as a predicate, but allows empty
-- | terms list
ruleHeadParser :: SliceParser antiquote => Parser (Predicate' antiquote)
ruleHeadParser = do
  skipSpace
  name <- nameParser
  skipSpace
  terms <- parens (commaList0 termParser)
  pure Predicate{name,terms}

ruleBodyParser :: SliceParser antiquote
               => Parser [Either (Predicate' antiquote) (Expression' antiquote)]
ruleBodyParser = do
  let predicateOrExprParser =
            Right <$> (fail "no expr yet")
        <|> Left <$> predicateParser
  sepBy1 (skipSpace *> predicateOrExprParser)
         (skipSpace *> char ',')


ruleParser :: SliceParser antiquote => Parser (Rule' antiquote)
ruleParser = do
  rhead <- ruleHeadParser
  skipSpace
  string "<-"
  (body, _) <- partitionEithers <$> ruleBodyParser
  pure Rule{rhead, body}

compileRule :: String -> Q Exp
compileRule str = case parseOnly (ruleParser @String) (pack str) of
  Right rule -> [| rule |]
  Left e     -> fail e

rule :: QuasiQuoter
rule = QuasiQuoter
  { quoteExp = compileRule
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

pRule :: Text -> Either String (Rule' String)
pRule = parseOnly ruleParser

pPred :: Text -> Either String (Predicate' String)
pPred = parseOnly predicateParser

pTerm :: Text -> Either String (ID' String)
pTerm = parseOnly termParser
