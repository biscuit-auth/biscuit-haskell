{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE ConstraintKinds       #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveLift            #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeFamilies          #-}
{- HLINT ignore "Reduce duplication" -}
module Datalog.Parser where

import           Control.Applicative       (liftA2, optional, (<|>))
import           Data.Attoparsec.Text
import           Data.ByteString           (ByteString)
import           Data.Either               (partitionEithers)
import           Data.Foldable             (fold)
import           Data.Functor              (void, ($>))
import           Data.Hex                  (unhex)
import qualified Data.Set                  as Set
import           Data.Text                 (Text, pack, unpack)
import           Data.Text.Encoding        (encodeUtf8)
import           Data.Time                 (UTCTime, defaultTimeLocale,
                                            parseTimeM)
import           Data.Void                 (Void)
import           Instances.TH.Lift         ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote

import           Datalog.AST

class ConditionalParse a v where
  ifPresent :: String -> Parser a -> Parser v

instance ConditionalParse a Void where
  ifPresent name _ = fail $ name <> " is not available in this context"

instance ConditionalParse m m where
  ifPresent _ p = p

class SetParser (inSet :: IsWithinSet) (ctx :: ParsedAs) where
  parseSet :: Parser (SetType inSet ctx)

instance SetParser 'WithinSet ctx where
  parseSet = fail "nested sets are forbidden"

instance SetParser 'NotWithinSet 'QuasiQuote where
  parseSet = Set.fromList <$> (char '[' *> commaList0 termParser <* char ']')

instance SetParser 'NotWithinSet 'RegularString where
  parseSet = Set.fromList <$> (char '[' *> commaList0 termParser <* char ']')

type HasTermParsers inSet ctx =
  ( ConditionalParse (SliceType inSet 'QuasiQuote)       (SliceType inSet ctx)
  , ConditionalParse (VariableType 'NotWithinSet ctx)    (VariableType inSet ctx)
  , SetParser inSet ctx
  )
type HasParsers ctx = HasTermParsers 'NotWithinSet ctx

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

predicateParser :: HasParsers ctx => Parser (Predicate' ctx)
predicateParser = do
  skipSpace
  name <- nameParser
  skipSpace
  terms <- parens (commaList termParser)
  pure Predicate{name,terms}

hexBsParser :: Parser ByteString
hexBsParser = do
  void $ string "hex:"
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

termParser :: forall inSet ctx
            . ( HasTermParsers inSet ctx
              )
           => Parser (ID' inSet ctx)
termParser = skipSpace *> choice
  [ Antiquote <$> ifPresent "slice" (string "${" *> many1 letter <* char '}')
  , Variable <$> ifPresent "var" (char '$' *> nameParser)
  , TermSet <$> parseSet @inSet @ctx
  , Symbol <$> (char '#' *> nameParser)
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
ruleHeadParser :: HasParsers ctx => Parser (Predicate' ctx)
ruleHeadParser = do
  skipSpace
  name <- nameParser
  skipSpace
  terms <- parens (commaList0 termParser)
  pure Predicate{name,terms}

ruleBodyParser :: HasParsers ctx
               => Parser [Either (Predicate' ctx) (Expression' ctx)]
ruleBodyParser = do
  let predicateOrExprParser =
            Right <$> fail "no expr yet"
        <|> Left <$> predicateParser
  sepBy1 (skipSpace *> predicateOrExprParser)
         (skipSpace *> char ',')


ruleParser :: HasParsers ctx => Parser (Rule' ctx)
ruleParser = do
  rhead <- ruleHeadParser
  skipSpace
  void $ string "<-"
  (body, _) <- partitionEithers <$> ruleBodyParser
  pure Rule{rhead, body}

compileRule :: String -> Q Exp
compileRule str = case parseOnly (ruleParser @'QuasiQuote) (pack str) of
  Right result -> [| result |]
  Left e       -> fail e

rule :: QuasiQuoter
rule = QuasiQuoter
  { quoteExp = compileRule
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

pRule :: Text -> Either String (Rule' 'QuasiQuote)
pRule = parseOnly ruleParser

pPred :: Text -> Either String (Predicate' 'QuasiQuote)
pPred = parseOnly predicateParser

pTerm :: Text -> Either String QQID
pTerm = parseOnly termParser
