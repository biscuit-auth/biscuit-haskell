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
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeFamilies          #-}
{- HLINT ignore "Reduce duplication" -}
module Auth.Biscuit.Datalog.Parser
  ( block
  , check
  , fact
  , predicate
  , rule
  , authorizer
  , query
  -- these are only exported for testing purposes
  , checkParser
  , expressionParser
  , policyParser
  , predicateParser
  , ruleParser
  , termParser
  , blockParser
  , authorizerParser
  , HasParsers
  , HasTermParsers
  ) where

import           Control.Applicative            (liftA2, optional, (<|>))
import qualified Control.Monad.Combinators.Expr as Expr
import           Data.Attoparsec.Text
import qualified Data.Attoparsec.Text           as A
import           Data.ByteString                (ByteString)
import           Data.ByteString.Base16         as Hex
import           Data.Char                      (isAlphaNum, isLetter, isLower,
                                                 isSpace)
import           Data.Either                    (partitionEithers)
import           Data.Foldable                  (fold)
import           Data.Functor                   (void, ($>))
import           Data.Maybe                     (isJust)
import qualified Data.Set                       as Set
import           Data.Text                      (Text, pack, singleton, unpack)
import           Data.Text.Encoding             (encodeUtf8)
import           Data.Time                      (UTCTime, defaultTimeLocale,
                                                 parseTimeM)
import           Data.Void                      (Void)
import           Instances.TH.Lift              ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Quote
import           Language.Haskell.TH.Syntax     (Lift)

import           Auth.Biscuit.Datalog.AST

class ConditionalParse a v where
  ifPresent :: String -> Parser a -> Parser v

instance ConditionalParse a Void where
  ifPresent name _ = fail $ name <> " is not available in this context"

instance ConditionalParse m m where
  ifPresent _ p = p

class SetParser (inSet :: IsWithinSet) (ctx :: DatalogContext) where
  parseSet :: Parser (SetType inSet ctx)

instance SetParser 'WithinSet ctx where
  parseSet = fail "nested sets are forbidden"

instance SetParser 'NotWithinSet 'WithSlices where
  parseSet = Set.fromList <$> (char '[' *> commaList0 termParser <* char ']')

instance SetParser 'NotWithinSet 'Representation where
  parseSet = Set.fromList <$> (char '[' *> commaList0 termParser <* char ']')

class ScopeParser (evalCtx :: EvaluationContext) (ctx :: DatalogContext) where
  parseBlockId :: Parser (BlockIdType evalCtx ctx)

instance ScopeParser 'Repr 'Representation where
  parseBlockId = string "ed25519/" *> hexBsParser

instance ScopeParser 'Repr 'WithSlices where
  parseBlockId = do
    choice [ Left . Slice <$> (string "${" *> haskellVariableParser <* char '}')
           , Right <$> (string "ed25519/" *> hexBsParser)
           ]

type HasTermParsers inSet pof ctx =
  ( ConditionalParse (SliceType 'WithSlices)                   (SliceType ctx)
  , ConditionalParse (VariableType 'NotWithinSet 'InPredicate) (VariableType inSet pof)
  , SetParser inSet ctx
  )
type HasTopTermParsers pof ctx = HasTermParsers 'NotWithinSet pof ctx
type HasParsers pof evalCtx ctx =
  ( ScopeParser evalCtx ctx
  , Ord (BlockIdType evalCtx ctx)
  , HasTermParsers 'NotWithinSet pof ctx
  )

-- | Parser for a datalog predicate name
predicateNameParser :: Parser Text
predicateNameParser = do
  first <- satisfy isLetter
  rest  <- A.takeWhile $ \c -> c == '_' || c == ':' || isAlphaNum c
  pure $ singleton first <> rest

variableNameParser :: Parser Text
variableNameParser = char '$' *> takeWhile1 (\c -> c == '_' || c == ':' || isAlphaNum c)

haskellVariableParser :: Parser Text
haskellVariableParser = do
  leadingUS <- optional $ char '_'
  first <- if isJust leadingUS
           then satisfy isLetter
           else satisfy (\c -> isLetter c && isLower c)
  rest  <- A.takeWhile (\c -> c == '_' || c == '\'' || isAlphaNum c)
  pure $ foldMap singleton leadingUS <> singleton first <> rest

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

predicateParser :: HasTopTermParsers pof ctx => Parser (Predicate' pof ctx)
predicateParser = do
  skipSpace
  name <- predicateNameParser
  skipSpace
  terms <- parens (commaList termParser)
  pure Predicate{name,terms}

unary :: HasTopTermParsers 'InPredicate ctx => Parser (Expression' ctx)
unary = choice
  [ unaryParens
  , unaryNegate
  , unaryLength
  ]

unaryParens :: HasTopTermParsers 'InPredicate ctx => Parser (Expression' ctx)
unaryParens = do
  skipSpace
  _ <- char '('
  skipSpace
  e <- expressionParser
  skipSpace
  _ <- char ')'
  pure $ EUnary Parens e

unaryNegate :: HasTopTermParsers 'InPredicate ctx => Parser (Expression' ctx)
unaryNegate = do
  skipSpace
  _ <- char '!'
  skipSpace
  EUnary Negate <$> expressionParser

unaryLength :: HasTopTermParsers 'InPredicate ctx => Parser (Expression' ctx)
unaryLength = do
  skipSpace
  e <- choice
         [ EValue <$> termParser
         , unaryParens
         ]
  skipSpace
  _ <- string ".length()"
  pure $ EUnary Length e

exprTerm :: HasTopTermParsers 'InPredicate ctx => Parser (Expression' ctx)
exprTerm = choice
  [ unary
  , EValue <$> termParser
  ]

methodParser :: HasTopTermParsers 'InPredicate ctx => Parser (Expression' ctx)
methodParser = do
  e1 <- exprTerm
  _ <- char '.'
  method <- choice
    [ Contains     <$ string "contains"
    , Intersection <$ string "intersection"
    , Union        <$ string "union"
    , Prefix       <$ string "starts_with"
    , Suffix       <$ string "ends_with"
    , Regex        <$ string "matches"
    ]
  _ <- char '('
  skipSpace
  e2 <- expressionParser
  skipSpace
  _ <- char ')'
  pure $ EBinary method e1 e2

expressionParser :: HasTopTermParsers 'InPredicate ctx => Parser (Expression' ctx)
expressionParser = Expr.makeExprParser (methodParser <|> exprTerm) table

table :: HasTopTermParsers 'InPredicate ctx
      => [[Expr.Operator Parser (Expression' ctx)]]
table = [ [ binary  "*" Mul
          , binary  "/" Div
          ]
        , [ binary  "+" Add
          , binary  "-" Sub
          ]
        , [ binary  "<=" LessOrEqual
          , binary  ">=" GreaterOrEqual
          , binary  "<"  LessThan
          , binary  ">"  GreaterThan
          , binary  "==" Equal
          ]
        , [ binary  "&&" And
          , binary  "||" Or
          ]
        ]

binary :: HasTopTermParsers 'InPredicate ctx
       => Text
       -> Binary
       -> Expr.Operator Parser (Expression' ctx)
binary name op = Expr.InfixL  (EBinary op <$ (skipSpace *> string name))

hexBsParser :: Parser ByteString
hexBsParser = do
  void $ string "hex:"
  either fail pure . Hex.decode . encodeUtf8 =<< takeWhile1 (inClass "0-9a-fA-F")

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
  let getDateInput = takeWhile1 (notInClass ", )];")
      parseDate = parseTimeM False defaultTimeLocale "%FT%T%Q%EZ"
   in parseDate . unpack =<< getDateInput

termParser :: forall inSet pof ctx
            . ( HasTermParsers inSet pof ctx
              )
           => Parser (Term' inSet pof ctx)
termParser = skipSpace *> choice
  [ Antiquote <$> ifPresent "slice" (Slice <$> (string "${" *> haskellVariableParser <* char '}'))
  , Variable <$> ifPresent "var" variableNameParser
  , TermSet <$> parseSet @inSet @ctx
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
ruleHeadParser :: HasTopTermParsers 'InPredicate ctx => Parser (Predicate' 'InPredicate ctx)
ruleHeadParser = do
  skipSpace
  name <- predicateNameParser
  skipSpace
  terms <- parens (commaList0 termParser)
  pure Predicate{name,terms}

ruleBodyParser :: (HasParsers 'InPredicate evalCtx ctx)
               => Parser ([Predicate' 'InPredicate ctx], [Expression' ctx], Set.Set (RuleScope' evalCtx ctx))
ruleBodyParser = do
  let predicateOrExprParser =
            Right <$> expressionParser
        <|> Left <$> predicateParser
  elems <- sepBy1 (skipSpace *> predicateOrExprParser)
                  (skipSpace *> char ',')
  scope <- ruleScopeParser
  let (predicates, expressions) = partitionEithers elems
  pure (predicates, expressions, scope)

scopeParser :: forall evalCtx ctx
             . ( ScopeParser evalCtx ctx
               , Ord (BlockIdType evalCtx ctx)
               )
            => Parser (Set.Set (RuleScope' evalCtx ctx))
scopeParser =
  let elemParser = choice [ OnlyAuthority <$  string "authority"
                          , Previous      <$  string "previous"
                          , BlockId       <$> parseBlockId @evalCtx @ctx
                          ]
   in Set.fromList <$> sepBy1 (skipSpace *> elemParser)
                              (skipSpace *> char ',')

ruleScopeParser :: forall evalCtx ctx
                 . ( ScopeParser evalCtx ctx
                   , Ord (BlockIdType evalCtx ctx)
                   )
                => Parser (Set.Set (RuleScope' evalCtx ctx))
ruleScopeParser = option Set.empty $ do
  skipSpace
  void $ string "@"
  skipSpace
  scopeParser

ruleParser :: HasParsers 'InPredicate evalCtx ctx
           => Parser (Rule' evalCtx ctx)
ruleParser = do
  rhead <- ruleHeadParser
  skipSpace
  void $ string "<-"
  (body, expressions, scope) <- ruleBodyParser
  pure Rule{rhead, body, expressions, scope }

queryParser :: HasParsers 'InPredicate evalCtx ctx => Parser (Query' evalCtx ctx)
queryParser =
  let mkQueryItem (qBody, qExpressions, qScope) = QueryItem { qBody, qExpressions, qScope }
   in fmap mkQueryItem <$> sepBy1 ruleBodyParser (skipSpace *> asciiCI "or" <* satisfy isSpace)

checkParser :: HasParsers 'InPredicate evalCtx ctx => Parser (Check' evalCtx ctx)
checkParser = string "check if" *> queryParser

commentParser :: Parser ()
commentParser = do
  skipSpace
  _ <- string "//"
  _ <- skipWhile ((&&) <$> (/= '\r') <*> (/= '\n'))
  void $ choice [ void (char '\n')
                , void (string "\r\n")
                , endOfInput
                ]

blockElementParser :: HasParsers 'InPredicate evalCtx ctx => Parser (BlockElement' evalCtx ctx)
blockElementParser = choice
  [ BlockRule    <$> ruleParser <* skipSpace <* char ';'
  , BlockFact    <$> predicateParser <* skipSpace <* char ';'
  , BlockCheck   <$> checkParser <* skipSpace <* char ';'
  , BlockComment <$  commentParser
  ]

authorizerElementParser :: HasParsers 'InPredicate evalCtx ctx => Parser (AuthorizerElement' evalCtx ctx)
authorizerElementParser = choice
  [ AuthorizerPolicy  <$> policyParser <* skipSpace <* char ';'
  , BlockElement    <$> blockElementParser
  ]

blockScopeParser :: forall evalCtx ctx
                  . ( ScopeParser evalCtx ctx
                    , Ord (BlockIdType evalCtx ctx)
                    )
                 => Parser (Set.Set (RuleScope' evalCtx ctx))
blockScopeParser = option Set.empty $ do
  skipSpace
  void $ string "trusting "
  skipSpace
  scope <- scopeParser
  void $ char ';'
  pure scope

authorizerParser :: ( HasParsers 'InPredicate evalCtx ctx
                    , HasParsers 'InFact evalCtx ctx
                    , Show (AuthorizerElement' evalCtx ctx)
                    )
                 => Parser (Authorizer' evalCtx ctx)
authorizerParser = do
  bScope <- blockScopeParser
  elems <- many' (skipSpace *> authorizerElementParser)
  let addScope a = a { vBlock = (vBlock a) { bScope = bScope } }
  pure $ addScope $ foldMap elementToAuthorizer elems

blockParser :: ( HasParsers 'InPredicate evalCtx ctx
               , HasParsers 'InFact evalCtx ctx
               , Show (BlockElement' evalCtx ctx)
               )
            => Parser (Block' evalCtx ctx)
blockParser = do
  bScope <- blockScopeParser
  elems <- many' (skipSpace *> blockElementParser)
  pure $ (foldMap elementToBlock elems) { bScope = bScope }

policyParser :: HasParsers 'InPredicate evalCtx ctx => Parser (Policy' evalCtx ctx)
policyParser = do
  policy <- choice
              [ Allow <$ string "allow if"
              , Deny  <$ string "deny if"
              ]
  (policy, ) <$> queryParser

compileParser :: Lift a => Parser a -> String -> Q Exp
compileParser p str = case parseOnly (p <* skipSpace <* endOfInput) (pack str) of
  Right result -> [| result |]
  Left e       -> fail e

-- | Quasiquoter for a rule expression. You can reference haskell variables
-- like this: @${variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
rule :: QuasiQuoter
rule = QuasiQuoter
  { quoteExp = compileParser (ruleParser @'Repr @'WithSlices)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Quasiquoter for a predicate expression. You can reference haskell variables
-- like this: @${variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
predicate :: QuasiQuoter
predicate = QuasiQuoter
  { quoteExp = compileParser (predicateParser @'InPredicate @'WithSlices)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Quasiquoter for a fact expression. You can reference haskell variables
-- like this: @${variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
fact :: QuasiQuoter
fact = QuasiQuoter
  { quoteExp = compileParser (predicateParser @'InFact @'WithSlices)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Quasiquoter for a check expression. You can reference haskell variables
-- like this: @${variableName}@.
--
-- You most likely want to directly use 'block' or 'authorizer' instead.
check :: QuasiQuoter
check = QuasiQuoter
  { quoteExp = compileParser (checkParser @'Repr @'WithSlices)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Compile-time parser for a block expression, intended to be used with the
-- @QuasiQuotes@ extension.
--
-- A typical use of 'block' looks like this:
--
-- > let fileName = "data.pdf"
-- >  in [block|
-- >       // datalog can reference haskell variables with ${variableName}
-- >       resource(${fileName});
-- >       rule($variable) <- fact($value), other_fact($value);
-- >       check if operation("read");
-- >     |]
block :: QuasiQuoter
block = QuasiQuoter
  { quoteExp = compileParser (blockParser @'Repr @'WithSlices)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Compile-time parser for an authorizer expression, intended to be used with the
-- @QuasiQuotes@ extension.
--
-- A typical use of 'authorizer' looks like this:
--
-- > do
-- >   now <- getCurrentTime
-- >   pure [authorizer|
-- >          // datalog can reference haskell variables with ${variableName}
-- >          current_time(${now});
-- >          // authorizers can contain facts, rules and checks like blocks, but
-- >          // also declare policies. While every check has to pass for a biscuit to
-- >          // be valid, policies are tried in order. The first one to match decides
-- >          // if the token is valid or not
-- >          allow if resource("file1");
-- >          deny if true;
-- >        |]
authorizer :: QuasiQuoter
authorizer = QuasiQuoter
  { quoteExp = compileParser (authorizerParser @'Repr @'WithSlices)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

-- | Compile-time parser for a query expression, intended to be used with the
-- @QuasiQuotes@ extension.
--
-- A typical use of 'query' looks like this:
--
-- > [query|user($user_id) or group($group_id)|]
query :: QuasiQuoter
query = QuasiQuoter
  { quoteExp = compileParser (queryParser @'Repr @'WithSlices)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }
