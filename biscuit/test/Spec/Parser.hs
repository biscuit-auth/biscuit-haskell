{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Spec.Parser (specs) where

import           Data.Attoparsec.Text        (parseOnly)
import qualified Data.Set                    as Set
import           Data.Text                   (Text)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit.Datalog.AST
import           Auth.Biscuit.Datalog.Parser (authorizerParser, blockParser,
                                              checkParser, expressionParser,
                                              policyParser, predicateParser,
                                              ruleParser, termParser)

parseTerm :: Text -> Either String Term
parseTerm = parseOnly termParser

parseTermQQ :: Text -> Either String QQTerm
parseTermQQ = parseOnly termParser

parsePredicate :: Text -> Either String Predicate
parsePredicate = parseOnly predicateParser

parseRule :: Text -> Either String Rule
parseRule = parseOnly ruleParser

parseExpression :: Text -> Either String Expression
parseExpression = parseOnly expressionParser

parseCheck :: Text -> Either String Check
parseCheck = parseOnly checkParser

parseAuthorizer :: Text -> Either String Authorizer
parseAuthorizer = parseOnly authorizerParser

parsePolicy :: Text -> Either String Policy
parsePolicy = parseOnly policyParser

parseBlock :: Text -> Either String Block
parseBlock = parseOnly blockParser

specs :: TestTree
specs = testGroup "datalog parser"
  [
    factWithDate
  , simpleFact
  , oneLetterFact
  , simpleRule
  , multilineRule
  , termsGroup
  , termsGroupQQ
  , constraints
  , constrainedRule
  , constrainedRuleOrdering
  , ruleWithScopeParsing
  , checkParsing
  , policyParsing
  , authorizerParsing
  , blockParsing
  ]

termsGroup :: TestTree
termsGroup = testGroup "Parse terms"
  [ testCase "String" $ parseTerm "\"file1 a hello - 123_\"" @?= Right (LString "file1 a hello - 123_")
  , testCase "Positive integer" $ parseTerm "123" @?= Right (LInteger 123)
  , testCase "Negative integer" $ parseTerm "-42" @?= Right (LInteger (-42))
  , testCase "Date" $ parseTerm "2019-12-02T13:49:53Z" @?=
        Right (LDate $ read "2019-12-02 13:49:53 UTC")
  , testCase "Variable" $ parseTerm "$1" @?= Right (Variable "1")
  , testCase "Antiquote" $ parseTerm "${toto}" @?= Left "Failed reading: empty"
  ]

termsGroupQQ :: TestTree
termsGroupQQ = testGroup "Parse terms (in a QQ setting)"
  [ testCase "String" $ parseTermQQ "\"file1 a hello - 123_\"" @?= Right (LString "file1 a hello - 123_")
  , testCase "Positive integer" $ parseTermQQ "123" @?= Right (LInteger 123)
  , testCase "Negative integer" $ parseTermQQ "-42" @?= Right (LInteger (-42))
  , testCase "Date" $ parseTermQQ "2019-12-02T13:49:53Z" @?=
        Right (LDate $ read "2019-12-02 13:49:53 UTC")
  , testCase "Variable" $ parseTermQQ "$1" @?= Right (Variable "1")
  , testGroup "Antiquote"
     [ testCase "Variable name" $ parseTermQQ "${toto2_'}" @?= Right (Antiquote "toto2_'")
     , testCase "Leading underscore" $ parseTermQQ "${_toto}" @?= Right (Antiquote "_toto")
     , testCase "`_` is reserved" $ parseTermQQ "${_}" @?= Left "Failed reading: empty"
     , testCase "Variables are lower-cased" $ parseTermQQ "${Toto}" @?= Left "Failed reading: empty"
     , testCase "_ is lower-case" $ parseTermQQ "${_Toto}" @?= Right (Antiquote "_Toto")
     , testCase "unicode is allowed" $ parseTermQQ "${éllo}" @?= Right (Antiquote "éllo")
     ]
  ]

simpleFact :: TestTree
simpleFact = testCase "Parse simple fact" $
  parsePredicate "right(\"file1\", \"read\")" @?=
    Right (Predicate "right" [LString "file1", LString "read"])

oneLetterFact :: TestTree
oneLetterFact = testCase "Parse one-letter fact" $
  parsePredicate "a(12)" @?=
    Right (Predicate "a" [LInteger 12])

factWithDate :: TestTree
factWithDate = testCase "Parse fact containing a date" $
  parsePredicate "date(2019-12-02T13:49:53Z)" @?=
    Right (Predicate "date" [LDate $ read "2019-12-02 13:49:53 UTC"])

simpleRule :: TestTree
simpleRule = testCase "Parse simple rule" $
  parseRule "right($0, \"read\") <- resource( $0), operation(\"read\")" @?=
    Right (Rule (Predicate "right" [Variable "0", LString "read"])
                [ Predicate "resource" [Variable "0"]
                , Predicate "operation" [LString "read"]
                ] [] Nothing)

multilineRule :: TestTree
multilineRule = testCase "Parse multiline rule" $
  parseRule "right($0, \"read\") <-\n resource( $0),\n operation(\"read\")" @?=
    Right (Rule (Predicate "right" [Variable "0", LString "read"])
                [ Predicate "resource" [Variable "0"]
                , Predicate "operation" [LString "read"]
                ] [] Nothing)

constrainedRule :: TestTree
constrainedRule = testCase "Parse constained rule" $
  parseRule "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2019-12-04T09:46:41+00:00" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Variable "0"]
                , Predicate "resource" [LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ] Nothing)

constrainedRuleOrdering :: TestTree
constrainedRuleOrdering = testCase "Parse constained rule (interleaved)" $
  parseRule "valid_date(\"file1\") <- time($0), $0 <= 2019-12-04T09:46:41+00:00, resource(\"file1\")" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Variable "0"]
                , Predicate "resource" [LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ] Nothing)

constraints :: TestTree
constraints = testGroup "Parse expressions"
  [ testCase "date comparison (LTE)" $
      parseExpression "$0 <= 2030-12-31T12:59:59+00:00" @?=
        Right (EBinary LessOrEqual
                 (EValue (Variable "0"))
                 (EValue (LDate $ read "2030-12-31 12:59:59 UTC"))
                 )
  , testCase "date comparison (GTE)" $
      parseExpression "$0 >= 2030-12-31T12:59:59+00:00" @?=
        Right (EBinary GreaterOrEqual
                 (EValue (Variable "0"))
                 (EValue (LDate $ read "2030-12-31 12:59:59 UTC"))
                 )
  , testCase "int comparison (LT)" $
      parseExpression "$0 < 1234" @?=
        Right (EBinary LessThan
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (GT)" $
      parseExpression "$0 > 1234" @?=
        Right (EBinary GreaterThan
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (LTE)" $
      parseExpression "$0 <= 1234" @?=
        Right (EBinary LessOrEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger 1234))
                 )
  , testCase "int comparison (EQ)" $
      parseExpression "$0 == 1" @?=
        Right (EBinary Equal
                 (EValue (Variable "0"))
                 (EValue (LInteger 1))
                 )
  , testCase "negative int comparison (GTE)" $
      parseExpression "$0 >= -1234" @?=
        Right (EBinary GreaterOrEqual
                 (EValue (Variable "0"))
                 (EValue (LInteger (-1234)))
                 )
  , testCase "string comparison" $
      parseExpression "$0 == \"abc\"" @?=
        Right (EBinary Equal
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (starts_with)" $
      parseExpression "$0.starts_with(\"abc\")" @?=
        Right (EBinary Prefix
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (ends_with)" $
      parseExpression "$0.ends_with(\"abc\")" @?=
        Right (EBinary Suffix
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "string comparison (matches)" $
      parseExpression "$0.matches(\"abc\")" @?=
        Right (EBinary Regex
                 (EValue (Variable "0"))
                 (EValue (LString "abc"))
                 )
  , testCase "int set operation" $
      parseExpression "[1, 2].contains($0)" @?=
        Right (EBinary Contains
                 (EValue (TermSet $ Set.fromList [LInteger 1, LInteger 2]))
                 (EValue (Variable "0"))
                 )
  , testCase "negated int set operation" $
      parseExpression "![1, 2].contains($0)" @?=
        Right (EUnary Negate
                 (EBinary Contains
                    (EValue (TermSet $ Set.fromList [LInteger 1, LInteger 2]))
                    (EValue (Variable "0"))
                    ))
  , testCase "string set operation" $
      parseExpression "[\"abc\", \"def\"].contains($0)" @?=
        Right (EBinary Contains
                 (EValue (TermSet $ Set.fromList [LString "abc", LString "def"]))
                 (EValue (Variable "0"))
                 )
  , testCase "negated string set operation" $
      parseExpression "![\"abc\", \"def\"].contains($0)" @?=
        Right (EUnary Negate
                 (EBinary Contains
                    (EValue (TermSet $ Set.fromList [LString "abc", LString "def"]))
                    (EValue (Variable "0"))
                    ))
  , operatorPrecedences
  ]

operatorPrecedences :: TestTree
operatorPrecedences = testGroup "mixed-precedence operators"
  [ testCase "< +" $
      parseExpression " 1 < $test + 2 " @?=
        Right (EBinary LessThan
                 (EValue $ LInteger 1)
                 (EBinary Add
                    (EValue $ Variable "test")
                    (EValue $ LInteger 2)
                 )
              )
  , testCase "< && starts_with" $
      parseExpression " 2 < $test && $var2.starts_with(\"test\") && true " @?=
        Right (EBinary And
                 (EBinary And
                    (EBinary LessThan
                       (EValue $ LInteger 2)
                       (EValue $ Variable "test")
                    )
                    (EBinary Prefix
                       (EValue $ Variable "var2")
                       (EValue $ LString "test")
                    )
                 )
                 (EValue $ LBool True)
              )
  , testCase "+ *" $
      parseExpression "1 + 2 * 3" @?=
        Right (EBinary Add
                 (EValue $ LInteger 1)
                 (EBinary Mul
                    (EValue $ LInteger 2)
                    (EValue $ LInteger 3)
                 )
              )
  , testCase "+ * parens" $
      parseExpression "(1 + 2) * 3" @?=
        Right (EBinary Mul
                 (EUnary Parens
                    (EBinary Add
                       (EValue $ LInteger 1)
                       (EValue $ LInteger 2)
                    )
                 )
                 (EValue $ LInteger 3)
              )
  ]

ruleWithScopeParsing :: TestTree
ruleWithScopeParsing = testCase "Parse constained rule with scope annotation" $
  parseRule "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2019-12-04T09:46:41+00:00 @ previous" @?=
    Right (Rule (Predicate "valid_date" [LString "file1"])
                [ Predicate "time" [Variable "0"]
                , Predicate "resource" [LString "file1"]
                ]
                [ EBinary LessOrEqual
                    (EValue $ Variable "0")
                    (EValue $ LDate $ read "2019-12-04 09:46:41 UTC")
                ] (Just Previous))

checkParsing :: TestTree
checkParsing = testGroup "check blocks"
  [ testCase "Simple check" $
      parseCheck "check if true" @?=
        Right [QueryItem [] [EValue $ LBool True] Nothing]
  , testCase "Multiple groups" $
      parseCheck
        "check if fact($var), $var == true or \
        \other($var), $var == 2" @?=
          Right
            [ QueryItem [Predicate "fact" [Variable "var"]]
                        [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                        Nothing
            , QueryItem [Predicate "other" [Variable "var"]]
                        [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                        Nothing
            ]
  , testCase "Multiple groups, scoped" $
      parseCheck
        "check if fact($var), $var == true @ previous or \
        \other($var), $var == 2 @ authority" @?=
          Right
            [ QueryItem [Predicate "fact" [Variable "var"]]
                        [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                        (Just Previous)
            , QueryItem [Predicate "other" [Variable "var"]]
                        [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                        (Just OnlyAuthority)
            ]
  ]

policyParsing :: TestTree
policyParsing = testGroup "policy blocks"
  [ testCase "Simple allow policy" $
      parsePolicy "allow if true" @?=
        Right (Allow, [QueryItem [] [EValue $ LBool True] Nothing])
  , testCase "Simple deny policy" $
      parsePolicy "deny if true" @?=
        Right (Deny, [QueryItem [] [EValue $ LBool True] Nothing])
  , testCase "Allow with multiple groups" $
      parsePolicy
        "allow if fact($var), $var == true or \
        \other($var), $var == 2" @?=
          Right
            ( Allow
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          Nothing
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          Nothing
              ]
            )
  , testCase "Deny with multiple groups" $
      parsePolicy
        "deny if fact($var), $var == true or \
        \other($var), $var == 2" @?=
          Right
            ( Deny
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          Nothing
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          Nothing
              ]
            )
  , testCase "Deny with multiple groups, multiline" $
      parsePolicy
        "deny if\n\
           \fact($var), $var == true or\n\
           \other($var), $var == 2" @?=
          Right
            ( Deny
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          Nothing
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          Nothing
              ]
            )
  , testCase "Allow with multiple groups, scoped" $
      parsePolicy
        "allow if fact($var), $var == true @ previous or \
        \other($var), $var == 2 @ed25519/hex:30,ed25519/hex:32,ed25519/hex:33 " @?=
          Right
            ( Allow
            , [ QueryItem [Predicate "fact" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LBool True))]
                          (Just Previous)
              , QueryItem [Predicate "other" [Variable "var"]]
                          [EBinary Equal (EValue (Variable "var")) (EValue (LInteger 2))]
                          (Just $ OnlyBlocks $ Set.fromList ["0","2","3"])
              ]
            )
  ]

authorizerParsing :: TestTree
authorizerParsing = testGroup "Simple authorizers"
  [ testCase "Just a deny" $
      parseAuthorizer "deny if true;" @?=
        Right (Authorizer [(Deny, [QueryItem [] [EValue (LBool True)] Nothing])] mempty
              )
  , testCase "Allow and deny" $
      parseAuthorizer "allow if operation(\"read\");\n deny if true;" @?=
        Right (Authorizer
                 [  (Allow, [QueryItem [Predicate "operation" [LString "read"]] [] Nothing])
                 , (Deny, [QueryItem [] [EValue (LBool True)] Nothing])
                 ]
                 mempty
              )
  , testCase "Complete authorizer" $ do
      let spec :: Text
          spec =
            " trusting previous;\n\
            \// the owner has all rights\n\
            \right($blog_id, $article_id, $operation) <-\n\
            \    article($blog_id, $article_id),\n\
            \    operation($operation),\n\
            \    user($user_id),\n\
            \    owner($user_id, $blog_id);\n\
            \// premium users can access some restricted articles\n\
            \right($blog_id, $article_id, \"read\") <-\n\
            \  article($blog_id, $article_id),\n\
            \  premium_readable($blog_id, $article_id),\n\
            \  user($user_id),\n\
            \  premium_user($user_id, $blog_id);\n\
            \// define teams and roles\n\
            \right($blog_id, $article_id, $operation) <-\n\
            \  article($blog_id, $article_id),\n\
            \  operation($operation),\n\
            \  user($user_id),\n\
            \  member($user_id, $team_id),\n\
            \  team_role($team_id, $blog_id, \"contributor\"),\n\
            \  [\"read\", \"write\"].contains($operation);\n\
            \// unauthenticated users have read access on published articles\n\
            \allow if\n\
            \  operation(\"read\"),\n\
            \  article($blog_id, $article_id),\n\
            \  readable($blog_id, $article_id);\n\
            \// authorize if got the rights on this blog and article\n\
            \allow if\n\
            \  blog($blog_id),\n\
            \  article($blog_id, $article_id),\n\
            \  operation($operation),\n\
            \  right($blog_id, $article_id, $operation);\n\
            \// catch all rule in case the allow did not match\n\
            \deny if true;\
            \ "
          p = Predicate
          sRead = LString "read"
          sWrite = LString "write"
          sContributor = LString "contributor"
          vBlogId = Variable "blog_id"
          vArticleId = Variable "article_id"
          vUserId = Variable "user_id"
          vTeamId = Variable "team_id"
          vOp = Variable "operation"
          bRules =
            [ Rule (p "right" [vBlogId, vArticleId, vOp])
                   [ p "article" [vBlogId, vArticleId]
                   , p "operation" [vOp]
                   , p "user" [vUserId]
                   , p "owner" [vUserId, vBlogId]
                   ] [] Nothing
            , Rule (p "right" [vBlogId, vArticleId, sRead])
                   [ p "article" [vBlogId, vArticleId]
                   , p "premium_readable" [vBlogId, vArticleId]
                   , p "user" [vUserId]
                   , p "premium_user" [vUserId, vBlogId]
                   ] [] Nothing
            , Rule (p "right" [vBlogId, vArticleId, vOp])
                   [ p "article" [vBlogId, vArticleId]
                   , p "operation" [vOp]
                   , p "user" [vUserId]
                   , p "member" [vUserId, vTeamId]
                   , p "team_role" [vTeamId, vBlogId, sContributor]
                   ] [EBinary Contains (EValue (TermSet $ Set.fromList [sRead, sWrite]))
                                       (EValue vOp)] Nothing
           ]
          bFacts = []
          bChecks = []
          bContext = Nothing
          bScope = Just Previous
          vPolicies =
            [ (Allow, [QueryItem [ p "operation" [sRead]
                                 , p "article"   [vBlogId, vArticleId]
                                 , p "readable"  [vBlogId, vArticleId]
                                 ] [] Nothing])
            , (Allow, [QueryItem [ p "blog" [vBlogId]
                                 , p "article" [vBlogId, vArticleId]
                                 , p "operation" [vOp]
                                 , p "right" [vBlogId, vArticleId, vOp]
                                 ] [] Nothing])
            , (Deny, [QueryItem [] [EValue (LBool True)] Nothing])
            ]
      parseAuthorizer spec @?= Right Authorizer{vBlock = Block{..}, ..}
  ]

blockParsing :: TestTree
blockParsing = testCase "Full block" $ do
  let spec :: Text
      spec =
        " trusting ed25519/hex:31,ed25519/hex:32,ed25519/hex:34;\n\
        \// the owner has all rights\n\
        \right($blog_id, $article_id, $operation) <-\n\
        \    article($blog_id, $article_id),\n\
        \    operation($operation),\n\
        \    user($user_id),\n\
        \    owner($user_id, $blog_id);\n\
        \// premium users can access some restricted articles\n\
        \right($blog_id, $article_id, \"read\") <-\n\
        \  article($blog_id, $article_id),\n\
        \  premium_readable($blog_id, $article_id),\n\
        \  user($user_id),\n\
        \  premium_user($user_id, $blog_id);\n\
        \// define teams and roles\n\
        \right($blog_id, $article_id, $operation) <-\n\
        \  article($blog_id, $article_id),\n\
        \  operation($operation),\n\
        \  user($user_id),\n\
        \  member($user_id, $team_id),\n\
        \  team_role($team_id, $blog_id, \"contributor\"),\n\
        \  [\"read\", \"write\"].contains($operation);\n\
        \ "
      p = Predicate
      sRead = LString "read"
      sWrite = LString "write"
      sContributor = LString "contributor"
      vBlogId = Variable "blog_id"
      vArticleId = Variable "article_id"
      vUserId = Variable "user_id"
      vTeamId = Variable "team_id"
      vOp = Variable "operation"
      bRules =
        [ Rule (p "right" [vBlogId, vArticleId, vOp])
               [ p "article" [vBlogId, vArticleId]
               , p "operation" [vOp]
               , p "user" [vUserId]
               , p "owner" [vUserId, vBlogId]
               ] [] Nothing
        , Rule (p "right" [vBlogId, vArticleId, sRead])
               [ p "article" [vBlogId, vArticleId]
               , p "premium_readable" [vBlogId, vArticleId]
               , p "user" [vUserId]
               , p "premium_user" [vUserId, vBlogId]
               ] [] Nothing
        , Rule (p "right" [vBlogId, vArticleId, vOp])
               [ p "article" [vBlogId, vArticleId]
               , p "operation" [vOp]
               , p "user" [vUserId]
               , p "member" [vUserId, vTeamId]
               , p "team_role" [vTeamId, vBlogId, sContributor]
               ] [EBinary Contains (EValue (TermSet $ Set.fromList [sRead, sWrite]))
                                   (EValue vOp)] Nothing
       ]
      bFacts = []
      bChecks = []
      bContext = Nothing
      bScope = Just $ OnlyBlocks $ Set.fromList ["1","2","4"]
  parseBlock spec @?= Right Block{..}
