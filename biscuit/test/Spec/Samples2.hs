{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Spec.Samples2
  ( specs
  ) where

import           Data.ByteString             (ByteString)
import qualified Data.ByteString             as ByteString
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Crypto
import           Auth.Biscuit.Datalog.AST    (Block)
import           Auth.Biscuit.Datalog.Parser (block)
import           Auth.Biscuit.Token2         (Biscuit, Biscuit' (..),
                                              ParseError (..), parseBiscuit)


pk :: PublicKey
pk = maybe undefined id $ parsePublicKeyHex "acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

readFromFile :: FilePath -> IO (Either ParseError Biscuit)
readFromFile path =
  parseBiscuit pk <$> ByteString.readFile ("test/samples/v2/" <> path)

getB ((_, b), _, _) = b

getAuthority :: Biscuit -> Block
getAuthority Biscuit{authority} = getB authority

getBlocks :: Biscuit -> [Block]
getBlocks Biscuit{blocks} = getB <$> blocks

specs :: TestTree
specs = testGroup "Biscuit samples"
  [ testCase "test1_basic" $ do
      result <- readFromFile "test1_basic.bc"
      getAuthority <$> result @?= Right
        [block|
          right(#authority, "file1", #read);
          right(#authority, "file2", #read);
          right(#authority, "file1", #write);
        |]
      getBlocks <$> result @?= Right
        [ [block|
            check if
              resource(#ambient, $0),
              operation(#ambient, #read),
              right(#authority, $0, #read);
          |]
        ]
  , testCase "test9_expired_token" $ do
      result <- readFromFile "test9_expired_token.bc"
      getAuthority <$> result @?= Right mempty
      getBlocks <$> result @?= Right
        [ [block|
            check if resource(#ambient, "file1");
            check if time(#ambient, $date), $date <= 2018-12-20T00:00:00+00:00;
          |]
        ]
  , testCase "test13_block_rules" $ do
      result <- readFromFile "test13_block_rules.bc"
      getAuthority <$> result @?= Right
        [block|
          right(#authority, "file1", #read);
          right(#authority, "file2", #read);
        |]
      getBlocks <$> result @?= Right
        [ [block|
            valid_date("file1") <- time(#ambient, $0), resource(#ambient, "file1"), $0 <= 2030-12-31T12:59:59+00:00;
            valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, !["file1"].contains($1);
            check if valid_date($0), resource(#ambient, $0);
          |]
        ]
  , testCase "test17_expressions" $ do
      result <- readFromFile "test17_expressions.bc"
      getAuthority <$> result @?= Right
        [block|
           check if true;
           check if !false;
           check if false or true;
           check if 1 < 2;
           check if 2 > 1;
           check if 1 <= 2;
           check if 1 <= 1;
           check if 2 >= 1;
           check if 2 >= 2;
           check if 3 == 3;
           check if 1 + 2 * 3 - 4 / 2 == 5;
           check if "hello world".starts_with("hello") && "hello world".ends_with("world");
           check if "aaabde".matches("a*c?.e");
           check if "abcD12" == "abcD12";
           check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00;
           check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00;
           check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00;
           check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
           check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00;
           check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
           check if 2020-12-04T09:46:41+00:00 == 2020-12-04T09:46:41+00:00;
           check if #abc == #abc;
           check if hex:12ab == hex:12ab;
           check if [1, 2].contains(2);
           check if [2019-12-04T09:46:41+00:00, 2020-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00);
           check if [false, true].contains(true);
           check if ["abc", "def"].contains("abc");
           check if [hex:12ab, hex:34de].contains(hex:34de);
           check if [#hello, #world].contains(#hello);
        |]
      getBlocks <$> result @?= Right []
  ]
