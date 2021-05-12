{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Spec.Samples
  ( specs
  ) where

import qualified Data.ByteString  as ByteString
import           Test.Tasty
import           Test.Tasty.HUnit

import           Biscuit          (ParseError (..), parse)
import           Datalog.AST      (Block)
import           Datalog.Parser   (block)
import           Token            (Biscuit (..))

readFromFile :: FilePath -> IO (Either ParseError Biscuit)
readFromFile path =
  parse <$> ByteString.readFile ("test/samples/" <> path)

getAuthority :: Biscuit -> Block
getAuthority = snd . snd . authority

getBlocks :: Biscuit -> [Block]
getBlocks = fmap (snd . snd) . blocks

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
