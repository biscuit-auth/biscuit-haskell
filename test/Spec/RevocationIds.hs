{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Spec.RevocationIds
  ( specs
  ) where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as ByteString
import qualified Data.ByteString.Base16 as Hex
import qualified Data.List.NonEmpty     as NE
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Token     (BlockWithRevocationIds (..),
                                         getRevocationIds)

readFromFile :: FilePath -> IO Biscuit
readFromFile path = do
  result <- parse <$> ByteString.readFile ("test/samples/" <> path)
  case result of
    Left x  -> fail $ show x
    Right b -> pure b

getHex :: Biscuit -> IO [ByteString]
getHex b = do
  let gi BlockWithRevocationIds{..} =
         Hex.encode genericRevocationId
  rids <- getRevocationIds b
  pure . NE.toList $ gi <$> rids

specs :: TestTree
specs = testGroup "Revocation ids"
  [ token1
  , token16
  ]

token1 :: TestTree
token1 = testCase "Token 1" $ do
  b <- readFromFile "test1_basic.bc"
  rids <- getHex b
  rids @?=
    [ "596a24631a8eeec5cbc0d84fc6c22fec1a524c7367bc8926827201ddd218f4bb"
    , "dec4e0a7f817fe6c5964a18e9f0eae5564c12531b05dc4525f553570519baa87"
    ]

token16 :: TestTree
token16 = testCase "Token 16" $ do
  b <- readFromFile "test16_caveat_head_name.bc"
  rids <- getHex b
  rids @?=
    [ "8f03890eeaa997cd03da71115168e41425b2be82731026225b0c5b87163e4d8e"
    , "94fff36a9fa4d4149ab1488bf4aa84ed0bab0075cc7d051270367fb9c9688795"
    ]
