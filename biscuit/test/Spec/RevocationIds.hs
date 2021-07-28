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

getHex :: Biscuit -> IO [(ByteString,ByteString)]
getHex b = do
  let gi BlockWithRevocationIds{..} =
         (Hex.encode genericRevocationId, Hex.encode uniqueRevocationId)
  rids  <- getRevocationIds b
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
    [ ( "596a24631a8eeec5cbc0d84fc6c22fec1a524c7367bc8926827201ddd218f4bb"
      , "0478d85ecc0176ecb7c4609216c10be4456bd288b28d1bc2d9ee6247935e968c"
      )
    , ( "dec4e0a7f817fe6c5964a18e9f0eae5564c12531b05dc4525f553570519baa87"
      , "ac3e75a72e35b936963e77d06a6aee38fc2654084f5a964dd4aaf7b02ae25774"
      )
    ]

token16 :: TestTree
token16 = testCase "Token 16" $ do
  b <- readFromFile "test16_caveat_head_name.bc"
  rids <- getHex b
  rids @?=
    [ ( "8f03890eeaa997cd03da71115168e41425b2be82731026225b0c5b87163e4d8e"
      , "83b0b7f0135609102299bd6db8de46722a2c2fcad6a348e684435ba5e528b564"
      )
    , ( "94fff36a9fa4d4149ab1488bf4aa84ed0bab0075cc7d051270367fb9c9688795"
      , "17b70d10fee614414e46e06f2aea2c3986c33eae4faee76a05a904d09f2a587e"
      )
    ]
