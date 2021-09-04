{-# LANGUAGE OverloadedStrings #-}
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
import           Auth.Biscuit.Token2    (getRevocationIds)

pk :: PublicKey
pk = maybe undefined id $ parsePublicKeyHex "acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

readFromFile :: FilePath -> IO Biscuit
readFromFile path = do
  result <- parse pk <$> ByteString.readFile ("test/samples/v2/" <> path)
  case result of
    Left x  -> fail $ show x
    Right b -> pure b

getHex :: Biscuit -> [ByteString]
getHex = NE.toList . fmap Hex.encode . getRevocationIds

specs :: TestTree
specs = testGroup "Revocation ids"
  [ token1
  , token16
  ]

token1 :: TestTree
token1 = testCase "Token 1" $ do
  b <- readFromFile "test1_basic.bc"
  let rids = getHex b
  rids @?=
    [ "2d41aa8d0131f0a9f171ae849f99f78461157101001752852e1731281ad460b3"
    , "601083ff09e19882d762976dbb9bc98851439052e8c1bf3da1f32718a5a57eed"
    ]

token16 :: TestTree
token16 = testCase "Token 16" $ do
  b <- readFromFile "test16_caveat_head_name.bc"
  let rids = getHex b
  rids @?=
    [ "4a366515e159a7577166d8158bdca3c0bb39cbabb4988824ad0c9aab5d3ea402"
    , "2e8c19fefac5e54b7a8e21bb40eaf8aac70909e48f22c388ebb8cc742065d1dc"
    ]
