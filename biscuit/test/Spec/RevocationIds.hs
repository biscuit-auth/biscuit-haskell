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
    [ "bd6e89a2b700700cc68e644298685b1283deee82cc119417d03391a652cfa2bd55968f8e6039c48c39daa6a5efe984eb56733e9eb3289d9fb4c310b95c0a3701"
    , "588f783d07f5bc0f145c452776494dcbbfed460484e7c06bba82b0f4edfbe2ecac9e97efc420a4344361544a21c6fa1f95dd0aeb4b161c6fbd06b839ffedd80a"
    ]

token16 :: TestTree
token16 = testCase "Token 16" $ do
  b <- readFromFile "test16_caveat_head_name.bc"
  let rids = getHex b
  rids @?=
    [ "75a758d48783b23b4337b71c3567fb1d5293d5538d74cf3a4f1bfe306a0f79f393f2e7e9bd48ca48ccb587deca870b71df82f7decf8ed663e801eb4ee7080804"
    , "177092ffbb60e4e44ea5c7d07415782c018a28a2765317ae3e14526ca8fbb0f55a60b264c60269ac277a48a868f27774d10cd46cbe77380dad9e73c82c49eb00"
    ]
