{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
module Spec.RevocationIds
  ( specs
  ) where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as ByteString
import qualified Data.ByteString.Base16 as Hex
import           Data.Functor           (void)
import qualified Data.List.NonEmpty     as NE
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Token     (getRevocationIds)

pk :: PublicKey
pk = maybe undefined id $ parsePublicKeyHex "acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

readFromFile :: FilePath -> IO (Biscuit OpenOrSealed Checked)
readFromFile path = do
  result <- parse pk <$> ByteString.readFile ("test/samples/v2/" <> path)
  case result of
    Left x  -> fail $ show x
    Right b -> pure b

readFromFileCheckRevocation :: (ByteString -> IO Bool)
                            -> FilePath
                            -> IO (Either ParseError (Biscuit OpenOrSealed Checked))
readFromFileCheckRevocation isRevoked path =
  parseWith isRevoked pk =<< ByteString.readFile ("test/samples/v2/" <> path)

getHex :: Biscuit OpenOrSealed Checked -> [ByteString]
getHex = NE.toList . fmap Hex.encode . getRevocationIds

specs :: TestTree
specs = testGroup "Revocation ids"
  [ testGroup "Computation"
      [ token1
      , token16
      ]
  , parseTimeCheck
  ]

token1 :: TestTree
token1 = testCase "Token 1" $ do
  b <- readFromFile "test1_basic.bc"
  let rids = getHex b
  rids @?=
    [ "9d3e984bd0447eea9f31a56df51ba606160c66102063dd29410a2c85601a2139ce0cd212daf755ed0b8fe1f0e9388a89074b009b7169499e51df83c308e8d20b"
    , "5cade9fd3690b72bf90c29c529cb5b1bb50832554ba525b15c5d3f7c994814af522c5a68d61a950bc5f98d9ff4e3e20ffecef65ddaa2858251768ec999ed8b06"
    ]

token16 :: TestTree
token16 = testCase "Token 16" $ do
  b <- readFromFile "test16_caveat_head_name.bc"
  let rids = getHex b
  rids @?=
    [ "aa8f26e32b6a55fe99decfb0f2c229776cc30360e5b68a5b06e730f1e9a13697f87929592f37b7b58dd00dececd6fa40540a3879f74bd232505f1c419907000c"
    , "02766fa2dbb0bd5a2d4d3fc4e0dd9252ec4dc118fe5bc0eafb67fbce0ddf6a86f4db7ecc0b1da14c210b8dcae53fcfc44565edb32ba18bfc9ca9f97258c4db0d"
    ]

parseTimeCheck :: TestTree
parseTimeCheck = testCase "Parse time revocation check" $ do
  let isRevoked = pure . ((== "02766fa2dbb0bd5a2d4d3fc4e0dd9252ec4dc118fe5bc0eafb67fbce0ddf6a86f4db7ecc0b1da14c210b8dcae53fcfc44565edb32ba18bfc9ca9f97258c4db0d") . Hex.encode)
  res1 <- readFromFileCheckRevocation isRevoked "test16_caveat_head_name.bc"
  res1 @?= Left RevokedBiscuit
  res2 <- void <$> readFromFileCheckRevocation isRevoked "test1_basic.bc"
  res2 @?= Right ()
