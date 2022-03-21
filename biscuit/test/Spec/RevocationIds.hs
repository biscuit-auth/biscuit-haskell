{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
module Spec.RevocationIds
  ( specs
  ) where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as ByteString
import qualified Data.ByteString.Base16 as Hex
import           Data.Functor           (void)
import           Data.List              (intersect)
import qualified Data.List.NonEmpty     as NE
import           Data.Maybe             (fromJust, mapMaybe)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Auth.Biscuit
import           Auth.Biscuit.Token     (getRevocationIds)

pk :: PublicKey
pk = fromJust $ parsePublicKeyHex "acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

readFromFile :: FilePath -> IO (Biscuit OpenOrSealed Verified)
readFromFile path = do
  result <- parse pk <$> ByteString.readFile ("test/samples/v2/" <> path)
  case result of
    Left x  -> fail $ show x
    Right b -> pure b

readFromFileCheckRevocation :: [ByteString]
                            -> FilePath
                            -> IO (Either ParseError (Biscuit OpenOrSealed Verified))
readFromFileCheckRevocation revokedIds path =
  let parser = parseWith ParserConfig { encoding = RawBytes
                                      , getPublicKey = const pk
                                      , isRevoked = fromRevocationList revokedIds
                                      }
   in parser =<< ByteString.readFile ("test/samples/v2/" <> path)

getHex :: Biscuit OpenOrSealed Verified -> [ByteString]
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
    [ "1d5f4e65ee45896f32708462af0e82c18ca953cd2e87e340c8a5c2e4e82a45639b9853ee92442273cdebde3c0f3692597d31d116e53593c813726946cdca4205"
    , "d4a96909b2d51a25b65079bb1e91dff8047a8754da8827123ae5bfc28b121afd9cca1acb266a3162c0d1d0371ee1b9011f6bfc278cafa7dae0dbe03848bc7f03"
    ]

token16 :: TestTree
token16 = testCase "Token 16" $ do
  b <- readFromFile "test16_caveat_head_name.bc"
  let rids = getHex b
  rids @?=
    [ "efd90e4a128ef2cbedf66c63331c151517f4b79320771902875d67ee4b18a55a9c22e7593eaf76fc4705f3ed46c1f847fbe3f042e05077129f9298dbdca1a10b"
    , "669e300264a304194dbb3945ceb37d5de862ad18e0dd25c4d8bd8426dc85fcab18f83a180daae0d044959198faffed3adee7a45eebe9b9e1c14a77292118dc0a"
    ]

parseTimeCheck :: TestTree
parseTimeCheck = testCase "Parse time revocation check" $ do
  let revokedIds :: [ByteString]
      revokedIds = mapMaybe fromHex [ "efd90e4a128ef2cbedf66c63331c151517f4b79320771902875d67ee4b18a55a9c22e7593eaf76fc4705f3ed46c1f847fbe3f042e05077129f9298dbdca1a10b" ]
  res1 <- readFromFileCheckRevocation revokedIds "test16_caveat_head_name.bc"
  res1 @?= Left RevokedBiscuit
  res2 <- void <$> readFromFileCheckRevocation revokedIds "test1_basic.bc"
  res2 @?= Right ()
