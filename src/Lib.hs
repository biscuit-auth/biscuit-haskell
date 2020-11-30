{-# LANGUAGE OverloadedStrings #-}
module Lib
    ( someFunc
    ) where

import           Biscuit
import           Control.Monad          ((<=<))
import           Control.Monad          (when)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.ByteString.Base64
import           Data.ByteString.Short
import           Data.Foldable          (traverse_)
import           System.Random

getSeed :: IO ByteString
getSeed = do
  BS.pack <$> traverse (const randomIO) [0..31]

printKeyPairAddr = flip withKeyPair print
printPublicKeyAddr = flip withPublicKey print
printBiscuitBuilderAddr = flip withBiscuitBuilder print
printBiscuitAddr = flip withBiscuit print

someFunc :: IO ()
someFunc = do
  -- kp      <- keyPairNew =<< getSeed
  -- print . encodeBase64 =<< serializeKeyPair kp
  kp <- maybe undefined id <$> deserializeKeyPair (decodeBase64Lenient "3W/koXfmhyHtiNAi+Y9V5EI9/fi8OrGobD5OISpf3A8=")
  printKeyPairAddr kp
  -- pub     <- keyPairPublic kp
  builder <- biscuitBuilder kp
  bisc    <-  biscuitBuilderBuild builder =<< getSeed
  printBiscuitAddr bisc
  print =<< encodeBase64 <$> serialize bisc
  {-
  verif <- biscuitVerify bisc pub
   bisc <- biscuitFrom $ decodeBase64Lenient "CjwIABIEZWZnaBIEeW9sbxICYWEaCgoICAQSBAgAEAcqHAoaCggICBIECAAQCRIOCAQSBAgAEAASBAgAEAcaINBXDBnzFZJHwJUlx40i9KYQbJSo5it3lT06hblNbx1DIkQKIBzjq7s4HRdA8v7fILHd2yJ5pYSTKh3af4z1wc1LdegZEiDE9WWYDcGS877S+DnDqezkQHCbsDr5Nkvz+upxZdrOBw==" {-
  res <- biscuitBuilderAddAuthorityFact builder "right(#efgh)"
  when (not res) $ do
    print "fact error"
    print =<< getErrorMessage
  printBiscuitBuilderAddr builder
  res' <- biscuitBuilderAddAuthorityCaveat builder "*yolo(#aa) <- right(#authority,#efgh)"
  when (not res') $ do
    print "caveat error"
    print =<< getErrorMessage
  res'' <- verifierAddCaveat verif "*right(#abcd) <- right(#authority,#efgh)"
  print res''
  -}
  putStrLn =<< verifierPrint verif
  vRes <- verifierVerify verif
  print vRes
  -}
