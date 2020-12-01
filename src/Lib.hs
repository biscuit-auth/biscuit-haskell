{-# LANGUAGE OverloadedStrings #-}
module Lib
    ( someFunc
    ) where

import           Biscuit
import           Control.Monad          ((<=<))
import           Control.Monad          (when)
import           Data.Bifoldable        (bitraverse_)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.ByteString.Base64
import           Data.ByteString.Short
import           Data.Foldable          (traverse_)
import           System.Random

import qualified Inline                 as I

getSeed :: IO ByteString
getSeed = do
  BS.pack <$> traverse (const randomIO) [0..31]

printKeyPairAddr = (putStrLn "KeyPair" >>) . flip withKeyPair print
printPublicKeyAddr = (putStrLn "PublicKey" >>) . flip withPublicKey print
printBiscuitBuilderAddr = (putStrLn "Builder" >>) . flip withBiscuitBuilder print
printBiscuitAddr = (putStrLn "Biscuit" >>) . flip withBiscuit print
printVerifierAddr = (putStrLn "Verifier" >>) . flip withVerifier print

someFunc :: IO ()
someFunc = c2hs

c2hs :: IO ()
c2hs = do
  kp      <- keyPairNew =<< getSeed
  print . encodeBase64 =<< serializeKeyPair kp
  kp <- maybe undefined id <$> deserializeKeyPair (decodeBase64Lenient "3W/koXfmhyHtiNAi+Y9V5EI9/fi8OrGobD5OISpf3A8=")
  printKeyPairAddr kp
  pub     <- keyPairPublic kp
  builder <- biscuitBuilder kp
  bisc' <- biscuitFrom $ decodeBase64Lenient "CjwIABIEZWZnaBIEeW9sbxICYWEaCgoICAQSBAgAEAcqHAoaCggICBIECAAQCRIOCAQSBAgAEAASBAgAEAcaINBXDBnzFZJHwJUlx40i9KYQbJSo5it3lT06hblNbx1DIkQKIBzjq7s4HRdA8v7fILHd2yJ5pYSTKh3af4z1wc1LdegZEiDE9WWYDcGS877S+DnDqezkQHCbsDr5Nkvz+upxZdrOBw=="
  printBiscuitAddr bisc'
  res <- biscuitBuilderAddAuthorityFact builder "right(#efgh)"
  print res
  when (not res) $ do
    print "fact error"
    print =<< getErrorMessage
  res' <- biscuitBuilderAddAuthorityCaveat builder "*yolo(#aa) <- right(#authority,#efgh)"
  print res'
  when (not res') $ do
    print "caveat error"
    print =<< getErrorMessage
  bisc    <-  biscuitBuilderBuild builder =<< getSeed
  printBiscuitAddr bisc
  print =<< encodeBase64 <$> serialize bisc
  verif <- biscuitVerify bisc pub
  printVerifierAddr verif
  printBiscuitBuilderAddr builder
  res'' <- verifierAddCaveat verif "*right(#abcd) <- right(#authority,#efgh)"
  print res''
  putStrLn =<< verifierPrint verif
  vRes <- verifierVerify verif
  print vRes

b64p :: ByteString -> IO ()
b64p = print . encodeBase64

inline :: IO ()
inline = do
  (bitraverse_ b64p b64p) =<< I.genKp =<< getSeed
