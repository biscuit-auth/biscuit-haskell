{-# LANGUAGE OverloadedStrings #-}
module Lib
    ( someFunc
    ) where

import           Control.Monad          (when, (<=<))
import           Data.Bifoldable        (bitraverse_)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.ByteString.Base64
import           Data.ByteString.Short
import           Data.Foldable          (traverse_)
import           System.Random

import           Biscuit.Internal
import qualified Inline                 as I

import qualified Biscuit                as B

someFunc :: IO ()
someFunc = nice

nice :: IO ()
nice = do
 let orFail = either (fail . show) pure
 keyPair   <- B.randomKeyPair
 let public = B.getPublic keyPair
 let authority =
       B.Block
         { B._facts = ["userId(#authority,123)"]
         , B._rules = []
         -- the token is only valid for read operations
         -- the token is only valid if the current user id has read rights on the current resource
         , B._caveats = [ "*readOnlyAccess($resourceId,$userId) <- operation(#ambient, #read), \
                                                                \resource(#ambient, $resourceId), \
                                                                \userId(#authority,$userId) , \
                                                                \right(#authority, $userid, $resourceId, #read)"
                        ]
         , B._context = Nothing
         }
 biscuit <- orFail =<< B.mkBiscuit keyPair authority =<< B.randomSeed
 print =<< encodeBase64 <$> B.serializeBiscuit biscuit
 let verifier = B.Verifier
                 [ "operation(#ambient, #read)" -- this is a read operation
                 , "resource(#ambient, 456)"    -- the current resource id is 456
                 , "right(#authority, 123, 456, #read)" -- the user 123 has read access to resource 456
                 , "date(#ambient,2020-12-01T00:00:00Z)" -- the current date
                 ] [] []
 bkp <- B.randomKeyPair
 result <- B.verifyBiscuit biscuit verifier public
 case result of
   Right () -> putStrLn "The token is valid"
   Left e   -> putStrLn $ "There was an error checking the token " <> show e
 let ttlBlock = B.Block [] [] [ "*ttl($date) <- date(#ambient,$date) @ $date < 2020-12-05T23:00:00Z"] Nothing
 withTtl <- orFail =<< B.attenuateBiscuit biscuit ttlBlock bkp =<< B.randomSeed
 result' <- B.verifyBiscuit withTtl verifier public
 case result' of
   Right () -> putStrLn "The token is valid"
   Left e   -> putStrLn $ "There was an error checking the token " <> show e

getSeed :: IO ByteString
getSeed =
  BS.pack <$> traverse (const randomIO) [0..31]

printKeyPairAddr = (putStrLn "KeyPair" >>) . flip withKeyPair print
printPublicKeyAddr = (putStrLn "PublicKey" >>) . flip withPublicKey print
printBiscuitBuilderAddr = (putStrLn "Builder" >>) . flip withBiscuitBuilder print
printBiscuitAddr = (putStrLn "Biscuit" >>) . flip withBiscuit print
printVerifierAddr = (putStrLn "Verifier" >>) . flip withVerifier print

c2hs :: IO ()
c2hs = do
  kp      <- keyPairNew =<< getSeed
  print . encodeBase64 =<< serializeKeyPair kp
  kp <- maybe undefined id <$> deserializeKeyPair (decodeBase64Lenient "3W/koXfmhyHtiNAi+Y9V5EI9/fi8OrGobD5OISpf3A8=")
  printKeyPairAddr kp
  pub     <- keyPairPublic kp
  builder <- biscuitBuilder kp
  printBiscuitBuilderAddr builder
  bisc' <- biscuitFrom $ decodeBase64Lenient "CjwIABIEZWZnaBIEeW9sbxICYWEaCgoICAQSBAgAEAcqHAoaCggICBIECAAQCRIOCAQSBAgAEAASBAgAEAcaINBXDBnzFZJHwJUlx40i9KYQbJSo5it3lT06hblNbx1DIkQKIBzjq7s4HRdA8v7fILHd2yJ5pYSTKh3af4z1wc1LdegZEiDE9WWYDcGS877S+DnDqezkQHCbsDr5Nkvz+upxZdrOBw=="
  printBiscuitAddr bisc'
  putStrLn =<< biscuitPrint bisc'
  res <- biscuitBuilderAddAuthorityFact builder "prout*right(#efgh,#authority)yolo"
  print res
  when (not res) $ do
    print "fact error"
    print =<< errorKind
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
  res'' <- verifierAddCaveat verif "*right(#abcd) <- right(#authority,#efgh)"
  print res''
  putStrLn =<< verifierPrint verif
  vRes <- verifierVerify verif
  print vRes

b64p :: ByteString -> IO ()
b64p = print . encodeBase64

inline :: IO ()
inline =
  bitraverse_ b64p b64p =<< I.genKp =<< getSeed
