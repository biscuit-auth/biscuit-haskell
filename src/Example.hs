{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Example where

import           Data.ByteString (ByteString)
import           Data.Functor    (($>))
import           Data.Time       (getCurrentTime)

import           Biscuit
import           Datalog.Parser  (block, verifier)

privateKey' :: PrivateKey
privateKey' = maybe (error "Error parsing private key") id $ parsePrivateKeyHex "todo"

publicKey' :: PublicKey
publicKey' = maybe (error "Error parsing public key") id $ parsePublicKeyHex "todo"

creation :: IO ByteString
creation = do
  let authority = [block|resource(#authority,"file1");|]
  keypair <- fromPrivateKey privateKey'
  biscuit <- mkBiscuit keypair authority
  let block1 = [block|check if current_time(#ambient, $time), $time < 2021-05-08T00:00:00Z;|]
  newBiscuit <- addBlock block1 biscuit
  pure $ serializeB64 newBiscuit

verification :: ByteString -> IO Bool
verification serialized = do
  now <- getCurrentTime
  biscuit <- either (fail . show) pure $ parseB64 serialized
  let verifier' = [verifier|current_time(#ambient, ${now});|]
  result <- verifyBiscuit biscuit verifier' publicKey'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True
