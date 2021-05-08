{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Example where

import           Data.ByteString (ByteString)
import           Data.Foldable   (fold)
import           Data.Functor    (($>))
import           Data.Time       (getCurrentTime)

import           Biscuit
import           Datalog.Parser  (check, fact)

privateKey :: PrivateKey
privateKey = either (error . show) id $ parsePrivateKeyB64 "todo"

publicKey :: PublicKey
publicKey = either (error . show) id $ parsePublicKeyB64 "todo"

creation :: IO ByteString
creation = do
  let authority = fold
        [ blockFact [fact|resource(#authority,"file1")|]
        ]
  biscuit <- mkBiscuit privateKey authority
  let block1 = fold
        [ blockCheck [check|check if current_time(#ambient, $time), $time < 2021-05-08T00:00:00Z|]
        ]
  newBiscuit <- addBlock block1 biscuit
  pure $ serializeB64 newBiscuit

verification :: ByteString -> IO Bool
verification serialized = do
  now <- getCurrentTime
  biscuit <- either (fail . show) pure $ parseB64 serialized
  let verifier' = fold
        [ verifierFact [fact|current_time(#ambient, ${now})|]
        ]
  result <- verifyBiscuit biscuit verifier' publicKey
  case result of
    Left e   -> print e $> False
    Right () -> pure True
