{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TypeApplications  #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE TypeOperators     #-}
module Main (main) where

import           Auth.Biscuit
import           Data.Maybe         (fromJust)
import           Data.Text          (Text)
import           Data.Text.Encoding (decodeUtf8)
import           Test.Hspec

import           AppWithVerifier    (app, call1, call2, call3)
import           ClientHelpers      (runC, withApp)

main :: IO ()
main = do
  keypair <- fromPrivateKey appPrivateKey
  let appPk = publicKey keypair
  adminB <- toText <$> mkAdminBiscuit keypair
  anonB  <- toText <$> mkAnonBiscuit keypair
  e1     <- toText <$> mkE1Biscuit keypair
  e21    <- toText <$> mkE2Biscuit 1 keypair
  e22    <- toText <$> mkE2Biscuit 2 keypair
  print adminB
  hspec $
    around (withApp $ app appPk) $
      describe "Biscuit-protected servant app" $ do
        it "Priority rules should apply everywhere" $ \port -> do
          runC port (call1 adminB) `shouldReturn` Right 1
          runC port (call2 adminB 1) `shouldReturn` Right 2
          runC port (call3 adminB) `shouldReturn` Right 3
        it "Fallback rules should only apply after inner rules" $ \port -> do
          runC port (call1 anonB) `shouldReturn` Right 1
          runC port (call2 anonB 1) `shouldReturn` Right 2
          runC port (call3 anonB) `shouldReturn` Left (Just "Biscuit failed checks")
        it "Endpoint rules should be matched after priority rules and before fallback rules" $ \port -> do
          runC port (call1 e1) `shouldReturn` Right 1
          runC port (call2 e21 1) `shouldReturn` Right 2
          runC port (call2 e22 1) `shouldReturn` Left (Just "Biscuit failed checks")
          runC port (call3 anonB) `shouldReturn` Left (Just "Biscuit failed checks")

appPrivateKey :: PrivateKey
appPrivateKey = fromJust . parsePrivateKeyHex $ "c2b7507af4f849fd028d0f7e90b04a4e74d9727b358fca18b65beffd86c47209"

toText :: Biscuit -> Text
toText = decodeUtf8 . serializeHex

mkAdminBiscuit :: Keypair -> IO Biscuit
mkAdminBiscuit kp = mkBiscuit kp [block|right(#authority, #admin);|]

mkAnonBiscuit :: Keypair -> IO Biscuit
mkAnonBiscuit kp = mkBiscuit kp [block|right(#authority, #anon);|]

mkE1Biscuit :: Keypair -> IO Biscuit
mkE1Biscuit kp = mkBiscuit kp [block|right(#authority, #one);|]

mkE2Biscuit :: Int -> Keypair -> IO Biscuit
mkE2Biscuit v kp = mkBiscuit kp [block|right(#authority, #two, ${v});|]
