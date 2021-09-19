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
import           Data.Time          (UTCTime, addUTCTime, getCurrentTime)
import           Test.Hspec

import           AppWithVerifier    (app, call1, call2, call3)
import           ClientHelpers      (runC, withApp)

main :: IO ()
main = do
  let appPk = toPublic appSecretKey
  later   <- addUTCTime (60*5) <$> getCurrentTime
  earlier <- addUTCTime (-60) <$> getCurrentTime
  adminB <- toText <$> mkAdminBiscuit appSecretKey
  anonB  <- toText <$> mkAnonBiscuit appSecretKey
  e1     <- toText <$> mkE1Biscuit appSecretKey
  e21    <- toText <$> mkE2Biscuit 1 appSecretKey
  e22    <- toText <$> mkE2Biscuit 2 appSecretKey
  ttld   <- toText <$> (addTtl later =<< mkAdminBiscuit appSecretKey)
  expd   <- toText <$> (addTtl earlier =<< mkAdminBiscuit appSecretKey)
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
        it "Effectful verification should work as expected" $ \port -> do
          runC port (call1 ttld) `shouldReturn` Right 1
          runC port (call1 expd) `shouldReturn` Left (Just "Biscuit failed checks")

appSecretKey :: SecretKey
appSecretKey = fromJust . parseSecretKeyHex $ "c2b7507af4f849fd028d0f7e90b04a4e74d9727b358fca18b65beffd86c47209"

toText :: BiscuitProof p => Biscuit p Checked -> Text
toText = decodeUtf8 . serializeB64

mkAdminBiscuit :: SecretKey -> IO (Biscuit Open Checked)
mkAdminBiscuit sk = mkBiscuit sk [block|right("admin");|]

mkAnonBiscuit :: SecretKey -> IO (Biscuit Open Checked)
mkAnonBiscuit sk = mkBiscuit sk [block|right("anon");|]

mkE1Biscuit :: SecretKey -> IO (Biscuit Open Checked)
mkE1Biscuit sk = mkBiscuit sk [block|right("one");|]

mkE2Biscuit :: Int -> SecretKey -> IO (Biscuit Open Checked)
mkE2Biscuit v sk = mkBiscuit sk [block|right("two", ${v});|]

addTtl :: UTCTime -> Biscuit Open Checked -> IO (Biscuit Open Checked)
addTtl expiration =
  addBlock [block|check if time($now), $now < ${expiration};|]
