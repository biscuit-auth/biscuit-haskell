{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TypeApplications  #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE TypeOperators     #-}
module AppWithVerifier where

import           Auth.Biscuit
import           Auth.Biscuit.Servant
import           Control.Monad.IO.Class (liftIO)
import           Data.Text              (Text)
import           Data.Time              (getCurrentTime)
import           Servant
import           Servant.Client

import           ClientHelpers

call1 :: Text -> ClientM Int
call1 b =
  let (e1 :<|> _) = client @API Proxy (protect b)
   in e1

call2 :: Text -> Int -> ClientM Int
call2 b =
  let (_ :<|> e2 :<|> _) = client @API Proxy (protect b)
   in e2

call3 :: Text -> ClientM Int
call3 b =
  let (_ :<|> _ :<|> e3) = client @API Proxy (protect b)
   in e3

type H = WithVerifier Handler
type API = RequireBiscuit :> ProtectedAPI
type ProtectedAPI =
       "endpoint1" :> Get '[JSON] Int
  :<|> "endpoint2" :> Capture "int" Int :> Get '[JSON] Int
  :<|> "endpoint3" :> Get '[JSON] Int

app :: PublicKey -> Application
app appPublicKey =
  serveWithContext @API Proxy (genBiscuitCtx appPublicKey) server

server :: Server API
server b =
  let nowFact = do
        now <- liftIO getCurrentTime
        pure [verifier|now(#ambient, ${now});|]
      handleAuth :: WithVerifier Handler x -> Handler x
      handleAuth =
          handleBiscuit b
        . withPriorityVerifierM nowFact
        . withPriorityVerifier [verifier|allow if right(#authority, #admin);|]
        . withFallbackVerifier [verifier|allow if right(#authority, #anon);|]
      handlers = handler1 :<|> handler2 :<|> handler3
   in hoistServer @ProtectedAPI Proxy handleAuth handlers

handler1 :: H Int
handler1 = withVerifier [verifier|allow if right(#authority, #one);|] $ pure 1

handler2 :: Int -> H Int
handler2 v = withVerifier [verifier|allow if right(#authority, #two, ${v});|] $ pure 2

handler3 :: H Int
handler3 = withVerifier [verifier|deny if true;|] $ pure 3
