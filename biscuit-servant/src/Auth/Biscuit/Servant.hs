{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Auth.Biscuit.Servant
  ( authHandler
  , RequireBiscuit
  , checkBiscuit
  , genBiscuitCtx
  , WithVerifier (..)
  , withVerifier
  , noVerifier
  , withFallbackVerifier
  , withPriorityVerifier
  , handleBiscuit
  ) where

import           Auth.Biscuit                     (Biscuit, PublicKey, Verifier,
                                                   checkBiscuitSignature,
                                                   parseB64, verifyBiscuit)
import           Control.Monad.Except             (MonadError, throwError)
import           Control.Monad.IO.Class           (MonadIO, liftIO)
import           Control.Monad.Reader             (ReaderT, lift, runReaderT)
import           Data.Bifunctor                   (first)
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Char8            as C8
import qualified Data.ByteString.Lazy             as LBS
import           Network.Wai
import           Servant                          (AuthProtect)
import           Servant.Server
import           Servant.Server.Experimental.Auth

type RequireBiscuit = AuthProtect "biscuit"
type instance AuthServerData RequireBiscuit = CheckedBiscuit

data CheckedBiscuit = CheckedBiscuit PublicKey Biscuit

data WithVerifier m a
  = WithVerifier
  { handler_  :: ReaderT Biscuit m a
  , verifier_ :: Verifier
  }

withFallbackVerifier :: Verifier
                     -> WithVerifier m a
                     -> WithVerifier m a
withFallbackVerifier newV h@WithVerifier{verifier_} =
  h { verifier_ = verifier_ <> newV }

withPriorityVerifier :: Verifier
                     -> WithVerifier m a
                     -> WithVerifier m a
withPriorityVerifier newV h@WithVerifier{verifier_} =
  h { verifier_ = newV <> verifier_ }

withVerifier :: Monad m => Verifier -> m a -> WithVerifier m a
withVerifier verifier_ handler =
  WithVerifier
    { handler_ = lift handler
    , verifier_
    }

noVerifier :: Monad m => m a -> WithVerifier m a
noVerifier = withVerifier mempty

extractBiscuit :: Request -> Either String Biscuit
extractBiscuit req = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders req
  b64Token   <- note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader
  first (const "Not a B64-encoded biscuit") $ parseB64 b64Token

authHandler :: PublicKey -> AuthHandler Request CheckedBiscuit
authHandler publicKey = mkAuthHandler handler
  where
    authError s = err401 { errBody = LBS.fromStrict (C8.pack s) }
    orError = either (throwError . authError) pure
    handler req = do
      biscuit <- orError $ extractBiscuit req
      result  <- liftIO $ checkBiscuitSignature biscuit publicKey
      case result of
        False -> throwError $ authError "Invalid signature"
        True  -> pure $ CheckedBiscuit publicKey biscuit

genBiscuitCtx :: PublicKey -> Context '[AuthHandler Request CheckedBiscuit]
genBiscuitCtx pk = authHandler pk :. EmptyContext

checkBiscuit :: (MonadIO m, MonadError ServerError m)
             => CheckedBiscuit
             -> Verifier
             -> m a
             -> m a
checkBiscuit (CheckedBiscuit pk b) v h = do
  res <- liftIO $ verifyBiscuit b v pk
  case res of
    Left e  -> do liftIO $ print e
                  throwError $ err401 { errBody = "Biscuit failed checks" }
    Right _ -> h

handleBiscuit :: (MonadIO m, MonadError ServerError m)
              => CheckedBiscuit
              -> WithVerifier m a
              -> m a
handleBiscuit cb@(CheckedBiscuit _ b) WithVerifier{verifier_, handler_} =
  let h = runReaderT handler_ b
  in checkBiscuit cb verifier_ h

