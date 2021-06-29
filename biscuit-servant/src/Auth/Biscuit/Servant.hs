{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Auth.Biscuit.Servant
  (
  -- Servant Auth Handler
    RequireBiscuit
  , CheckedBiscuit (..)
  , authHandler
  , genBiscuitCtx
  , checkBiscuit
  , checkBiscuitM
  -- Decorate regular handlers with composable verifiers
  , WithVerifier (..)
  , handleBiscuit
  , withVerifier
  , withVerifier_
  , withVerifierM
  , withVerifierM_
  , noVerifier
  , noVerifier_
  , withFallbackVerifier
  , withPriorityVerifier
  , withFallbackVerifierM
  , withPriorityVerifierM
  ) where

import           Auth.Biscuit                     (Biscuit, PublicKey, Verifier,
                                                   checkBiscuitSignature,
                                                   parseB64, verifyBiscuit)
import           Control.Applicative              (liftA2)
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

-- | Type used to protect and API tree, requiring a biscuit token
-- to be attached to requests. The associated auth handler will
-- only check the biscuit signature. Checking the datalog part
-- usually requires endpoint-specific information, and has to
-- be performed separately with either 'checkBiscuit' (for simple
-- use-cases) or 'handleBiscuit' (for more complex use-cases).
type RequireBiscuit = AuthProtect "biscuit"
type instance AuthServerData RequireBiscuit = CheckedBiscuit

-- | A biscuit which signature has already been verified.
-- Since the biscuit lib checks the signature while verifying the datalog
-- part, the public key is needed. 'CheckedBiscuit' carries the public key
-- used for verifying the signature so that the datalog verification part
-- can use it.
data CheckedBiscuit = CheckedBiscuit PublicKey Biscuit

-- | Wrapper for a servant handler, equipped with a biscuit 'Verifier'
-- that will be used to authorize the request. If the authorization
-- succeeds, the handler is ran.
-- The handler itself is given access to the verified biscuit through
-- a 'ReaderT Biscuit'.
data WithVerifier m a
  = WithVerifier
  { handler_  :: ReaderT Biscuit m a
  -- ^ the wrapped handler, in a 'ReaderT' to give easy access to the biscuit
  , verifier_ :: m Verifier
  -- ^ the 'Verifier' associated to the handler
  }

-- | Combines the provided 'Verifier' to the 'Verifier' attached to the wrapped
-- handler. _facts_, _rules_ and _checked_ are unordered, but _policies_ have a
-- specific order. 'withFallbackVerifier' puts the provided policies at the _bottom_
-- of the list (ie as _fallback_ policies).
-- If you want the policies to be tried before the ones of the wrapped handler, you
-- can use 'withPriorityVerifier'.
withFallbackVerifier :: Functor m
                     => Verifier
                     -> WithVerifier m a
                     -> WithVerifier m a
withFallbackVerifier newV h@WithVerifier{verifier_} =
  h { verifier_ = (<> newV) <$> verifier_ }

-- todo
withFallbackVerifierM :: Applicative m
                      => m Verifier
                      -> WithVerifier m a
                      -> WithVerifier m a
withFallbackVerifierM newV h@WithVerifier{verifier_} =
  h { verifier_ = liftA2 (<>) verifier_ newV }

-- | Combines the provided 'Verifier' to the 'Verifier' attached to the wrapped
-- handler. _facts_, _rules_ and _checked_ are unordered, but _policies_ have a
-- specific order. 'withFallbackVerifier' puts the provided policies at the _top_
-- of the list (ie as _priority_ policies).
-- If you want the policies to be tried after the ones of the wrapped handler, you
-- can use 'withFallbackVerifier'.
withPriorityVerifier :: Functor m
                     => Verifier
                     -> WithVerifier m a
                     -> WithVerifier m a
withPriorityVerifier newV h@WithVerifier{verifier_} =
     h { verifier_ = (newV <>) <$> verifier_ }

-- todo
withPriorityVerifierM :: Applicative m
                      => m Verifier
                      -> WithVerifier m a
                      -> WithVerifier m a
withPriorityVerifierM newV h@WithVerifier{verifier_} =
     h { verifier_ = liftA2 (<>) newV verifier_ }

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler has
-- to be a 'ReaderT Biscuit' to be able to access the token. If you don't need
-- to access the token from the handler block, you can use 'withVerifier_'
-- instead.
withVerifier :: Applicative m => Verifier -> ReaderT Biscuit m a -> WithVerifier m a
withVerifier v handler_ =
  WithVerifier
    { handler_
    , verifier_ = pure v
    }

-- todo
withVerifierM :: m Verifier -> ReaderT Biscuit m a -> WithVerifier m a
withVerifierM verifier_ handler_ =
  WithVerifier
    { handler_
    , verifier_
    }

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler can be
-- any monad, but won't be able to access the 'Biscuit'. If you want to read the
-- biscuit token from the handler block, you can use 'withVerifier' instead.
withVerifier_ :: Monad m => Verifier -> m a -> WithVerifier m a
withVerifier_ v = withVerifier v . lift

-- todo
withVerifierM_ :: Monad m => m Verifier -> m a -> WithVerifier m a
withVerifierM_ v = withVerifierM v . lift

-- | Wraps an existing handler block, attaching an empty 'Verifier'. The handler has
-- to be a 'ReaderT Biscuit' to be able to access the token. If you don't need
-- to access the token from the handler block, you can use 'noVerifier_'
-- instead.
--
-- This function can be used together with 'withFallbackVerifier' or 'withPriorityVerifier'
-- to apply policies on several handlers at the same time (with 'hoistServer' for instance).
noVerifier :: Applicative m => ReaderT Biscuit m a -> WithVerifier m a
noVerifier = withVerifier mempty

-- | Wraps an existing handler block, attaching an empty 'Verifier'. The handler can be
-- any monad, but won't be able to access the 'Biscuit'. If you want to read the
-- biscuit token from the handler block, you can use 'noVerifier' instead.
--
-- This function can be used together with 'withFallbackVerifier' or 'withPriorityVerifier'
-- to apply policies on several handlers at the same time (with 'hoistServer' for instance).
noVerifier_ :: Monad m => m a -> WithVerifier m a
noVerifier_ = noVerifier . lift

-- | Extracts a biscuit from an http request, assuming:
--
-- - the biscuit is b64-encoded
-- - prefixed with the `Bearer ` string
-- - in the `Authorization` header
extractBiscuit :: Request -> Either String Biscuit
extractBiscuit req = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders req
  b64Token   <- note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader
  first (const "Not a B64-encoded biscuit") $ parseB64 b64Token

-- | Servant authorization handler. This extracts the biscuit from the request,
-- checks its signature (but not the datalog part) and returns a 'CheckedBiscuit'
-- upon success.
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

-- | Helper function generating a servant context containing the authorization
-- handler.
genBiscuitCtx :: PublicKey -> Context '[AuthHandler Request CheckedBiscuit]
genBiscuitCtx pk = authHandler pk :. EmptyContext

-- | Given a 'CheckedBiscuit' (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Verifier').
--
-- If you need to perform effects in the verification phase (eg to get the current time,
-- or if you need to issue a DB query to get context), you can use 'checkBiscuitM' instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to
-- blanket apply verifiers on whole API trees, you can consider using 'withVerifier'
-- (on endpoints), 'withFallbackVerifier' and 'withPriorityVerifier' (on API sub-trees)
-- and 'handleBiscuit' (on the whole API).
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

-- | Given a 'CheckedBiscuit' (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Verifier', which can be effectful).
--
-- If you don't need to run any effects in the verifying phase, you can use 'checkBiscuit'
-- instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to blanket apply
-- verifiers on whole API trees, you can consider using 'withVerifier' (on endpoints),
-- 'withFallbackVerifier' and 'withPriorityVerifier' (on API sub-trees) and 'handleBiscuit'
-- (on the whole API).
checkBiscuitM :: (MonadIO m, MonadError ServerError m)
              => CheckedBiscuit
              -> m Verifier
              -> m a
              -> m a
checkBiscuitM (CheckedBiscuit pk b) mv h = do
  v   <- mv
  res <- liftIO $ verifyBiscuit b v pk
  case res of
    Left e  -> do liftIO $ print e
                  throwError $ err401 { errBody = "Biscuit failed checks" }
    Right _ -> h

-- | Given a handler wrapped in a 'WithVerifier', use the attached 'Verifier' to
-- verify the provided biscuit and return an error as needed.
--
-- For simpler use cases, consider using 'checkBiscuit' instead, which works on regular
-- servant handlers.
handleBiscuit :: (MonadIO m, MonadError ServerError m)
              => CheckedBiscuit
              -> WithVerifier m a
              -> m a
handleBiscuit cb@(CheckedBiscuit _ b) WithVerifier{verifier_, handler_} =
  let h = runReaderT handler_ b
  in checkBiscuitM cb verifier_ h

