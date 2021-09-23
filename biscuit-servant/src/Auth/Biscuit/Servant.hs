{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Auth.Biscuit.Servant
  (
  -- * Protecting a servant API with biscuits
  -- $presentation

  -- ** Annotating servant API types
  -- $apitypes
    RequireBiscuit
  , authHandler
  , genBiscuitCtx
  -- ** Supplying a verifier for a single endpoint
  -- $singleEndpointVerifier
  , checkBiscuit
  , checkBiscuitM
  -- ** Decorate regular handlers with composable verifiers
  -- $composableVerifiers
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

  , module Biscuit
  ) where

import           Auth.Biscuit                     as Biscuit
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

-- $presentation
--
-- Biscuit are bearer tokens that can be used to protect API endpoints.
-- This package provides utilities to protect servant endpoints with such
-- tokens.
--
-- The token will be extracted from the @Authorization@ header, and must
-- be base64-encoded, prefixed with the @Bearer @ string.

-- $apitypes
--
-- To protect and endpoint (or a whole API tree), you can use 'RequireBiscuit'
-- like so:
--
--
-- > type API = RequireBiscuit :> ProtectedAPI
-- > type ProtectedAPI =
-- >        "endpoint1" :> Get '[JSON] Int
-- >   :<|> "endpoint2" :> Capture "int" Int :> Get '[JSON] Int
-- >   :<|> "endpoint3" :> Get '[JSON] Int
-- >
-- > app :: PublicKey -> Application
-- > app publicKey =
-- >   -- servant needs access to the biscuit /public/
-- >   -- key to be able to check biscuit signatures.
-- >   -- The public key can be read from the environment
-- >   -- and parsed using 'parsePublicKeyHex' for instance.
-- >   serveWithContext
-- >     (Proxy :: Proxy API)
-- >     (genBiscuitCtx publicKey)
-- >     server
-- >
-- > -- server :: Biscuit OpenOrSealed Checked -> Server ProtectedAPI
-- > server :: Server API
-- > server biscuit = … -- this will be detailed later
--
-- This will instruct servant to extract the biscuit from the requests and
-- check its signature. /It will not/, however, run any datalog check (as
-- the checks typically depend on the request contents).
--
-- $singleEndpointVerifier
--
-- The corresponding @Server API@ value will be a @Biscuit OpenOrSealed Checked -> Server ProtectedAPI@.
-- The next step is to provide a 'Verifier' so that the biscuit datalog can be
-- verified. For that, you can use 'checkBiscuit' (or 'checkBiscuitM' for effectful checks).
--
-- > server :: Server API
-- > server biscuit = h1 biscuit
-- >             :<|> h2 biscuit
-- >             :<|> h3 biscuit
-- >
-- > h1 :: Biscuit OpenOrSealed Checked -> Handler Int
-- > h1 biscuit =
-- >   checkBiscuit biscuit
-- >     [verifier|allow if right("one");|]
-- >     -- ^ only allow biscuits granting access to the endpoint tagged "one"
-- >     (pure 1)
-- >
-- > h2 :: Biscuit OpenOrSealed Checked -> Int -> Handler Int
-- > h2 biscuit value =
-- >   let verifier' = do
-- >         now <- liftIO getCurrentTime
-- >         pure [verifier|
-- >                // provide the current time so that TTL checks embedded in
-- >                // the biscuit can decide if it's still valid
-- >                // this show how to run an effectful check with
-- >                // checkBiscuitM (getting the current time is an effect)
-- >                time(${now});
-- >                // only allow biscuits granting access to the endpoint tagged "two"
-- >                // AND for the provided int value. This show how the checks can depend
-- >                // on the http request contents.
-- >                allow if right("two", ${value});
-- >              |]
-- >   checkBiscuitM biscuit verifier
-- >     (pure 2)
-- >
-- > h3 :: Biscuit OpenOrSealed Checked -> Handler Int
-- > h3 biscuit =
-- >   checkBiscuit biscuit
-- >     [verifier|deny if true;|]
-- >     -- ^ reject every biscuit
-- >     (pure 3)
--
-- $composableVerifiers
--
-- 'checkBiscuit' allows you to describe validation rules endpoint by endpoint. If your
-- application has a lot of endpoints with the same policies, it can become tedious to
-- maintain.
--
-- 'biscuit-servant' provides a way to apply verifiers on whole API trees,
-- in a composable way, thanks to 'hoistServer'. 'hoistServer' is a mechanism
-- provided by servant-server that lets apply a transformation function to whole
-- API trees.
--
-- > -- 'withVerifier' wraps a 'Handler' and lets you attach a verifier to a
-- > -- specific endoint. This verifier may be combined with other verifiers
-- > -- attached to the whole API tree
-- > handler1 :: WithVerifier Handler Int
-- > handler1 = withVerifier
-- >   [verifier|allow if right("one");|]
-- >   (pure 1)
-- >
-- > handler2 :: Int -> WithVerifier Handler Int
-- > handler2 value = withVerifier
-- >   [verifier|allow if right("two", ${value});|]
-- >   (pure 2)
-- >
-- > handler3 :: WithVerifier Handler Int
-- > handler3 = withVerifier
-- >   [verifier|allow if right("three");|]
-- >   (pure 3)
-- >
-- > server :: Biscuit OpenOrSealed Checked -> Server ProtectedAPI
-- > server biscuit =
-- >  let nowFact = do
-- >        now <- liftIO getCurrentTime
-- >        pure [verifier|time(${now});|]
-- >      handleAuth :: WithVerifier Handler x -> Handler x
-- >      handleAuth =
-- >          handleBiscuit biscuit
-- >          -- ^ this runs datalog checks on the biscuit, based on verifiers attached to
-- >          -- the handlers
-- >        . withPriorityVerifierM nowFact
-- >          -- ^ this provides the current time to the verification context so that biscuits with
-- >          -- a TTL can verify if they are still valid.
-- >          -- Verifiers can be provided in a monadic context (it has to be the same monad as
-- >          -- the handlers themselves, so here it's 'Handler').
-- >        . withPriorityVerifier [verifier|allow if right("admin");|]
-- >          -- ^ this policy will be tried /before/ any endpoint policy, so `endpoint3` will be
-- >          -- reachable with an admin biscuit
-- >        . withFallbackVerifier [verifier|allow if right("anon");|]
-- >          -- ^ this policy will be tried /after/ the endpoints policies, so `endpoint3` will
-- >          -- *not* be reachable with an anon macaroon.
-- >      handlers = handler1 :<|> handler2 :<|> handler3
-- >   in hoistServer @ProtectedAPI Proxy handleAuth handlers
-- >        -- ^ this will apply `handleAuth` on all 'ProtectedAPI' endpoints.

-- | Type used to protect and API tree, requiring a biscuit token
-- to be attached to requests. The associated auth handler will
-- only check the biscuit signature. Checking the datalog part
-- usually requires endpoint-specific information, and has to
-- be performed separately with either 'checkBiscuit' (for simple
-- use-cases) or 'handleBiscuit' (for more complex use-cases).
type RequireBiscuit = AuthProtect "biscuit"
type instance AuthServerData RequireBiscuit = Biscuit OpenOrSealed Checked

-- | Wrapper for a servant handler, equipped with a biscuit 'Verifier'
-- that will be used to authorize the request. If the authorization
-- succeeds, the handler is ran.
-- The handler itself is given access to the verified biscuit through
-- a @ReaderT (Biscuit OpenOrSealed Checked)@.
data WithVerifier m a
  = WithVerifier
  { handler_  :: ReaderT (Biscuit OpenOrSealed Checked) m a
  -- ^ the wrapped handler, in a 'ReaderT' to give easy access to the biscuit
  , verifier_ :: m Verifier
  -- ^ the 'Verifier' associated to the handler
  }

-- | Combines the provided 'Verifier' to the 'Verifier' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackVerifier' puts the provided policies at the /bottom/
-- of the list (ie as /fallback/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityVerifier' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried before the ones of the wrapped handler, you
-- can use 'withPriorityVerifier'.
--
-- If you need to perform effects to compute the verifier (eg. to get the current date,
-- or to query a database), you can use 'withFallbackVerifierM' instead.
withFallbackVerifier :: Functor m
                     => Verifier
                     -> WithVerifier m a
                     -> WithVerifier m a
withFallbackVerifier newV h@WithVerifier{verifier_} =
  h { verifier_ = (<> newV) <$> verifier_ }

-- | Combines the provided 'Verifier' to the 'Verifier' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackVerifier' puts the provided policies at the /bottom/
-- of the list (ie as /fallback/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityVerifier' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried before the ones of the wrapped handler, you
-- can use 'withPriorityVerifier'.
--
-- Here, the 'Verifier' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withFallbackVerifier' instead.
withFallbackVerifierM :: Applicative m
                      => m Verifier
                      -> WithVerifier m a
                      -> WithVerifier m a
withFallbackVerifierM newV h@WithVerifier{verifier_} =
  h { verifier_ = liftA2 (<>) verifier_ newV }

-- | Combines the provided 'Verifier' to the 'Verifier' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackVerifier' puts the provided policies at the /top/
-- of the list (ie as /priority/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityVerifier' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried after the ones of the wrapped handler, you
-- can use 'withFallbackVerifier'.
--
-- If you need to perform effects to compute the verifier (eg. to get the current date,
-- or to query a database), you can use 'withPriorityVerifierM' instead.
withPriorityVerifier :: Functor m
                     => Verifier
                     -> WithVerifier m a
                     -> WithVerifier m a
withPriorityVerifier newV h@WithVerifier{verifier_} =
     h { verifier_ = (newV <>) <$> verifier_ }

-- | Combines the provided 'Verifier' to the 'Verifier' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackVerifier' puts the provided policies at the /top/
-- of the list (ie as /priority/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityVerifier' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried after the ones of the wrapped handler, you
-- can use 'withFallbackVerifier'.
--
-- Here, the 'Verifier' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withFallbackVerifier' instead.
withPriorityVerifierM :: Applicative m
                      => m Verifier
                      -> WithVerifier m a
                      -> WithVerifier m a
withPriorityVerifierM newV h@WithVerifier{verifier_} =
     h { verifier_ = liftA2 (<>) newV verifier_ }

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Checked)' to be able to access the token.
-- If you don't need to access the token from the handler block, you can use
-- 'withVerifier_' instead.
--
-- If you need to perform effects to compute the verifier (eg. to get the current date,
-- or to query a database), you can use 'withVerifierM' instead.
withVerifier :: Applicative m
             => Verifier
             -> ReaderT (Biscuit OpenOrSealed Checked) m a
             -> WithVerifier m a
withVerifier v handler_ =
  WithVerifier
    { handler_
    , verifier_ = pure v
    }

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Checked)@ to be able to access the token.
-- If you don't need to access the token from the handler block, you can use
-- 'withVerifier_' instead.
--
-- Here, the 'Verifier' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withVerifier' instead.
withVerifierM :: m Verifier
              -> ReaderT (Biscuit OpenOrSealed Checked) m a
              -> WithVerifier m a
withVerifierM verifier_ handler_ =
  WithVerifier
    { handler_
    , verifier_
    }

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler can be
-- any monad, but won't be able to access the biscuit. If you want to read the biscuit
-- token from the handler block, you can use 'withVerifier' instead.
--
-- If you need to perform effects to compute the verifier (eg. to get the current date,
-- or to query a database), you can use 'withVerifierM_' instead.
withVerifier_ :: Monad m => Verifier -> m a -> WithVerifier m a
withVerifier_ v = withVerifier v . lift

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler can be
-- any monad, but won't be able to access the 'Biscuit'.
--
-- If you want to read the biscuit token from the handler block, you can use 'withVerifier'
-- instead.
--
-- Here, the 'Verifier' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withVerifier_' instead.
withVerifierM_ :: Monad m => m Verifier -> m a -> WithVerifier m a
withVerifierM_ v = withVerifierM v . lift

-- | Wraps an existing handler block, attaching an empty 'Verifier'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Checked)@ to be able to access the token. If you don't need
-- to access the token from the handler block, you can use 'noVerifier_'
-- instead.
--
-- This function is useful when the endpoint does not have any specific verifier
-- context, and the verifier context is applied on the whole API tree through
-- 'withFallbackVerifier' or 'withPriorityVerifier' to apply policies on several
-- handlers at the same time (with 'hoistServer' for instance).
noVerifier :: Applicative m
           => ReaderT (Biscuit OpenOrSealed Checked) m a
           -> WithVerifier m a
noVerifier = withVerifier mempty

-- | Wraps an existing handler block, attaching an empty 'Verifier'. The handler can be
-- any monad, but won't be able to access the biscuit. If you want to read the
-- biscuit token from the handler block, you can use 'noVerifier' instead.
--
-- This function is useful when the endpoint does not have any specific verifier
-- context, and the verifier context is applied on the whole API tree through
-- 'withFallbackVerifier' or 'withPriorityVerifier' to apply policies on several
-- handlers at the same time (with 'hoistServer' for instance).
noVerifier_ :: Monad m => m a -> WithVerifier m a
noVerifier_ = noVerifier . lift

-- | Extracts a biscuit from an http request, assuming:
--
-- - the biscuit is b64-encoded
-- - prefixed with the @Bearer @ string
-- - in the @Authorization@ header
extractBiscuit :: PublicKey
               -> Request
               -> Either String (Biscuit OpenOrSealed Checked)
extractBiscuit pk req = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders req
  b64Token   <- note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader
  first (const "Not a B64-encoded biscuit") $ parseB64 pk b64Token

-- | Servant authorization handler. This extracts the biscuit from the request,
-- checks its signature (but not the datalog part) and returns a 'Biscuit'
-- upon success.
authHandler :: PublicKey
            -> AuthHandler Request (Biscuit OpenOrSealed Checked)
authHandler publicKey = mkAuthHandler handler
  where
    authError s = err401 { errBody = LBS.fromStrict (C8.pack s) }
    orError = either (throwError . authError) pure
    handler req =
      orError $ extractBiscuit publicKey req

-- | Helper function generating a servant context containing the authorization
-- handler.
genBiscuitCtx :: PublicKey
              -> Context '[AuthHandler Request (Biscuit OpenOrSealed Checked)]
genBiscuitCtx pk = authHandler pk :. EmptyContext

-- | Given a biscuit (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Verifier').
--
-- If you need to perform effects in the verification phase (eg to get the current time,
-- or if you need to issue a DB query to retrieve extra information needed to check the token),
-- you can use 'checkBiscuitM' instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to
-- blanket apply verifiers on whole API trees, you can consider using 'withVerifier'
-- (on endpoints), 'withFallbackVerifier' and 'withPriorityVerifier' (on API sub-trees)
-- and 'handleBiscuit' (on the whole API).
checkBiscuit :: (MonadIO m, MonadError ServerError m)
             => Biscuit OpenOrSealed Checked
             -> Verifier
             -> m a
             -> m a
checkBiscuit vb v h = do
  res <- liftIO $ verifyBiscuit vb v
  case res of
    Left e  -> do liftIO $ print e
                  throwError $ err401 { errBody = "Biscuit failed checks" }
    Right _ -> h

-- | Given a 'Biscuit' (provided by the servant authorization mechanism),
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
              => Biscuit OpenOrSealed Checked
              -> m Verifier
              -> m a
              -> m a
checkBiscuitM vb mv h = do
  v   <- mv
  res <- liftIO $ verifyBiscuit vb v
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
              => Biscuit OpenOrSealed Checked
              -> WithVerifier m a
              -> m a
handleBiscuit b WithVerifier{verifier_, handler_} =
  let h = runReaderT handler_ b
  in checkBiscuitM b verifier_ h
