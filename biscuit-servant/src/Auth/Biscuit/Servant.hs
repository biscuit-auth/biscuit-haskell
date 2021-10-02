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
  -- ** Supplying a authorizer for a single endpoint
  -- $singleEndpointAuthorizer
  , checkBiscuit
  , checkBiscuitM
  -- ** Decorate regular handlers with composable authorizers
  -- $composableAuthorizers
  , WithAuthorizer (..)
  , handleBiscuit
  , withAuthorizer
  , withAuthorizer_
  , withAuthorizerM
  , withAuthorizerM_
  , noAuthorizer
  , noAuthorizer_
  , withFallbackAuthorizer
  , withPriorityAuthorizer
  , withFallbackAuthorizerM
  , withPriorityAuthorizerM

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
-- > -- server :: Biscuit OpenOrSealed Verified -> Server ProtectedAPI
-- > server :: Server API
-- > server biscuit = … -- this will be detailed later
--
-- This will instruct servant to extract the biscuit from the requests and
-- check its signature. /It will not/, however, run any datalog check (as
-- the checks typically depend on the request contents).
--
-- $singleEndpointAuthorizer
--
-- The corresponding @Server API@ value will be a @Biscuit OpenOrSealed Verified -> Server ProtectedAPI@.
-- The next step is to provide a 'Authorizer' so that the biscuit datalog can be
-- verified. For that, you can use 'checkBiscuit' (or 'checkBiscuitM' for effectful checks).
--
-- > server :: Server API
-- > server biscuit = h1 biscuit
-- >             :<|> h2 biscuit
-- >             :<|> h3 biscuit
-- >
-- > h1 :: Biscuit OpenOrSealed Verified -> Handler Int
-- > h1 biscuit =
-- >   checkBiscuit biscuit
-- >     [authorizer|allow if right("one");|]
-- >     -- ^ only allow biscuits granting access to the endpoint tagged "one"
-- >     (pure 1)
-- >
-- > h2 :: Biscuit OpenOrSealed Verified -> Int -> Handler Int
-- > h2 biscuit value =
-- >   let authorizer' = do
-- >         now <- liftIO getCurrentTime
-- >         pure [authorizer|
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
-- >   checkBiscuitM biscuit authorizer
-- >     (pure 2)
-- >
-- > h3 :: Biscuit OpenOrSealed Verified -> Handler Int
-- > h3 biscuit =
-- >   checkBiscuit biscuit
-- >     [authorizer|deny if true;|]
-- >     -- ^ reject every biscuit
-- >     (pure 3)
--
-- $composableAuthorizers
--
-- 'checkBiscuit' allows you to describe validation rules endpoint by endpoint. If your
-- application has a lot of endpoints with the same policies, it can become tedious to
-- maintain.
--
-- 'biscuit-servant' provides a way to apply authorizers on whole API trees,
-- in a composable way, thanks to 'hoistServer'. 'hoistServer' is a mechanism
-- provided by servant-server that lets apply a transformation function to whole
-- API trees.
--
-- > -- 'withAuthorizer' wraps a 'Handler' and lets you attach a authorizer to a
-- > -- specific endoint. This authorizer may be combined with other authorizers
-- > -- attached to the whole API tree
-- > handler1 :: WithAuthorizer Handler Int
-- > handler1 = withAuthorizer
-- >   [authorizer|allow if right("one");|]
-- >   (pure 1)
-- >
-- > handler2 :: Int -> WithAuthorizer Handler Int
-- > handler2 value = withAuthorizer
-- >   [authorizer|allow if right("two", ${value});|]
-- >   (pure 2)
-- >
-- > handler3 :: WithAuthorizer Handler Int
-- > handler3 = withAuthorizer
-- >   [authorizer|allow if right("three");|]
-- >   (pure 3)
-- >
-- > server :: Biscuit OpenOrSealed Verified -> Server ProtectedAPI
-- > server biscuit =
-- >  let nowFact = do
-- >        now <- liftIO getCurrentTime
-- >        pure [authorizer|time(${now});|]
-- >      handleAuth :: WithAuthorizer Handler x -> Handler x
-- >      handleAuth =
-- >          handleBiscuit biscuit
-- >          -- ^ this runs datalog checks on the biscuit, based on authorizers attached to
-- >          -- the handlers
-- >        . withPriorityAuthorizerM nowFact
-- >          -- ^ this provides the current time to the verification context so that biscuits with
-- >          -- a TTL can check if they are still valid.
-- >          -- Authorizers can be provided in a monadic context (it has to be the same monad as
-- >          -- the handlers themselves, so here it's 'Handler').
-- >        . withPriorityAuthorizer [authorizer|allow if right("admin");|]
-- >          -- ^ this policy will be tried /before/ any endpoint policy, so `endpoint3` will be
-- >          -- reachable with an admin biscuit
-- >        . withFallbackAuthorizer [authorizer|allow if right("anon");|]
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
type instance AuthServerData RequireBiscuit = Biscuit OpenOrSealed Verified

-- | Wrapper for a servant handler, equipped with a biscuit 'Authorizer'
-- that will be used to authorize the request. If the authorization
-- succeeds, the handler is ran.
-- The handler itself is given access to the verified biscuit through
-- a @ReaderT (Biscuit OpenOrSealed Verified)@.
data WithAuthorizer m a
  = WithAuthorizer
  { handler_    :: ReaderT (Biscuit OpenOrSealed Verified) m a
  -- ^ the wrapped handler, in a 'ReaderT' to give easy access to the biscuit
  , authorizer_ :: m Authorizer
  -- ^ the 'Authorizer' associated to the handler
  }

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /bottom/
-- of the list (ie as /fallback/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried before the ones of the wrapped handler, you
-- can use 'withPriorityAuthorizer'.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withFallbackAuthorizerM' instead.
withFallbackAuthorizer :: Functor m
                     => Authorizer
                     -> WithAuthorizer m a
                     -> WithAuthorizer m a
withFallbackAuthorizer newV h@WithAuthorizer{authorizer_} =
  h { authorizer_ = (<> newV) <$> authorizer_ }

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /bottom/
-- of the list (ie as /fallback/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried before the ones of the wrapped handler, you
-- can use 'withPriorityAuthorizer'.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withFallbackAuthorizer' instead.
withFallbackAuthorizerM :: Applicative m
                      => m Authorizer
                      -> WithAuthorizer m a
                      -> WithAuthorizer m a
withFallbackAuthorizerM newV h@WithAuthorizer{authorizer_} =
  h { authorizer_ = liftA2 (<>) authorizer_ newV }

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /top/
-- of the list (ie as /priority/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried after the ones of the wrapped handler, you
-- can use 'withFallbackAuthorizer'.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withPriorityAuthorizerM' instead.
withPriorityAuthorizer :: Functor m
                     => Authorizer
                     -> WithAuthorizer m a
                     -> WithAuthorizer m a
withPriorityAuthorizer newV h@WithAuthorizer{authorizer_} =
     h { authorizer_ = (newV <>) <$> authorizer_ }

-- | Combines the provided 'Authorizer' to the 'Authorizer' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackAuthorizer' puts the provided policies at the /top/
-- of the list (ie as /priority/ policies): these policies will be tried /after/
-- the policies declared through 'withPriorityAuthorizer' and after the policies
-- declared by the endpoints.
--
-- If you want the policies to be tried after the ones of the wrapped handler, you
-- can use 'withFallbackAuthorizer'.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withFallbackAuthorizer' instead.
withPriorityAuthorizerM :: Applicative m
                      => m Authorizer
                      -> WithAuthorizer m a
                      -> WithAuthorizer m a
withPriorityAuthorizerM newV h@WithAuthorizer{authorizer_} =
     h { authorizer_ = liftA2 (<>) newV authorizer_ }

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Verified)' to be able to access the token.
-- If you don't need to access the token from the handler block, you can use
-- 'withAuthorizer_' instead.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withAuthorizerM' instead.
withAuthorizer :: Applicative m
             => Authorizer
             -> ReaderT (Biscuit OpenOrSealed Verified) m a
             -> WithAuthorizer m a
withAuthorizer v handler_ =
  WithAuthorizer
    { handler_
    , authorizer_ = pure v
    }

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Verified)@ to be able to access the token.
-- If you don't need to access the token from the handler block, you can use
-- 'withAuthorizer_' instead.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withAuthorizer' instead.
withAuthorizerM :: m Authorizer
              -> ReaderT (Biscuit OpenOrSealed Verified) m a
              -> WithAuthorizer m a
withAuthorizerM authorizer_ handler_ =
  WithAuthorizer
    { handler_
    , authorizer_
    }

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler can be
-- any monad, but won't be able to access the biscuit. If you want to read the biscuit
-- token from the handler block, you can use 'withAuthorizer' instead.
--
-- If you need to perform effects to compute the authorizer (eg. to get the current date,
-- or to query a database), you can use 'withAuthorizerM_' instead.
withAuthorizer_ :: Monad m => Authorizer -> m a -> WithAuthorizer m a
withAuthorizer_ v = withAuthorizer v . lift

-- | Wraps an existing handler block, attaching a 'Authorizer'. The handler can be
-- any monad, but won't be able to access the 'Biscuit'.
--
-- If you want to read the biscuit token from the handler block, you can use 'withAuthorizer'
-- instead.
--
-- Here, the 'Authorizer' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withAuthorizer_' instead.
withAuthorizerM_ :: Monad m => m Authorizer -> m a -> WithAuthorizer m a
withAuthorizerM_ v = withAuthorizerM v . lift

-- | Wraps an existing handler block, attaching an empty 'Authorizer'. The handler has
-- to be a @ReaderT (Biscuit OpenOrSealed Verified)@ to be able to access the token. If you don't need
-- to access the token from the handler block, you can use 'noAuthorizer_'
-- instead.
--
-- This function is useful when the endpoint does not have any specific authorizer
-- context, and the authorizer context is applied on the whole API tree through
-- 'withFallbackAuthorizer' or 'withPriorityAuthorizer' to apply policies on several
-- handlers at the same time (with 'hoistServer' for instance).
noAuthorizer :: Applicative m
           => ReaderT (Biscuit OpenOrSealed Verified) m a
           -> WithAuthorizer m a
noAuthorizer = withAuthorizer mempty

-- | Wraps an existing handler block, attaching an empty 'Authorizer'. The handler can be
-- any monad, but won't be able to access the biscuit. If you want to read the
-- biscuit token from the handler block, you can use 'noAuthorizer' instead.
--
-- This function is useful when the endpoint does not have any specific authorizer
-- context, and the authorizer context is applied on the whole API tree through
-- 'withFallbackAuthorizer' or 'withPriorityAuthorizer' to apply policies on several
-- handlers at the same time (with 'hoistServer' for instance).
noAuthorizer_ :: Monad m => m a -> WithAuthorizer m a
noAuthorizer_ = noAuthorizer . lift

-- | Extracts a biscuit from an http request, assuming:
--
-- - the biscuit is b64-encoded
-- - prefixed with the @Bearer @ string
-- - in the @Authorization@ header
extractBiscuit :: PublicKey
               -> Request
               -> Either String (Biscuit OpenOrSealed Verified)
extractBiscuit pk req = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders req
  b64Token   <- note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader
  first (const "Not a B64-encoded biscuit") $ parseB64 pk b64Token

-- | Servant authorization handler. This extracts the biscuit from the request,
-- checks its signature (but not the datalog part) and returns a 'Biscuit'
-- upon success.
authHandler :: PublicKey
            -> AuthHandler Request (Biscuit OpenOrSealed Verified)
authHandler publicKey = mkAuthHandler handler
  where
    authError s = err401 { errBody = LBS.fromStrict (C8.pack s) }
    orError = either (throwError . authError) pure
    handler req =
      orError $ extractBiscuit publicKey req

-- | Helper function generating a servant context containing the authorization
-- handler.
genBiscuitCtx :: PublicKey
              -> Context '[AuthHandler Request (Biscuit OpenOrSealed Verified)]
genBiscuitCtx pk = authHandler pk :. EmptyContext

-- | Given a biscuit (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Authorizer').
--
-- If you need to perform effects in the verification phase (eg to get the current time,
-- or if you need to issue a DB query to retrieve extra information needed to check the token),
-- you can use 'checkBiscuitM' instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to
-- blanket apply authorizers on whole API trees, you can consider using 'withAuthorizer'
-- (on endpoints), 'withFallbackAuthorizer' and 'withPriorityAuthorizer' (on API sub-trees)
-- and 'handleBiscuit' (on the whole API).
checkBiscuit :: (MonadIO m, MonadError ServerError m)
             => Biscuit OpenOrSealed Verified
             -> Authorizer
             -> m a
             -> m a
checkBiscuit vb v h = do
  res <- liftIO $ authorizeBiscuit vb v
  case res of
    Left e  -> do liftIO $ print e
                  throwError $ err401 { errBody = "Biscuit failed checks" }
    Right _ -> h

-- | Given a 'Biscuit' (provided by the servant authorization mechanism),
-- verify its validity (with the provided 'Authorizer', which can be effectful).
--
-- If you don't need to run any effects in the verifying phase, you can use 'checkBiscuit'
-- instead.
--
-- If you don't want to pass the biscuit manually to all the endpoints or want to blanket apply
-- authorizers on whole API trees, you can consider using 'withAuthorizer' (on endpoints),
-- 'withFallbackAuthorizer' and 'withPriorityAuthorizer' (on API sub-trees) and 'handleBiscuit'
-- (on the whole API).
checkBiscuitM :: (MonadIO m, MonadError ServerError m)
              => Biscuit OpenOrSealed Verified
              -> m Authorizer
              -> m a
              -> m a
checkBiscuitM vb mv h = do
  v   <- mv
  res <- liftIO $ authorizeBiscuit vb v
  case res of
    Left e  -> do liftIO $ print e
                  throwError $ err401 { errBody = "Biscuit failed checks" }
    Right _ -> h

-- | Given a handler wrapped in a 'WithAuthorizer', use the attached 'Authorizer' to
-- verify the provided biscuit and return an error as needed.
--
-- For simpler use cases, consider using 'checkBiscuit' instead, which works on regular
-- servant handlers.
handleBiscuit :: (MonadIO m, MonadError ServerError m)
              => Biscuit OpenOrSealed Verified
              -> WithAuthorizer m a
              -> m a
handleBiscuit b WithAuthorizer{authorizer_, handler_} =
  let h = runReaderT handler_ b
  in checkBiscuitM b authorizer_ h
