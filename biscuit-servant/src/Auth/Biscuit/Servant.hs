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
  , CheckedBiscuit (..)
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
-- > app :: Application
-- > app = serveWithContext (Proxy :: Proxy API)
-- >         (genBiscuitCtx publicKey) -- servant needs access to the biscuit /public/
-- >                                   -- key to be able to check biscuit signatures.
-- >                                   -- The public key can be read from the environment
-- >                                   -- and parsed using 'parsePublicKeyHex' for instance.
-- >         server
-- >
-- > server :: Server API -- CheckedBiscuit -> Server ProtectedAPI
-- > server biscuit = … -- this will be detailed later
--
-- This will instruct servant to extract the biscuit from the requests and
-- check its signature. *It will not*, however, run any datalog check (as
-- the checks typically depend on the request contents).
--
-- $singleEndpointVerifier
--
-- The corresponding @Server API@ value will be a @CheckedBiscuit -> Server ProtectedAPI@.
-- The next step is to provide a 'Verifier' so that the biscuit datalog can be
-- verified. For that, you can use 'checkBiscuit' (or 'checkBiscuitM').
--
-- > server :: Server API
-- > server biscuit = h1 biscuit
-- >             :<|> h2 biscuit
-- >             :<|> h3 biscuit
-- >
-- > h1 :: CheckedBiscuit -> Handler Int
-- > h1 biscuit =
-- >   checkBiscuit biscuit
-- >     [verifier|allow if right(#authority,#one);|]
-- >     -- ^ only allow biscuits granting access to the endpoint tagged `#one`
-- >     (pure 1)
-- >
-- > h2 :: CheckedBiscuit -> Int -> Handler Int
-- > h2 biscuit value =
-- >   checkBiscuit biscuit
-- >     [verifier|allow if right(#authority,#two, ${value});|]
-- >     -- ^ only allow biscuits granting access to the endpoint tagged `#two`
-- >     -- AND for the provided int value.
-- >     (pure 2)
-- >
-- > h3 :: CheckedBiscuit -> Handler Int
-- > h3 biscuit =
-- >   checkBiscuit biscuit
-- >     [verifier|deny if true;|]
-- >     -- ^ reject every biscuit
-- >     (pure 3)
--
-- $composableVerifiers
--
-- 'checkBiscuit' allows you to describe validation rules endpoint by endpoint. Since 'Verifier'
-- has a 'Monoid' instance, you can avoid duplication by extracting common rules, but that still
-- requires some boilerplate (and it won't prevent you from forgetting to add them on some endpoints).
--
-- 'biscuit-servant' provides a way to apply verifiers on whole API trees, in a composable way, thanks
-- to 'hoistServer':
--
-- > -- 'withVerifier' wraps a 'Handler' and lets you attach a verifier
-- > handler1 :: WithVerifier Handler Int
-- > handler1 = withVerifier
-- >   [verifier|allow if right(#authority, #one);|]
-- >   (pure 1)
-- >
-- > handler2 :: Int -> WithVerifier Handler Int
-- > handler2 value = withVerifier
-- >   [verifier|allow if right(#authority, #two, ${value});|]
-- >   (pure 2)
-- >
-- > handler3 :: WithVerifier Handler Int
-- > handler3 = withVerifier
-- >   [verifier|allow if right(#authority, #three);|]
-- >   (pure 3)
-- >
-- > server :: Server API
-- > server =
-- >  let nowFact = do
-- >        now <- liftIO getCurrentTime
-- >        pure [verifier|now(#ambient, ${now});|]
-- >      handleAuth :: WithVerifier Handler x -> Handler x
-- >      handleAuth =
-- >          handleBiscuit b
-- >          -- ^ this runs datalog checks on the biscuit, based on verifiers attached to
-- >          -- the handlers
-- >        . withPriorityVerifierM nowFact
-- >          -- ^ this provides the current time to the verification context so that biscuits with
-- >          -- a TTL can verify if they are still valid.
-- >          -- Verifiers can be provided in a monadic context (it just has to be the same as
-- >          -- the handlers themselves, so here it's 'Handler').
-- >        . withPriorityVerifier [verifier|allow if right(#authority, #admin);|]
-- >          -- ^ this policy will be tried /before/ any endpoint policy, so `endpoint3` will be
-- >          -- reachable with an admin biscuit
-- >        . withFallbackVerifier [verifier|allow if right(#authority, #anon);|]
-- >          -- ^ this policy will be tried /after/ the endpoints policies, so `endpoint3` will
-- >          -- *not* be reachable with an anon macaroon.
-- >      handlers = handler1 :<|> handler2 :<|> handler3
-- >   in hoistServer @ProtectedAPI Proxy handleAuth handlers
-- >        -- ^ this will apply `handleAuth` on all 'ProtectedAPI' endpoints.
--
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
-- a 'ReaderT' 'Biscuit'.
data WithVerifier m a
  = WithVerifier
  { handler_  :: ReaderT Biscuit m a
  -- ^ the wrapped handler, in a 'ReaderT' to give easy access to the biscuit
  , verifier_ :: m Verifier
  -- ^ the 'Verifier' associated to the handler
  }

-- | Combines the provided 'Verifier' to the 'Verifier' attached to the wrapped
-- handler. /facts/, /rules/ and /checks/ are unordered, but /policies/ have a
-- specific order. 'withFallbackVerifier' puts the provided policies at the /bottom/
-- of the list (ie as /fallback/ policies).
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
-- of the list (ie as /fallback/ policies).
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
-- of the list (ie as /priority/ policies).
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
-- of the list (ie as /priority/ policies).
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
-- to be a 'ReaderT' 'Biscuit' to be able to access the token.
--
-- If you don't need to access the token from the handler block, you can use
-- 'withVerifier_' instead.
--
-- If you need to perform effects to compute the verifier (eg. to get the current date,
-- or to query a database), you can use 'withVerifierM' instead.
withVerifier :: Applicative m => Verifier -> ReaderT Biscuit m a -> WithVerifier m a
withVerifier v handler_ =
  WithVerifier
    { handler_
    , verifier_ = pure v
    }

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler has
-- to be a 'ReaderT' 'Biscuit' to be able to access the token.
--
-- If you don't need to access the token from the handler block, you can use
-- 'withVerifier_' instead.
--
-- Here, the 'Verifier' can be computed effectfully. If you don't need to perform effects,
-- you can use 'withVerifier' instead.
withVerifierM :: m Verifier -> ReaderT Biscuit m a -> WithVerifier m a
withVerifierM verifier_ handler_ =
  WithVerifier
    { handler_
    , verifier_
    }

-- | Wraps an existing handler block, attaching a 'Verifier'. The handler can be
-- any monad, but won't be able to access the 'Biscuit'.
--
-- If you want to read the biscuit token from the handler block, you can use 'withVerifier'
-- instead.
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
-- to be a 'ReaderT' 'Biscuit' to be able to access the token. If you don't need
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
-- - prefixed with the @Bearer @ string
-- - in the @Authorization@ header
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
