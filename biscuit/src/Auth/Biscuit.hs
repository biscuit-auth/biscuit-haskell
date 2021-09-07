{-# LANGUAGE EmptyDataDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-|
  Module      : Auth.Biscuit
  Copyright   : © Clément Delafargue, 2021
  License     : MIT
  Maintainer  : clement@delafargue.name
  Haskell implementation for the Biscuit token.
-}
module Auth.Biscuit
  (
  -- * The biscuit auth token
  -- $biscuitOverview

  -- * Creating keypairs
    newSecret
  , toPublic
  , SecretKey
  , PublicKey

  -- ** Parsing and serializing keypairs
  , serializeSecretKeyHex
  , serializePublicKeyHex
  , parseSecretKeyHex
  , parsePublicKeyHex
  , serializeSecretKey
  , serializePublicKey
  , parseSecretKey
  , parsePublicKey

  -- * Creating a biscuit
  , block
  , blockContext
  , mkBiscuit
  , addBlock
  , fromOpen
  , fromSealed
  , Biscuit
  , OpenBiscuit
  , SealedBiscuit
  , Block
  -- ** Parsing and serializing biscuits
  , serializeB64
  , parseB64
  , parse
  , serialize
  , parseHex
  , serializeHex

  -- * Verifying a biscuit
  , verifier
  , verifyBiscuit
  , verifyBiscuitWithLimits
  , defaultLimits
  , Verifier
  , ParseError (..)
  , ExecutionError (..)
  , Limits (..)

  , fromHex
  ) where

import           Control.Monad                 ((<=<))
import           Data.Bifunctor                (first)
import           Data.ByteString               (ByteString)
import qualified Data.ByteString.Base16        as Hex
import qualified Data.ByteString.Base64.URL    as B64
import           Data.Text                     (Text)

import           Auth.Biscuit.Crypto
import           Auth.Biscuit.Datalog.AST      (Block, Verifier, bContext)
import           Auth.Biscuit.Datalog.Executor (ExecutionError (..),
                                                Limits (..), defaultLimits)
import           Auth.Biscuit.Datalog.Parser   (block, verifier)
import           Auth.Biscuit.Token            (Biscuit, Biscuit',
                                                BiscuitProof (..), OpenBiscuit,
                                                ParseError (..), SealedBiscuit,
                                                addBlock, fromOpen, fromSealed,
                                                mkBiscuit, parseBiscuit,
                                                serializeBiscuit, verifyBiscuit,
                                                verifyBiscuitWithLimits)
import           Auth.Biscuit.Utils            (maybeToRight)


-- $biscuitOverview
--
-- <https://github.com/CleverCloud/biscuit/blob/master/SUMMARY.md Biscuit> is a /bearer token/,
-- allowing /offline attenuation/ (meaning that anyone having a token can restrict its use),
-- and /public key verification/. Token rights and attenuation are expressed using a logic language.
--
-- Here's how to create a biscuit token:
--
-- > buildToken :: Keypair -> IO Biscuit
-- > buildToken keypair =
-- >   mkBiscuit keypair [block|
-- >       // the token holder is identified as `user_1234`
-- >       user(#authority, "user_1234");
-- >       // the token holder is granted access to resource `file1`
-- >       resource(#authority, "file1");
-- >       // the token can only be used before a specified date
-- >       check if time(#ambient, $time), $time < 2021-05-08T00:00:00Z;
-- >    |]
--
-- Here's how to attenuate a biscuit token:
--
-- > restrictToken :: Biscuit -> IO Biscuit
-- > restrictToken =
-- >   addBlock [block|
-- >       // restrict the token to local use only
-- >       check if user_ip_address(#ambient, "127.0.0.1");
-- >    |]
--
-- Here's how to verify a biscuit token:
--
-- > verifyToken :: PublicKey -> Biscuit -> IO Bool
-- > verifyToken publicKey biscuit = do
-- >   now <- getCurrentTime
-- >   let verif = [verifier|
-- >            // the datalog snippets can reference haskell variables
-- >            current_time(#ambient, ${now});
-- >
-- >            // policies are tried in order
-- >            allow if resource(#authority, "file1");
-- >            // catch-all policy if the previous ones did not match
-- >            deny if true;
-- >         |]
-- >   result <- verifyBiscuit biscuit [verifier|current_time()|]
-- >   case result of
-- >     Left e -> print e $> False
-- >     Right _ -> pure True

-- | Build a block containing an explicit context value.
-- The context of a block can't be parsed from datalog currently,
-- so you'll need an explicit call to `blockContext` to add it
--
-- >     [block|check if time(#ambient, $t), $t < 2021-01-01;|]
-- >  <> blockContext "ttl-check"
blockContext :: Text -> Block
blockContext c = mempty { bContext = Just c }

-- | Decode a base16-encoded bytestring, reporting errors via `MonadFail`
fromHex :: MonadFail m => ByteString -> m ByteString
fromHex input = do
  (decoded, "") <- pure $ Hex.decode input
  pure decoded

newSecret :: IO SecretKey
newSecret = generateSecretKey

serializeSecretKey :: SecretKey -> ByteString
serializeSecretKey = convert

serializePublicKey :: PublicKey -> ByteString
serializePublicKey = convert

-- | Get an hex bytestring from a private key
serializeSecretKeyHex :: SecretKey -> ByteString
serializeSecretKeyHex = Hex.encode . convert

-- | Get an hex bytestring from a public key
serializePublicKeyHex :: PublicKey -> ByteString
serializePublicKeyHex = Hex.encode . convert

parseSecretKey :: ByteString -> Maybe SecretKey
parseSecretKey = maybeCryptoError . secretKey

-- | Read a private key from an hex bytestring
parseSecretKeyHex :: ByteString -> Maybe SecretKey
parseSecretKeyHex = parseSecretKey <=< fromHex

parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey = maybeCryptoError . publicKey

-- | Read a public key from an hex bytestring
parsePublicKeyHex :: ByteString -> Maybe PublicKey
parsePublicKeyHex = parsePublicKey <=< fromHex

-- | Parse a biscuit from a raw bytestring. If you want to parse
-- from a URL-compatible base 64 bytestring, consider using `parseB64`
-- instead.
-- The biscuit signature is checked with the provided public key before
-- completely decoding blocks
parse :: PublicKey -> ByteString -> Either ParseError Biscuit
parse = parseBiscuit

-- | Parse a biscuit from a URL-compatible base 64 encoded bytestring
parseB64 :: PublicKey -> ByteString -> Either ParseError Biscuit
parseB64 pk = parse pk <=< first (const InvalidB64Encoding) . B64.decodeBase64

-- | Parse a biscuit from an hex-encoded bytestring
parseHex :: PublicKey -> ByteString -> Either ParseError Biscuit
parseHex pk = parse pk <=< maybeToRight InvalidHexEncoding . fromHex

-- | Serialize a biscuit to a binary format. If you intend to send
-- the biscuit over a text channel, consider using `serializeB64` or
-- `serializeHex` instead
serialize :: BiscuitProof p => Biscuit' p -> ByteString
serialize = serializeBiscuit

-- | Serialize a biscuit to URL-compatible base 64, as recommended by the spec
serializeB64 :: BiscuitProof p => Biscuit' p -> ByteString
serializeB64 = B64.encodeBase64' . serialize

-- | Serialize a biscuit to a hex (base 16) string. Be advised that the specs
-- recommends base 64 instead.
serializeHex :: BiscuitProof p => Biscuit' p -> ByteString
serializeHex = Hex.encode . serialize
