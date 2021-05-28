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
  ( PrivateKey
  , PublicKey
  , Biscuit
  , Block
  , Verifier
  , ParseError (..)
  , VerificationError (..)
  , Limits (..)
  , blockContext
  , newKeypair
  , publicKey
  , privateKey
  , fromPrivateKey
  , serializePrivateKey
  , serializePublicKey
  , serializePrivateKeyHex
  , serializePublicKeyHex
  , parsePrivateKey
  , parsePublicKey
  , parsePrivateKeyHex
  , parsePublicKeyHex
  , mkBiscuit
  , addBlock
  , parse
  , parseB64
  , parseHex
  , serialize
  , serializeB64
  , serializeHex
  , verifyBiscuit
  , verifyBiscuitWithLimits
  , checkBiscuitSignature

  , defaultLimits
  ) where

import           Control.Monad                 ((<=<))
import           Data.Bifunctor                (first)
import           Data.ByteString               (ByteString)
import qualified Data.ByteString.Base16        as Hex
import qualified Data.ByteString.Base64.URL    as B64
import           Data.Text                     (Text)

import           Auth.Biscuit.Datalog.AST      (Block, Verifier, bContext)
import           Auth.Biscuit.Datalog.Executor (Limits (..), defaultLimits)
import           Auth.Biscuit.Sel              (Keypair (..), PrivateKey,
                                                PublicKey, fromPrivateKey,
                                                newKeypair, parsePrivateKey,
                                                parsePublicKey,
                                                serializePrivateKey,
                                                serializePublicKey)
import           Auth.Biscuit.Token            (Biscuit, ParseError (..),
                                                VerificationError (..),
                                                addBlock, checkBiscuitSignature,
                                                mkBiscuit, parseBiscuit,
                                                serializeBiscuit, verifyBiscuit,
                                                verifyBiscuitWithLimits)
import           Auth.Biscuit.Utils            (maybeToRight)

-- | Build a block containing an explicit context value.
-- The context of a block can't be parsed from datalog currently,
-- so you'll need an explicit call to `blockContext` to add it
-- @
--      [block|check if time(#ambient, $t), $t < 2021-01-01;|]
--   <> blockContext "ttl-check"
-- @
blockContext :: Text -> Block
blockContext c = mempty { bContext = Just c }

-- | Decode a base16-encoded bytestring, reporting errors via `MonadFail`
fromHex :: MonadFail m => ByteString -> m ByteString
fromHex input = do
  (decoded, "") <- pure $ Hex.decode input
  pure decoded

-- | Get an hex bytestring from a private key
serializePrivateKeyHex :: PrivateKey -> ByteString
serializePrivateKeyHex = Hex.encode . serializePrivateKey

-- | Get an hex bytestring from a public key
serializePublicKeyHex :: PublicKey -> ByteString
serializePublicKeyHex = Hex.encode . serializePublicKey

-- | Read a private key from an hex bytestring
parsePrivateKeyHex :: ByteString -> Maybe PrivateKey
parsePrivateKeyHex = parsePrivateKey <=< fromHex

-- | Read a public key from an hex bytestring
parsePublicKeyHex :: ByteString -> Maybe PublicKey
parsePublicKeyHex = parsePublicKey <=< fromHex

-- | Parse a biscuit from a raw bytestring. If you want to parse
-- from a URL-compatible base 64 bytestring, consider using `parseB64`
-- instead
parse :: ByteString -> Either ParseError Biscuit
parse = parseBiscuit

-- | Parse a biscuit from a URL-compatible base 64 encoded bytestring
parseB64 :: ByteString -> Either ParseError Biscuit
parseB64 = parse <=< first (const InvalidB64Encoding) . B64.decodeBase64

-- | Parse a biscuit from an hex-encoded bytestring
parseHex :: ByteString -> Either ParseError Biscuit
parseHex = parse <=< maybeToRight InvalidHexEncoding . fromHex

-- | Serialize a biscuit to a binary format. If you intend to send
-- the biscuit over a text channel, consider using `serializeB64` or
-- `serializeHex` instead
serialize :: Biscuit -> ByteString
serialize = serializeBiscuit

-- | Serialize a biscuit to URL-compatible base 64, as recommended by the spec
serializeB64 :: Biscuit -> ByteString
serializeB64 = Hex.encode . serialize

-- | Serialize a biscuit to a hex (base 16) string. Be advised that the specs
-- recommends base 64 instead.
serializeHex :: Biscuit -> ByteString
serializeHex = B64.encodeBase64' . serialize
