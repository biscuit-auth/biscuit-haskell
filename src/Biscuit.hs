{-# LANGUAGE EmptyDataDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
module Biscuit
  ( PrivateKey
  , PublicKey
  , Biscuit
  , Block
  , Verifier
  , ParseError (..)
  , blockFact
  , blockRule
  , blockCheck
  , blockContext
  , verifierFact
  , verifierRule
  , verifierCheck
  , verifierPolicy
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

import           Control.Monad              ((<=<))
import           Data.Bifunctor             (first)
import           Data.ByteString            (ByteString)
import qualified Data.ByteString.Base16     as Hex
import qualified Data.ByteString.Base64.URL as B64
import           Data.Either.Combinators    (maybeToRight)
import           Data.Text                  (Text)

import           Datalog.AST                (Block, BlockElement' (..), Check,
                                             Fact, Policy, Rule, Verifier,
                                             VerifierElement' (..), bContext,
                                             elementToBlock, elementToVerifier)
import           Sel                        (Keypair (..), PrivateKey,
                                             PublicKey, fromPrivateKey,
                                             newKeypair, parsePrivateKey,
                                             parsePublicKey,
                                             serializePrivateKey,
                                             serializePublicKey)
import           Token                      (Biscuit, ParseError (..), addBlock,
                                             checkBiscuitSignature, mkBiscuit,
                                             parseBiscuit)

data VerificationError deriving Show
data Limits

blockFact :: Fact -> Block
blockFact = elementToBlock . BlockFact
blockRule :: Rule -> Block
blockRule = elementToBlock . BlockRule
blockCheck :: Check -> Block
blockCheck = elementToBlock . BlockCheck
blockContext :: Text -> Block
blockContext c = mempty { bContext = Just c }

verifierFact :: Fact -> Verifier
verifierFact = elementToVerifier . BlockElement . BlockFact
verifierRule :: Rule -> Verifier
verifierRule = elementToVerifier . BlockElement . BlockRule
verifierCheck :: Check -> Verifier
verifierCheck = elementToVerifier . BlockElement . BlockCheck
verifierPolicy :: Policy -> Verifier
verifierPolicy = elementToVerifier . VerifierPolicy

fromHex :: MonadFail m => ByteString -> m ByteString
fromHex input = do
  (decoded, "") <- pure $ Hex.decode input
  pure decoded

serializePrivateKeyHex :: PrivateKey -> ByteString
serializePrivateKeyHex = Hex.encode . serializePrivateKey
serializePublicKeyHex :: PublicKey -> ByteString
serializePublicKeyHex = Hex.encode . serializePublicKey
parsePrivateKeyHex :: ByteString -> Maybe PrivateKey
parsePrivateKeyHex = parsePrivateKey <=< fromHex
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
serialize = error "todo"

-- | Serialize a biscuit to URL-compatible base 64, as recommended by the spec
serializeB64 :: Biscuit -> ByteString
serializeB64 = Hex.encode . serialize

-- | Serialize a biscuit to a hex (base 16) string. Be advised that the specs
-- recommends base 64 instead.
serializeHex :: Biscuit -> ByteString
serializeHex = B64.encodeBase64' . serialize

-- | Given a provided verifier (a set of facts, rules, checks and policies),
-- and a public key, verify a biscuit
-- - make sure the biscuit has been signed with the private key associated to the public key
-- - make sure the biscuit is valid for the provided verifier
verifyBiscuit :: Biscuit -> Verifier -> PublicKey -> IO (Either VerificationError ())
verifyBiscuit = error "todo"

-- | Same as `verifyBiscuit`, but allows providing runtime restrictions
-- - timeout
-- - max number of facts created
-- - max number of iterations when computing facts
-- - expressions restrictions (eg, disallow regexes)
-- - blocks restrictions (eg disallow rules and facts in non-authority blocks)
verifyBiscuitWithLimits :: Limits -> Biscuit -> Verifier -> PublicKey -> IO (Either VerificationError ())
verifyBiscuitWithLimits = error "todo"

----- these functions are not meant to be in the top-level module, but they are not
-- implemented yet, so i'm putting them there for now
defaultLimits :: Limits
defaultLimits = error "todo"
