{-# LANGUAGE DataKinds         #-}
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
  -- $keypairs
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
  -- $biscuitBlocks
  , mkBiscuit
  , block
  , blockContext
  , addBlock
  , fromOpen
  , fromSealed
  , Biscuit
  , OpenOrSealed
  , Open
  , Sealed
  , Checked
  , NotChecked
  , BiscuitProof
  , Block
  -- ** Parsing and serializing biscuits
  , serializeB64
  , parseB64
  , parse
  , serialize
  , parseHex
  , serializeHex

  -- * Verifying a biscuit
  -- $verifying
  , verifier
  , Verifier
  , verifyBiscuit
  , verifyBiscuitWithLimits
  , Limits (..)
  , defaultLimits
  , ParseError (..)
  , ExecutionError (..)
  , VerificationSuccess (..)

  -- * Retrieving information from a biscuit
  , getRevocationIds
  , getCheckedBiscuitSignature
  ) where

import           Control.Monad                       ((<=<))
import           Data.Bifunctor                      (first)
import           Data.ByteString                     (ByteString)
import qualified Data.ByteString.Base16              as Hex
import qualified Data.ByteString.Base64.URL          as B64
import           Data.Text                           (Text)

import           Auth.Biscuit.Crypto
import           Auth.Biscuit.Datalog.AST            (Block, Verifier, bContext)
import           Auth.Biscuit.Datalog.Executor       (ExecutionError (..),
                                                      Limits (..),
                                                      defaultLimits)
import           Auth.Biscuit.Datalog.Parser         (block, verifier)
import           Auth.Biscuit.Datalog.ScopedExecutor (VerificationSuccess (..))
import           Auth.Biscuit.Token                  (Biscuit,
                                                      BiscuitProof (..),
                                                      Checked, NotChecked, Open,
                                                      OpenOrSealed,
                                                      ParseError (..), Sealed,
                                                      addBlock, fromOpen,
                                                      fromSealed,
                                                      getCheckedBiscuitSignature,
                                                      getRevocationIds,
                                                      mkBiscuit, parseBiscuit,
                                                      serializeBiscuit,
                                                      verifyBiscuit,
                                                      verifyBiscuitWithLimits)
import           Auth.Biscuit.Utils                  (maybeToRight)


-- $biscuitOverview
--
-- <https://github.com/CleverCloud/biscuit/blob/master/SUMMARY.md Biscuit> is a /bearer token/,
-- allowing /offline attenuation/ (meaning that anyone having a token can craft a new, more
-- restricted token),
-- and /'PublicKey' verification/. Token rights and attenuation are expressed using a logic
-- language, derived from <todo datalog>. Such a language can describe facts (things we know
-- about the world), rules (describing how to derive new facts from existing ones) and checks
-- (ensuring that facts hold). Facts and checks let you describe access control rules, while
-- rules make them modular. /Verifier policies/ lets the verifying party ensure that a
-- provided biscuit grants access to the required operations.
--
-- Here's how to create a biscuit token:
--
-- > -- Biscuit Open Checked means the token has valid signatures
-- > -- and is open to further restriction
-- > buildToken :: Keypair -> IO (Biscuit Open Checked)
-- > buildToken keypair =
-- >   -- the logic language has its own syntax, which can be typed directly in haskell
-- >   -- source code thanks to QuasiQuotes. The datalog snippets are parsed and checked
-- >   -- at compile time, so a datalog error results in a compilation error, not a runtime
-- >   -- error
-- >   mkBiscuit keypair [block|
-- >       // the two first lines describe facts:
-- >       // the token holder is identified as `user_1234`
-- >       user("user_1234");
-- >       // the token holder is granted access to resource `file1`
-- >       resource("file1");
-- >       // this last line defines a restriction: properties that need
-- >       // to be verified for the token to be verified:
-- >       // the token can only be used before a specified date
-- >       check if time($time), $time < 2021-05-08T00:00:00Z;
-- >    |]
--
-- Here's how to attenuate a biscuit token:
--
-- > restrictToken :: Biscuit Open Checked -> IO Biscuit Open Checked
-- > restrictToken =
-- >   addBlock [block|
-- >       // restrict the token to local use only
-- >       check if user_ip_address("127.0.0.1");
-- >    |]
--
-- To verify a biscuit token, we need two things:
--  - a public key, that will let us verify the token has been emitted by
--    a trusted authority
--  - a verifier, that will make sure all the checks declared in the token are fulfilled,
--    as well as providing its own checks, and policies which decide if the token is
--    verified or not
--
-- Here's how to verify a base64-serialized biscuit token:
--
-- > verifyToken :: PublicKey -> ByteString -> IO Bool
-- > verifyToken publicKey token = do
-- >   -- complete parsing is only attempted if signatures can be verified,
-- >   -- that's the reason why 'parseB64' takes a public key as a parameter
-- >   parseResult <- parseB64 publicKey token
-- >   case parseResult of
-- >     Left e -> print e $> False
-- >     Right biscuit -> do
-- >       now <- getCurrentTime
-- >       let verif = [verifier|
-- >                // the datalog snippets can reference haskell variables
-- >                // with the ${variableName} syntax
-- >                time(${now});
-- >
-- >                // policies are tried in order. The first matching policy
-- >                // will decide if the token is valid or not. If no policies
-- >                // match, the token will fail validation
-- >                allow if resource("file1");
-- >                // catch-all policy if the previous ones did not match
-- >                deny if true;
-- >             |]
-- >       result <- verifyBiscuit biscuit [verifier|current_time()|]
-- >       case result of
-- >         Left e -> print e $> False
-- >         Right _ -> pure True

-- | Build a block containing an explicit context value.
-- The context of a block can't be parsed from datalog currently,
-- so you'll need an explicit call to `blockContext` to add it
--
-- >     [block|check if time($t), $t < 2021-01-01;|]
-- >  <> blockContext "ttl-check"
blockContext :: Text -> Block
blockContext c = mempty { bContext = Just c }

-- | Decode a base16-encoded bytestring, reporting errors via `MonadFail`
fromHex :: MonadFail m => ByteString -> m ByteString
fromHex input = do
  (decoded, "") <- pure $ Hex.decode input
  pure decoded

-- $keypairs
--
-- Biscuits rely on public key cryptography: biscuits are signed with a secret key only known
-- to the party which emits it. Verifying a biscuit, on the other hand, can be done with a
-- public key that can be widely distributed. A private key and its corresponding public key
-- is called a keypair, but since a public key can be deterministically computed from a
-- private key, owning a private key is the same as owning a keypair.

-- | Generate a new random 'SecretKey'
newSecret :: IO SecretKey
newSecret = generateSecretKey

-- | Serialize a 'SecretKey' to raw bytes, without any encoding
serializeSecretKey :: SecretKey -> ByteString
serializeSecretKey = convert

-- | Serialize a 'PublicKey' to raw bytes, without any encoding
serializePublicKey :: PublicKey -> ByteString
serializePublicKey = convert

-- | Serialize a 'SecretKey' to a hex-encoded bytestring
serializeSecretKeyHex :: SecretKey -> ByteString
serializeSecretKeyHex = Hex.encode . convert

-- | Serialize a 'PublicKey' to a hex-encoded bytestring
serializePublicKeyHex :: PublicKey -> ByteString
serializePublicKeyHex = Hex.encode . convert

-- | Read a 'SecretKey' from raw bytes
parseSecretKey :: ByteString -> Maybe SecretKey
parseSecretKey = maybeCryptoError . secretKey

-- | Read a 'SecretKey' from an hex bytestring
parseSecretKeyHex :: ByteString -> Maybe SecretKey
parseSecretKeyHex = parseSecretKey <=< fromHex

-- | Read a 'PublicKey' from raw bytes
parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey = maybeCryptoError . publicKey

-- | Read a 'PublicKey' from an hex bytestring
parsePublicKeyHex :: ByteString -> Maybe PublicKey
parsePublicKeyHex = parsePublicKey <=< fromHex

-- | Parse a biscuit from a raw bytestring. If you want to parse
-- from a URL-compatible base 64 bytestring, consider using `parseB64`
-- instead.
-- The biscuit signature is checked with the provided 'PublicKey' before
-- completely decoding blocks
parse :: PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Checked)
parse = parseBiscuit

-- | Parse a biscuit from a URL-compatible base 64 encoded bytestring
parseB64 :: PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Checked)
parseB64 pk = parse pk <=< first (const InvalidB64Encoding) . B64.decodeBase64

-- | Parse a biscuit from an hex-encoded bytestring
parseHex :: PublicKey -> ByteString -> Either ParseError (Biscuit OpenOrSealed Checked)
parseHex pk = parse pk <=< maybeToRight InvalidHexEncoding . fromHex

-- | Serialize a biscuit to a binary format. If you intend to send
-- the biscuit over a text channel, consider using `serializeB64` instead
serialize :: BiscuitProof p => Biscuit p Checked -> ByteString
serialize = serializeBiscuit

-- | Serialize a biscuit to URL-compatible base 64, as recommended by the spec
serializeB64 :: BiscuitProof p => Biscuit p Checked -> ByteString
serializeB64 = B64.encodeBase64' . serialize

-- | Serialize a biscuit to a hex (base 16) string. Be advised that the specs
-- recommends base 64 instead.
serializeHex :: BiscuitProof p => Biscuit p Checked -> ByteString
serializeHex = Hex.encode . serialize

-- $biscuitBlocks
--
-- The core of a biscuit is its authority block. This block declares facts and rules and
-- is signed by its creator with a secret key. In addition to this trusted, authority
-- block, a biscuit may carry extra blocks that can only restrict what it can do. By
-- default, biscuits can be restricted, but it's possible to seal a biscuit and prevent
-- further modifications.
--
-- Blocks are defined with a logic language (datalog) that can be used directly from haskell
-- with the `QuasiQuotes` extension.

-- $verifying
--
-- Verifying a biscuit requires providing a list of policies (/allow/ or /deny/), which will
-- decide if the biscuit is accepted. Policies are tried in order, and the first one to match
-- decides whether the biscuit is accepted.
--
-- In addition to policies, a verifier typically provides facts (such as the current time) so
-- that checks and policies can be verified.
--
-- The verifier checks and policies only see the content of the authority (first) block. Extra
-- blocks can only carry restrictions and cannot interfere with the authority facts.
