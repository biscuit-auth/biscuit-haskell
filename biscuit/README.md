# biscuit-haskell [![CI-badge][CI-badge]][CI-url] [![Hackage][hackage]][hackage-url]

<img src="https://raw.githubusercontent.com/biscuit-auth/biscuit-haskell/main/assets/biscuit-logo.png" align=right>

Main library for biscuit tokens support, providing minting and signature verification of biscuit tokens, as well as a datalog engine allowing to compute the validity of a token in a given context.

## Supported biscuit versions

The core library supports [`v2` biscuits][v2spec] (both open and sealed).

## How to use this library

This library was designed with the use of [`QuasiQuotes`][quasiquotes] in mind.

A [minimal example][biscuitexample] is provided in the library itself, and the [package documentation][packagedoc] contains comprehensive examples and explanations for all the library features.

Familiarity with biscuit tokens will make the examples easier to follow.
Reading the [biscuit presentation][biscuit] and the [biscuit tutorial][biscuittutorial] is advised.

### Checking a biscuit token

To make sure a biscuit token is valid, two checks have to take place:

- a signature check with a public key, making sure the token is authentic
- a datalog check making sure the token is authorized for the given context

```haskell
-- public keys are typically serialized as hex-encoded strings.
-- In most cases they will be read from a config file or an environment
-- variable
publicKey' :: PublicKey
publicKey' = case parsePublicKeyHex "todo" of
  Nothing -> error "Error parsing public key"
  Just k  -> k

-- this function takes a base64-encoded biscuit in a bytestring, parses it,
-- checks it signature and its validity. Here the provided context is just
-- the current time (useful for TTL checks). In most cases, the provided context
-- will carry a permissions check for the endpoint being accessed.
verification :: ByteString -> IO Bool
verification serialized = do
  now <- getCurrentTime
  -- biscuits are typically serialized as base64 bytestrings. The publicKey is needed
  -- to check the biscuit integrity before completely deserializing it
  biscuit <- either (fail . show) pure $ parseB64 publicKey' serialized
  -- the verifier can carry facts (like here), but also checks or policies.
  -- verifiers are defined inline, directly in datalog, through the `verifier`
  -- quasiquoter. datalog parsing and validation happens at compile time, but
  -- can still reference haskell variables.
  let authorizer' = [authorizer|time({now});
                                allow if true;
                               |]
  -- `authorizeBiscuit` only works on valid biscuits, and runs the datalog verifications
  -- ensuring the biscuit is authorized in a given context
  result <- authorizeBiscuit biscuit authorizer'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True
```

### Creating (and attenuating) biscuit tokens

Biscuit tokens are created from a secret key, and can be attenuated without it.

```haskell
-- secret keys are typically serialized as hex-encoded strings.
-- In most cases they will be read from a config file or an environment
-- variable (env vars or another secret management system are favored,
-- since the secret key is sensitive information).
-- A random secret key can be generated with `generateSecretKey`
secretKey' :: SecretKey
secretKey' = case parseSecretPrivateKeyHex "todo" of
  Nothing -> error "Error parsing secret key"
  Just k  -> k

creation :: IO ByteString
creation = do
  -- biscuit tokens carry an authority block, which contents are guaranteed by the
  -- secret key.
  -- Blocks are defined inline, directly in datalog, through the `block`
  -- quasiquoter. datalog parsing and validation happens at compile time, but
  -- can still reference haskell variables.
  let authority = [block|
       // toto
       resource("file1");
       |]
  biscuit <- mkBiscuit secretKey authority
  -- biscuits can be attenuated with blocks. blocks are not guaranteed by the secret key and
  -- should only restrict the token use. This property is guaranteed by the datalog evaluation:
  -- facts and rules declared in a block cannot interact with previous blocks.
  -- Here, the block only adds a TTL check.
  let block1 = [block|check if time($time), $time < 2021-05-08T00:00:00Z;|]
  -- `addBlock` only takes a block and a biscuit, the secret key is not needed:
  -- any biscuit can be attenuated by its holder.
  newBiscuit <- addBlock block1 biscuit
  pure $ serializeB64 newBiscuit
```

[CI-badge]: https://img.shields.io/github/workflow/status/Divarvel/biscuit-haskell/CI?style=flat-square
[CI-url]: https://github.com/Divarvel/biscuit-haskell/actions
[Hackage]: https://img.shields.io/hackage/v/biscuit-haskell?color=purple&style=flat-square
[hackage-url]: https://hackage.haskell.org/package/biscuit-haskell
[gcouprie]: https://github.com/geal
[biscuit]: https://www.clever-cloud.com/blog/engineering/2021/04/12/introduction-to-biscuit/
[biscuittutorial]: https://www.clever-cloud.com/blog/engineering/2021/04/15/biscuit-tutorial/
[v2spec]: https://github.com/CleverCloud/biscuit/blob/2.0/SPECIFICATIONS.md
[quasiquotes]: https://wiki.haskell.org/Quasiquotation
[biscuitexample]: https://github.com/biscuit-auth/biscuit-haskell/blob/main/biscuit/src/Auth/Biscuit/Example.hs
[packagedoc]: https://hackage.haskell.org/package/biscuit-haskell-0.1.0.0/docs/Auth-Biscuit.html
