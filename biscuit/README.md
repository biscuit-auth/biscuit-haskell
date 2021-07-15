# biscuit-haskell [![CI-badge][CI-badge]][CI-url] [![Hackage][hackage]][hackage-url]

<img src="https://raw.githubusercontent.com/divarvel/biscuit-haskell/main/assets/biscuit-logo.png" align=right>

Main library for biscuit tokens support, providing minting and signature checking of biscuit tokens, as well as a datalog engine allowing to compute the validity of a token in a given context.

## Supported biscuit versions

The core library supports regular [`v1` biscuits][v1spec] ([sealed tokens][v1sealedspec] are not supported yet).

### Extensions

This haskell library provides additional features that are not in the biscuit spec yet. There is ongoing work to integrate them in the main spec:

- extra runtime restrictions ([github issue](https://github.com/CleverCloud/biscuit/issues/69))
  - disallow regex matching, a common DoS vector
  - disallow fact generation in attenuation blocks
- unique revocation ids allowing tokens to be uniquely revoked ([github issue](https://github.com/CleverCloud/biscuit/issues/68))
- datalog syntax for whole blocks allowing blocks (facts, rules and checks) to be defined in a single expression ([github issue](https://github.com/CleverCloud/biscuit/issues/70))

## System requirements

This library has two system dependencies:

- The [`c2hs`](https://hackage.haskell.org/package/c2hs) preprocessor
- [`libsodium-1.0.18-stable`](https://download.libsodium.org/libsodium/releases/) (library and headers)

## How to use this library

This library was designed with the use of [`QuasiQuotes`][quasiquotes] in mind.

A [minimal example][biscuitexample] is provided in the library itself, and the [package documentation][packagedoc] contains comprehensive examples and explanations for all the library features.

Familiarity with biscuit tokens will make the examples easier to follow.
Reading the [biscuit presentation][biscuit] and the [biscuit tutorial][biscuittutorial] is advised.

### Checking a biscuit token

To make sure a biscuit token is valid, two checks have to take place:

- a signature check with a public key, making sure the token is authentic
- a datalog check making sure the token is valid in the given context

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
  -- biscuits are typically serialized as base64 bytestrings
  biscuit <- either (fail . show) pure $ parseB64 serialized
  -- the verifier can carry facts (like here), but also checks or policies
  -- verifiers are defined inline, directly in datalog, through the `verifier`
  -- quasiquoter. datalog parsing and validation happens at compile time, but
  -- can still reference haskell variables.
  let verifier' = [verifier|current_time(#ambient, ${now});
                            allow if true;
                           |]
  -- `verifyBiscuit` performs both the signature and datalog checks at the same time
  result <- verifyBiscuit biscuit verifier' publicKey'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True
```

### Creating (and attenuating) biscuit tokens

Biscuit tokens are created from a private key, and can be attenuated without it.

```haskell
-- private keys are typically serialized as hex-encoded strings.
-- In most cases they will be read from a config file or an environment
-- variable (env vars or another secret management system are favored,
-- since the private key is sensitive information).
privateKey' :: PrivateKey
privateKey' = case parsePrivateKeyHex "todo" of
  Nothing -> error "Error parsing private key"
  Just k  -> k

creation :: IO ByteString
creation = do
  -- biscuit tokens carry an authority block, which contents are guaranteed by the
  -- private key. Its facts and rules carry the `#authority` symbol to denote their
  -- privileged status.
  -- blocks are defined inline, directly in datalog, through the `block`
  -- quasiquoter. datalog parsing and validation happens at compile time, but
  -- can still reference haskell variables.
  let authority = [block|
       // toto
       resource(#authority,"file1");
       |]
  keypair <- fromPrivateKey privateKey'
  biscuit <- mkBiscuit keypair authority
  -- biscuits can be attenuated with blocks. blocks are not guaranteed by the private key and
  -- should only restrict the token use. As a result, facts generated in blocks cannot carry
  -- the `#authority` symbol.
  -- Here, the block only adds a TTL check.
  let block1 = [block|check if current_time(#ambient, $time), $time < 2021-05-08T00:00:00Z;|]
  -- `addBlock` only takes a block and a biscuit, the private key is not needed:
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
[v1spec]: https://github.com/CleverCloud/biscuit/blob/master/SPECIFICATIONS.md#version-1
[v1sealedspec]: https://github.com/CleverCloud/biscuit/blob/master/SPECIFICATIONS.md#sealed-tokens
[extensionissue]: https://github.com/CleverCloud/biscuit/issues/69
[quasiquotes]: https://wiki.haskell.org/Quasiquotation
[biscuitexample]: https://github.com/divarvel/biscuit-haskell/blob/main/biscuit/src/Auth/Biscuit/Example.hs
[packagedoc]: https://hackage.haskell.org/package/biscuit-haskell-0.1.0.0/docs/Auth-Biscuit.html
