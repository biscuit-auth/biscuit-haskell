# Biscuit [![CI-badge][CI-badge]][CI-url] [![Hackage][hackage]][hackage-url]

<img src="https://raw.githubusercontent.com/divarvel/biscuit-haskell/main/assets/biscuit-logo.png" align=right>

This is the repository for a collection of haskell libraries providing support for the [Biscuit][biscuit] auth toolkit, created by [Geoffroy Couprie][gcouprie].

You will find below the main lib and its companions:

* [biscuit](./biscuit/) — Main library, providing minting and signature checking of biscuit tokens, as well as a datalog engine allowing to compute the validity of a token in a given context
* [biscuit-servant](./biscuit-servant) — Servant combinators, for a smooth integration in your API

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

The core library (and transitively all the others) have two system dependencies:

- The [`c2hs`](https://hackage.haskell.org/package/c2hs) preprocessor
- [`libsodium-1.0.18-stable`](https://download.libsodium.org/libsodium/releases/) (library and headers)

[CI-badge]: https://img.shields.io/github/workflow/status/Divarvel/biscuit-haskell/CI?style=flat-square
[CI-url]: https://github.com/Divarvel/biscuit-haskell/actions
[Hackage]: https://img.shields.io/hackage/v/biscuit-haskell?color=purple&style=flat-square
[hackage-url]: https://hackage.haskell.org/package/biscuit-haskell
[gcouprie]: https://github.com/geal
[biscuit]: https://www.clever-cloud.com/blog/engineering/2021/04/12/introduction-to-biscuit/
[v1spec]: https://github.com/CleverCloud/biscuit/blob/master/SPECIFICATIONS.md#version-1
[v1sealedspec]: https://github.com/CleverCloud/biscuit/blob/master/SPECIFICATIONS.md#sealed-tokens
