# Biscuit [![CI-badge][CI-badge]][CI-url] [![Hackage][hackage]][hackage-url]

<img src="https://raw.githubusercontent.com/divarvel/biscuit-haskell/main/assets/biscuit-logo.png" align=right>

This is the repository for `biscuit-haskell`, a binding to the [Biscuit][biscuit]  
authorisation toolkit, created by [Geoffroy Couprie][gcouprie].

You will find below the main lib and its companions:

* [biscuit](./biscuit/) — The logic engine that verifies authentication policies
* [biscuit-servant](./biscuit-servant) — Servant combinators, for a smooth integration in your API

[CI-badge]: https://img.shields.io/github/workflow/status/Divarvel/biscuit-haskell/CI?style=flat-square
[CI-url]: https://github.com/Divarvel/biscuit-haskell/actions
[Hackage]: https://img.shields.io/hackage/v/biscuit-haskell?color=purple&style=flat-square
[hackage-url]: https://hackage.haskell.org/package/biscuit-haskell
[gcouprie]: https://github.com/geal
[biscuit]: https://www.clever-cloud.com/blog/engineering/2021/04/12/introduction-to-biscuit/
