# Changelog for biscuit-haskell

## 0.3.0.1

- GHC 9.6 and 9.8 support
- Support for `!=`
- Fixed-sized arithmetic and overflow detection
- Allow parsing chained method calls

## 0.3.0.0

- GHC 9.2 support
- support for `v4` blocks:
  - support for third-party blocks & scope annotations
  - support for `check all`
  - support for bitwise operations in datalog
  - support for scoped queries after authorization
- new datalog parser with better error reporting
- forbid unbound variables during datalog parsing and
  token deserialization
- update parameters syntax: `${name}` is now `{name}`
- support for runtime datalog parsing
- support for pre-authorization queries

## 0.2.1.0

- support for string concatenation in datalog
- support for `.contains()` on strings in datalog
- update default symbol table

## 0.2.0.1

- rename `verifier` to `authorizer`
- keep track of the public key used to verify a biscuit
- check revocation id during parsing
- support for sealing biscuits
- support for querying facts after authorization

## 0.2.0.0

- support for v2 biscuits

## 0.1.1.0

Bugfix for `serializeB64` and `serializeHex`.

## 0.1.0.0

Basic biscuit support.
