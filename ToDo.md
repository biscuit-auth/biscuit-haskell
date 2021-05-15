# ToDo

- [x] spec user-facing API
- [x] implement user-facing API
  - [x] parse
  - [x] serialize
  - [x] create biscuit
  - [x] attenuate existing biscuit
  - [x] verify signature
  - [x] run checks & policies

- [ ] Datalog engine
  - [x] forbid use of variables in facts (through the AST)
  - [ ] handle revocation ids
  - [x] enforce `#authority` / `#ambient` restrictions in blocks
  - [ ] implement verifier limits (facts count, iterations count, timeout)

- [ ] Harden crypto
  - [ ] check all sensitive buffers are filled with zeroes after use
  - [ ] investigate zeroing the pk bytestring buffer on free

- [x] Implement parsers & serialization
  - [x] parse `check if` conditions
  - [x] parse `allow` / `deny` conditions
  - [x] parse whole policies (with an associated quasiquoter)
  - [x] parse whole block (with an associated quasiquoter)
  - [x] convert protobuf messages into `AST` values
  - [x] convert `AST` values into protobuf messages

- [ ] implement a CLI tool
  - [ ] create biscuit (spec)
  - [ ] create biscuit
  - [ ] check biscuit (spec)
  - [ ] check biscuit
  - [ ] attenuate biscuit (spec)
  - [ ] attenuate biscuit

- [ ] use ContT in `Sel`
- [ ] move the modules under a `Crypto` namespace
- [ ] try building with cabal
- [ ] add CI
