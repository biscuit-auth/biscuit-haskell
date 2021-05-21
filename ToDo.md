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
  - [x] handle revocation ids
  - [x] consider computing unique revocation ids (based on signatures)
  - [x] enforce `#authority` / `#ambient` restrictions in blocks
  - [x] report more detailed errors in datalog execution
  - [ ] support regexes
  - [x] accumulate checks errors instead of returning the first one
  - [ ] log predicate / expressions errors with a writer to ease debugging
  - [ ] implement verifier limits
    - [x] facts count
    - [x] iterations count
    - [x] timeout
    - [x] rules / facts in blocks
    - [ ] regexes

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

- [ ] use ContT in `Sel`
- [ ] move the modules under a `Crypto` namespace
- [x] try building with cabal
- [ ] add CI
- [ ] check AST constraints after, not during, the parsing phase

# Questions

- what happens if no policies match? (examples always assume there is a catch-all policy). Should this be enforced?
