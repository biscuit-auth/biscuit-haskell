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
  - [x] support regexes
  - [x] accumulate checks errors instead of returning the first one
  - [ ] log predicate / expressions errors with a writer to ease debugging
  - [x] implement verifier limits
    - [x] facts count
    - [x] iterations count
    - [x] timeout
    - [x] rules / facts in blocks
    - [x] regexes

- [x] Implement parsers & serialization
  - [x] parse `check if` conditions
  - [x] parse `allow` / `deny` conditions
  - [x] parse whole policies (with an associated quasiquoter)
  - [x] parse whole block (with an associated quasiquoter)
  - [x] convert protobuf messages into `AST` values
  - [x] convert `AST` values into protobuf messages
  - [x] only accept `v1` biscuits
  - [ ] accumulate protobuf errors with `Validation`

- [x] use ContT in `Sel`
- [x] Cleanup modules
  - [x] move the modules under a `Auth.Biscuit` namespace
  - [x] cleanup exports
  - [x] add missing haddock comments
- [x] try building with cabal
- [x] add CI
- [ ] check AST constraints after, not during, the parsing phase
- [ ] replace ad-hoc typeclasses / duplicated functions with HOFs

# Questions

- [x] what happens if no policies match? (examples always assume there is a catch-all policy). Should this be enforced?
    
    A dedicated error is reported when no policies match.
