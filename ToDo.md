# ToDo

- [x] spec user-facing API
- [ ] implement user-facing API
- [ ] handle revocation ids
- [ ] enforce `#authority` / `#ambient` restrictions in blocks
- [ ] check all sensitive buffers are filled with zeroes after use
- [ ] investigate zeroing the pk bytestring buffer on free
- [x] forbid use of variables in facts (through the AST)
- [ ] parse `check if` conditions
- [ ] parse `allow` / `deny` conditions
- [ ] implement verifier limits (facts count, iterations count, timeout)
- [ ] parse whole policies (with an associated quasiquoter)
- [ ] parse whole block (with an associated quasiquoter)
- [ ] move the modules under a `Crypto` namespace
- [ ] try building with cabal
