.PHONY: ghcid
ghcid:
	ghcid -l -c 'cabal repl'

.PHONY: ghcid-tests
ghcid-tests:
	ghcid -l -c 'cabal repl biscuit-servant-test' -T main

.PHONY: configure
configure:
	cabal configure --enable-tests --test-show-details=direct --disable-optimization

.PHONY: build
build:
	cabal build -j all
