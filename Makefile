init: ## Set up git hooks properly - needs calling once
	git config core.hooksPath .githooks

deps: ## Install the dependencies of the backend
	@cabal build all --only-dependencies

build: ## Build the project in fast mode
	@cabal build all

test: ## Build and run the test suite
	@cabal repl --with-ghc=doctest
	@cabal test all

clean: ## Remove compilation artifacts
	@cabal clean 

repl: ## Start a REPL
	@cabal repl --repl-options -fobject-code

lint: ## Run the code linter (HLint)
	@find src test -name "*.hs" | xargs -P $(PROCS) -I {} hlint --refactor-options="-i" --refactor {}

style: ## Run the code formatter (fourmolu, cabal-fmt)
	@cabal-gild --io one-time-password.cabal
	@fourmolu -q --mode inplace test src

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.* ?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

PROCS := $(shell nproc)

.PHONY: all $(MAKECMDGOALS)

.DEFAULT_GOAL := help
