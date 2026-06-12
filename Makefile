# CI/CD tasks

.DEFAULT_GOAL := help

.PHONY: help deploy-clab-ci destroy-clab-ci deploy-clab-record destroy-clab-record run-tests record-fixtures dist release

TESTS := $(shell find test/ci -name '*.py')

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deploy-clab-ci: ## Deploy "ci" test topology
	cd .clab && sudo clab deploy -t ci-topology.yml --reconfigure

destroy-clab-ci: ## Destroy "ci" test topology
	cd .clab && sudo clab destroy -t ci-topology.yml --cleanup

deploy-clab-record: ## Deploy the two-node fixture-recording topology
	cd .clab && sudo clab deploy -t record-topology.yml --reconfigure

destroy-clab-record: ## Destroy the fixture-recording topology
	cd .clab && sudo clab destroy -t record-topology.yml --cleanup

run-tests: $(TESTS) ## Run all CI tests under test/ci (needs the "ci" topology)
	for test in $(TESTS); do \
		uv run $$test || exit 1; \
	done

record-fixtures: ## Re-record unit test fixtures (needs the recording topology)
	uv run tools/record_fixtures.py --prepare
	uv run tools/record_fixtures.py

dist: ## This creates a ./dist directory with wheel package
	uv build

release: dist ## release to PyPi
	uv publish
