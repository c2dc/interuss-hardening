.PHONY: lint
lint: validate-docs

.PHONY: validate-docs
validate-docs: check-no-cross-reference
	./scripts/validate_test_definitions.sh
	./scripts/format_test_suite_docs.sh --lint

.PHONY: check-no-cross-reference
check-no-cross-reference:
	./scripts/check-netrid-cross-references.sh

.PHONY: format
format: format-documentation

.PHONY: format-documentation
format-documentation:
	./scripts/format_test_documentation.sh
	./scripts/format_test_suite_docs.sh

# NOTE: there is no `unit_test` target. The pytest suites it ran were removed
# when the project was trimmed to the local UTM test ecosystem, and pytest is no
# longer a declared dependency. The end-to-end gate is `test` below, plus the
# individual configurations under configurations/dev/.

# WARNING: destructive. This tears the whole local ecosystem down on entry AND
# on exit (make down-locally), then brings it up, runs configurations against it
# and tears it down again. Do not run it against an environment you are using.
.PHONY: test
test:
	./scripts/test_docker_fully_mocked.sh
