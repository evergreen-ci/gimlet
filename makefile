# start project configuration
name := gimlet
buildDir := build
packages := $(name) acl ldap okta rolemanager
compilePackages := $(subst $(name),,$(subst -,/,$(foreach target,$(packages),./$(target))))
orgPath := github.com/evergreen-ci
projectPath := $(orgPath)/$(name)
# end project configuration

# start environment setup
gobin := go
ifneq (,$(GOROOT))
gobin := $(GOROOT)/bin/go
endif

ifeq ($(OS),Windows_NT)
gobin := $(shell cygpath $(gobin))
export GOCACHE := $(shell cygpath -m $(abspath $(buildDir)/.cache))
export GOLANGCI_LINT_CACHE := $(shell cygpath -m $(abspath $(buildDir)/.lint-cache))
export GOPATH := $(shell cygpath -m $(GOPATH))
export GOROOT := $(shell cygpath -m $(GOROOT))
endif

export GO111MODULE := off
# end environment setup

# Ensure the build directory exists, since most targets require it.
$(shell mkdir -p $(buildDir))

# start lint setup targets
lintDeps := $(buildDir)/run-linter $(buildDir)/golangci-lint
$(buildDir)/golangci-lint:
	@curl --retry 10 --retry-max-time 60 -sSfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(buildDir) v1.40.0 >/dev/null 2>&1
$(buildDir)/run-linter: cmd/run-linter/run-linter.go $(buildDir)/golangci-lint
	@$(gobin) build -o $@ $<
# end lint setup targets

# start output files
testOutput := $(subst -,/,$(foreach target,$(packages),$(buildDir)/output.$(target).test))
lintOutput := $(subst -,/,$(foreach target,$(packages),$(buildDir)/output.$(target).lint))
coverageOutput := $(subst -,/,$(foreach target,$(packages),$(buildDir)/output.$(target).coverage))
coverageHtmlOutput := $(subst -,/,$(foreach target,$(packages),$(buildDir)/output.$(target).coverage.html))
.PRECIOUS: $(testOutput) $(lintOuptut) $(coverageOutput) $(coverageHtmlOutput)
# end output files

# start basic development operations
lint: $(lintOutput)
compile:
	$(gobin) build $(compilePackages)
test: $(testOutput)
coverage: $(coverageOutput)
coverage-html: $(coverageHtmlOutput)
phony := compile test coverage coverage-html

# start convenience targets for running tests and coverage tasks on a
# specific package.
test-%: $(buildDir)/output.%.test
	@grep -s -q -e "^PASS" $<
coverage-%: $(buildDir)/output.%.coverage

html-coverage-%: $(buildDir)/output.%.coverage.html
	
lint-%: $(buildDir)/output.%.lint
	@grep -v -s -q "^--- FAIL" $<
# end convenience targets
# end basic development operations

# start test and coverage artifacts
testArgs := -v
ifeq (,$(DISABLE_COVERAGE))
testArgs += -cover
endif
ifneq (,$(RACE_DETECTOR))
testArgs += -race
endif
ifneq (,$(RUN_TEST))
testArgs += -run='$(RUN_TEST)'
endif
ifneq (,$(RUN_COUNT))
testArgs += -count=$(RUN_COUNT)
endif
ifneq (,$(TEST_TIMEOUT))
testArgs += -timeout=$(TEST_TIMEOUT)
endif
$(buildDir)/output.%.coverage: .FORCE
	$(gobin) test $(testArgs) ./$(if $(subst $(name),,$*),$(subst -,/,$*),) -covermode=count -coverprofile $@ | tee $(buildDir)/output.$*.test
	@-[ -f $@ ] && $(gobin) tool cover -func=$@ | sed 's%$(projectPath)/%%' | column -t
$(buildDir)/output.%.coverage.html: $(buildDir)/output.%.coverage .FORCE
	$(gobin) tool cover -html=$< -o $@
$(buildDir)/output.%.test: .FORCE
	$(gobin) test $(testArgs) ./$(if $(subst $(name),,$*),$(subst -,/,$*),) | tee $(buildDir)/output.$(subst /,-,$*).test

ifneq (go,$(gobin))
# We have to handle the PATH specially for linting in CI, because if the PATH has a different version of the Go
# binary in it, the linter won't work properly.
lintEnvVars := PATH="$(shell dirname $(gobin)):$(PATH)"
endif
$(buildDir)/output.%.lint: $(buildDir)/run-linter .FORCE
	@$(lintEnvVars) ./$< --output=$@ --lintBin=$(buildDir)/golangci-lint --packages='$*'
# end test and coverage artifacts

# start vendoring configuration
vendor-clean:
	rm -rf vendor/github.com/mongodb/grip/vendor/github.com/pkg/
	rm -rf vendor/github.com/mongodb/grip/vendor/github.com/stretchr/
	rm -rf vendor/gopkg.in/asn1-ber.v1/tests/
	rm -rf vendor/github.com/rs/cors/examples/
	find vendor/ -name "*.gif" -o -name "*.gz" -o -name "*.png" -o -name "*.ico" -o -name "*.dat" -o -name "*testdata" | xargs rm -rf
	find vendor/ -type d -name '.git' | xargs rm -rf
phony += vendor-clean
# end vendoring tooling configuration

# start mongodb targets
mongodb/.get-mongodb:
	rm -rf mongodb
	mkdir -p mongodb
	cd mongodb && curl "$(MONGODB_URL)" -o mongodb.tgz && $(DECOMPRESS) mongodb.tgz && chmod +x ./mongodb-*/bin/*
	cd mongodb && mv ./mongodb-*/bin/* . && rm -rf db_files && rm -rf db_logs && mkdir -p db_files && mkdir -p db_logs
get-mongodb: mongodb/.get-mongodb
	@touch $<
start-mongod: mongodb/.get-mongodb
	./mongodb/mongod --dbpath ./mongodb/db_files --port 27017 --replSet evg --smallfiles --oplogSize 10
	@echo "waiting for mongod to start up"
init-rs: mongodb/.get-mongodb
	./mongodb/mongo --eval 'rs.initiate()'
check-mongod: mongodb/.get-mongodb
	./mongodb/mongo --nodb --eval "assert.soon(function(x){try{var d = new Mongo(\"localhost:27017\"); return true}catch(e){return false}}, \"timed out connecting\")"
	@echo "mongod is up"
phony += get-mongodb start-mongod init-rs check-mongod
# end mongodb targets

# start cleanup targets
clean:
	rm -rf $(buildDir)
clean-results:
	rm -rf $(buildDir)/output.*
phony += clean clean-results
# end cleanup targets

# configure phony targets
.FORCE:
.PHONY: $(phony)
