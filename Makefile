TESTS=tests
UNIT=${TESTS}/unit
INTEGRATION=${TESTS}/integration

.PHONY: all
all: format test

.PHONY: install-dependencies
install-dependencies:
	python -m pip install -r requirements.txt

.PHONY: format
format:
	python -m black .

.PHONY: test
test: unit-tests integration-tests

.PHONY: unit-tests
unit-tests:
	python -m unittest discover -s ${UNIT}

.PHONY: integration-tests
integration-tests:
	python -m unittest discover -s ${INTEGRATION}