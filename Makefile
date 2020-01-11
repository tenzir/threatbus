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
	python -m unittest discover

.PHONY: integration-tests
integration-tests:
	docker build -q . -t threatbus-integration-test
	docker run -td --name=tb-int --rm -p 47761:47761 threatbus-integration-test -c config_integration_test.yaml
	-python -m unittest tests/integration/test_zeek_inmem.py
	-${RM} {broker,intel,reporter,weird}.log
	docker kill tb-int