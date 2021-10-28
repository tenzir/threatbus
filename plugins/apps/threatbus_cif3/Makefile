colon := :
$(colon) := :

.PHONY: all
all: format build test update

.PHONY: format
format:
	poetry run black --check .

.PHONY: test
test: unit-tests

.PHONY: unit-tests
unit-tests:
	python -m unittest discover .

.PHONY: build
build:
	poetry build -vvv

.PHONY: install
install:
	poetry install

.PHONY: update
update:
	poetry update
