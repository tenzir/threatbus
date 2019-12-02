.PHONY: all
all: format test

.PHONY: install-dependencies
install-dependencies:
	python -m pip install -r requirements.txt

.PHONY: test
test:
	python -m unittest discover -s tests

.PHONY: format
format:
	python -m black .