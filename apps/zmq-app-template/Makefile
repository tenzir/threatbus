colon := :
$(colon) := :

.PHONY: all
all: format build dist test

.PHONY: format
format:
	python -m black .

.PHONY: test
test: unit-tests

.PHONY: unit-tests
unit-tests:
	python -m unittest discover .

.PHONY: clean
clean:
	${RM} -r __pycache__ *egg-info build dist

.PHONY: build
build:
	python setup.py build

.PHONY: dist
dist:
	python setup.py sdist bdist_wheel

.PHONY: install
install:
	pip install .

.PHONY: dev-mode
dev-mode:
	pip install ../..
	pip install --editable .
