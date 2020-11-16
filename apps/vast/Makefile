colon := :
$(colon) := :

.PHONY: all
all: format build dist test

.PHONY: format
format:
	python -m black .

.PHONY: test
test: unit-tests integration-tests

.PHONY: unit-tests
unit-tests:
	python -m unittest discover .

.PHONY: clean
clean:
	-find . -type d -name "*egg-info" -exec ${RM} -r {} \;
	-find . -type d -name "__pycache__" -exec ${RM} -r {} \;
	-${RM} -r build

.PHONY: build
build:
	python setup.py build

.PHONY: dist
dist:
	python setup.py sdist bdist_wheel

.PHONY: install
install:
	python setup.py install

.PHONY: dev-mode
dev-mode:
	python setup.py develop
