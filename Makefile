.PHONY: help install dev test cov demo serve report lint clean

help:
	@echo "Wyvern — passive AI-worm network sentinel"
	@echo "  make install   install runtime dependencies"
	@echo "  make dev       install runtime + dev dependencies (editable)"
	@echo "  make test      run the test suite"
	@echo "  make cov       run tests with coverage report"
	@echo "  make demo      run the synthetic worm scenario + print report"
	@echo "  make serve     run the simulation and open the dashboard"
	@echo "  make report    print the current threat assessment"
	@echo "  make clean     remove caches and runtime data"

install:
	python3 -m pip install -r requirements.txt

dev:
	python3 -m pip install -e ".[dev,desktop]"

test:
	python3 -m pytest

cov:
	python3 -m coverage run -m pytest && python3 -m coverage report --include="wyvern/*"

demo:
	python3 -m wyvern --data-dir ./wyvern-data simulate

serve:
	python3 -m wyvern --data-dir ./wyvern-data simulate --web

report:
	python3 -m wyvern --data-dir ./wyvern-data report

clean:
	rm -rf .pytest_cache .coverage htmlcov **/__pycache__ wyvern-data
