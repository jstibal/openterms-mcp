.PHONY: run test docker clean quickstart

# Run the server locally
run:
	python run.py

# Run all tests (120)
test:
	python -m unittest tests.test_core tests.test_mvp3 -v

# Build and run with Docker
docker:
	docker compose up --build

# Clean database and cache files
clean:
	rm -f openterms.db
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# One-command quickstart: creates workspace, gets API key, issues first receipt
quickstart:
	@bash quickstart.sh
