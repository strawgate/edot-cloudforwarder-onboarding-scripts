.PHONY: help lint check typecheck test setup

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

setup: ## Install development dependencies
	uv sync --dev

lint: ## Format code and auto-fix linting issues
	uv run ruff format .
	uv run ruff check --fix .

check: ## Check formatting and linting (fails on changes, for CI)
	uv run ruff format --check .
	uv run ruff check .

typecheck: ## Run type checking
	uv run basedpyright src

test: ## Run tests
	uv run pytest
