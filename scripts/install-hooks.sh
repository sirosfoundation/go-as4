#!/bin/bash
# Install git hooks for go-as4 development
# Run: ./scripts/install-hooks.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks..."

# Install pre-commit hook
if [ -f "$SCRIPT_DIR/pre-commit" ]; then
    ln -sf "../../scripts/pre-commit" "$HOOKS_DIR/pre-commit"
    chmod +x "$SCRIPT_DIR/pre-commit"
    echo "✓ Installed pre-commit hook"
fi

# Install pre-push hook
if [ -f "$SCRIPT_DIR/pre-push" ]; then
    ln -sf "../../scripts/pre-push" "$HOOKS_DIR/pre-push"
    chmod +x "$SCRIPT_DIR/pre-push"
    echo "✓ Installed pre-push hook"
fi

echo ""
echo "Git hooks installed successfully!"
echo ""
echo "Alternatively, you can use pre-commit framework:"
echo "  pip install pre-commit"
echo "  pre-commit install"
echo "  pre-commit install --hook-type pre-push"
