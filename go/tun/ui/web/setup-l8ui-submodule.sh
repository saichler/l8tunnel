#!/usr/bin/env bash
set -e

REPO_URL="https://github.com/saichler/l8ui.git"
SUBMODULE_PATH="l8ui"

# Must be run from the web directory (where l8ui/ lives)
if [ ! -d "../../../.." ] || [ "$(basename "$(pwd)")" != "web" ]; then
    echo "ERROR: Run this script from the web directory (e.g., go/erp/ui/web/)"
    exit 1
fi

# Find the git root
GIT_ROOT=$(git rev-parse --show-toplevel)
REL_PATH=$(realpath --relative-to="$GIT_ROOT" "$PWD/$SUBMODULE_PATH")

echo "Git root: $GIT_ROOT"
echo "Submodule path: $REL_PATH"

# Step 1: Remove existing l8ui if tracked by git
if git ls-files --error-unmatch "$SUBMODULE_PATH" &>/dev/null; then
    echo "Removing tracked l8ui directory..."
    git rm -rf "$SUBMODULE_PATH"
    git commit -m "Remove l8ui directory before adding as submodule"
elif [ -d "$SUBMODULE_PATH" ]; then
    echo "Removing untracked l8ui directory..."
    rm -rf "$SUBMODULE_PATH"
fi

# Step 2: Clean up any leftover submodule state
if [ -d "$GIT_ROOT/.git/modules/$REL_PATH" ]; then
    echo "Cleaning leftover submodule cache..."
    rm -rf "$GIT_ROOT/.git/modules/$REL_PATH"
fi

# Remove stale .gitmodules entry if present
if [ -f "$GIT_ROOT/.gitmodules" ] && grep -q "$REL_PATH" "$GIT_ROOT/.gitmodules"; then
    echo "Removing stale .gitmodules entry..."
    git submodule deinit -f "$REL_PATH" 2>/dev/null || true
    git rm -f "$GIT_ROOT/.gitmodules" 2>/dev/null || true
    rm -rf "$GIT_ROOT/.git/modules/$REL_PATH" 2>/dev/null || true
    git commit -m "Clean up stale submodule state" 2>/dev/null || true
fi

# Step 3: Add the submodule
echo "Adding l8ui submodule..."
cd "$GIT_ROOT"
git submodule add "$REPO_URL" "$REL_PATH"

# Step 4: Verify
echo "Verifying..."
git submodule status "$REL_PATH"
ls "$REL_PATH/" | head -5

# Step 5: Commit
git add .gitmodules "$REL_PATH"
git commit -m "Add l8ui as git submodule

Replaces the copied l8ui directory with a git submodule pointing to
$REPO_URL to enable shared development across projects."

echo ""
echo "Done! l8ui submodule added successfully."
