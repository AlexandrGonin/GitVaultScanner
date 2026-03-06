#!/bin/bash
# download_test_repos.sh - download public repos for testing

set -e

REPOS_DIR="testing_data/repos"
mkdir -p "$REPOS_DIR"

echo "downloading test repositories..."

# small python repos with known security issues
REPOS=(
    "https://github.com/vulhub/vulhub.git"
    "https://github.com/terraform-aws-modules/terraform-aws-eks.git"
    "https://github.com/docker-library/python.git"
)

for repo in "${REPOS[@]}"; do
    repo_name=$(basename "$repo" .git)
    target="$REPOS_DIR/$repo_name"

    if [ -d "$target" ]; then
        echo "updating $repo_name..."
        cd "$target"
        git pull
        cd - > /dev/null
    else
        echo "cloning $repo_name..."
        git clone --depth 1 "$repo" "$target"
    fi
done

echo "done. repos saved in $REPOS_DIR"
