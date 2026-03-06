"""
git_utils.py - git repository handling utilities
"""

import os
import subprocess

from core.exceptions import GitCloneError


def clone_repository(repo_url: str, target_dir: str) -> str:
    """
    clone a git repository to target directory
    returns path to cloned repository
    """
    # extract repo name from url
    repo_name = repo_url.split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    repo_path = os.path.join(target_dir, repo_name)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, repo_path],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )
    except subprocess.CalledProcessError as e:
        raise GitCloneError(f"failed to clone {repo_url}: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise GitCloneError(f"timeout cloning {repo_url}")

    return repo_path


def get_repo_info(repo_path: str) -> dict:
    """get information about a local repository"""
    info = {"path": repo_path, "branch": "unknown", "commit": "unknown", "remote": None}

    try:
        # get current branch
        branch = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        info["branch"] = branch.stdout.strip()

        # get latest commit
        commit = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        info["commit"] = commit.stdout.strip()

        # get remote url
        remote = subprocess.run(
            ["git", "-C", repo_path, "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
        )
        if remote.returncode == 0:
            info["remote"] = remote.stdout.strip()

    except Exception:
        pass

    return info
