"""
docker_utils.py - docker image handling utilities
"""

import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from core.exceptions import DockerPullError


def pull_docker_image(image_name: str, target_dir: str) -> str:
    """
    pull a docker image and save it as tar
    returns path to image tar file
    """
    # create safe filename from image name
    safe_name = image_name.replace("/", "_").replace(":", "_")
    image_path = os.path.join(target_dir, f"{safe_name}.tar")

    try:
        # pull the image
        pull_result = subprocess.run(
            ["docker", "pull", image_name],
            check=True,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
        )

        # save image to tar
        save_result = subprocess.run(
            ["docker", "save", image_name, "-o", image_path],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )

    except subprocess.CalledProcessError as e:
        raise DockerPullError(f"failed to pull/save {image_name}: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise DockerPullError(f"timeout pulling {image_name}")

    return image_path


def extract_image_layers(image_tar_path: str, extract_path: str) -> str:
    """
    extract docker image layers to a directory
    returns path to extracted filesystem
    """
    os.makedirs(extract_path, exist_ok=True)

    try:
        with tarfile.open(image_tar_path, "r") as tar:
            tar.extractall(extract_path)

        # find and extract layer tars
        for item in os.listdir(extract_path):
            item_path = os.path.join(extract_path, item)

            # look for layer.tar files
            if os.path.isfile(item_path) and item.endswith(".tar"):
                layer_dir = os.path.join(extract_path, item.replace(".tar", "_layer"))
                os.makedirs(layer_dir, exist_ok=True)

                with tarfile.open(item_path, "r") as layer_tar:
                    layer_tar.extractall(layer_dir)

    except Exception as e:
        raise DockerPullError(f"failed to extract image layers: {str(e)}")

    # find the root filesystem (usually in a directory with layer files)
    root_fs = extract_path
    for root, dirs, files in os.walk(extract_path):
        if "etc" in dirs and "bin" in dirs:
            root_fs = root
            break

    return root_fs


def list_image_layers(image_name: str) -> list:
    """list layers of a docker image"""
    try:
        result = subprocess.run(
            ["docker", "history", "--no-trunc", image_name],
            check=True,
            capture_output=True,
            text=True,
        )

        layers = []
        for line in result.stdout.split("\n")[1:]:  # skip header
            if line.strip():
                layers.append(line.strip())

        return layers

    except Exception:
        return []
