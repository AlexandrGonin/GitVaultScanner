"""
docker_utils.py - docker image handling utilities
"""

import json
import os
import shutil
import subprocess
import tarfile

from core.exceptions import DockerPullError


def image_exists_locally(image_name: str) -> bool:
    """check if image exists locally"""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def pull_docker_image(image_name: str, target_dir: str) -> str:
    """
    pull a docker image and save it as tar
    if image exists locally, use local image
    returns path to image tar file
    """
    safe_name = image_name.replace("/", "_").replace(":", "_").replace(".", "_")
    image_path = os.path.join(target_dir, f"{safe_name}.tar")

    local_image = image_exists_locally(image_name)

    try:
        if local_image:
            print(f"[*] using local image: {image_name}")
            subprocess.run(
                ["docker", "save", image_name, "-o", image_path],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
        else:
            print(f"[*] pulling image from registry: {image_name}")
            subprocess.run(
                ["docker", "pull", image_name],
                check=True,
                capture_output=True,
                text=True,
                timeout=600,
            )
            subprocess.run(
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
    supports both old format (layer.tar) and new OCI format
    returns path to extracted filesystem
    """
    os.makedirs(extract_path, exist_ok=True)

    # create a temp dir for initial extraction
    temp_extract = os.path.join(extract_path, "_temp")
    os.makedirs(temp_extract, exist_ok=True)

    # directory for merged filesystem
    root_fs = os.path.join(extract_path, "rootfs")
    os.makedirs(root_fs, exist_ok=True)

    try:
        with tarfile.open(image_tar_path, "r") as tar:
            tar.extractall(temp_extract)

        # check for manifest.json
        manifest_path = os.path.join(temp_extract, "manifest.json")
        if not os.path.exists(manifest_path):
            # try old format with manifest in different location
            manifest_path = os.path.join(temp_extract, "manifest.json")

        if os.path.exists(manifest_path):
            with open(manifest_path, "r") as f:
                manifests = json.load(f)

            # extract all layers
            layer_index = 0
            for manifest in manifests:
                # get layers from manifest
                layers = manifest.get("Layers", [])
                if not layers:
                    # try alternative field names
                    layers = manifest.get("layers", [])

                for layer_file in layers:
                    layer_path = os.path.join(temp_extract, layer_file)

                    # handle OCI format where layers might be in blobs
                    if not os.path.exists(layer_path) and "blobs" in layer_file:
                        # convert blob path
                        blob_parts = layer_file.split("/")
                        if len(blob_parts) >= 3:
                            blob_path = os.path.join(
                                temp_extract, "blobs", blob_parts[-2], blob_parts[-1]
                            )
                            if os.path.exists(blob_path):
                                layer_path = blob_path

                    if os.path.exists(layer_path):
                        layer_dir = os.path.join(
                            extract_path, f"layer_{layer_index:03d}"
                        )
                        os.makedirs(layer_dir, exist_ok=True)
                        try:
                            with tarfile.open(layer_path, "r") as layer_tar:
                                layer_tar.extractall(layer_dir)

                            # merge this layer into rootfs
                            for item in os.listdir(layer_dir):
                                src = os.path.join(layer_dir, item)
                                dst = os.path.join(root_fs, item)
                                if os.path.isdir(src):
                                    shutil.copytree(src, dst, dirs_exist_ok=True)
                                else:
                                    shutil.copy2(src, dst)

                            layer_index += 1
                        except Exception:
                            pass

        # if no manifest, try to find layer.tar files directly
        if not os.path.exists(manifest_path):
            for root, dirs, files in os.walk(temp_extract):
                for file in files:
                    if file.endswith(".tar") and file != os.path.basename(
                        image_tar_path
                    ):
                        layer_path = os.path.join(root, file)
                        layer_dir = os.path.join(
                            extract_path, f"layer_{len(os.listdir(extract_path)):03d}"
                        )
                        os.makedirs(layer_dir, exist_ok=True)
                        try:
                            with tarfile.open(layer_path, "r") as layer_tar:
                                layer_tar.extractall(layer_dir)

                            # merge into rootfs
                            for item in os.listdir(layer_dir):
                                src = os.path.join(layer_dir, item)
                                dst = os.path.join(root_fs, item)
                                if os.path.isdir(src):
                                    shutil.copytree(src, dst, dirs_exist_ok=True)
                                else:
                                    shutil.copy2(src, dst)
                        except Exception:
                            pass
        return root_fs

    except Exception as e:
        raise DockerPullError(f"failed to extract image layers: {str(e)}")
    finally:
        # clean up temp directory
        try:
            shutil.rmtree(temp_extract, ignore_errors=True)
        except Exception:
            pass
