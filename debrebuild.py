import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

from bs4 import BeautifulSoup
import debian.deb822
import requests
from flask import jsonify

import package_repo_api

# Configure logging
logger = logging.getLogger("debrebuild")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def setup_keyrings_in_docker():
    # List of specific keyring files to copy
    DEBIAN_KEYRINGS = [
        "debian-archive-bullseye-automatic.gpg",
        "debian-archive-bullseye-security-automatic.gpg",
        "debian-archive-bullseye-stable.gpg",
        "debian-archive-buster-automatic.gpg",
        "debian-archive-buster-security-automatic.gpg",
        "debian-archive-buster-stable.gpg",
        "debian-archive-keyring.gpg",
        "debian-archive-removed-keys.gpg",
        "debian-archive-stretch-automatic.gpg",
        "debian-archive-stretch-security-automatic.gpg",
        "debian-archive-stretch-stable.gpg",
        "debian-ports-archive-keyring-removed.gpg",
        "debian-ports-archive-keyring.gpg",
        "debian-keyring.gpg",
    ]

    # Directory name in the Docker container where keyrings will be stored
    container_keyring_dir = "/app/keyrings"

    # Command to create the keyrings directory inside the Docker container
    create_directory_command = f"mkdir -p {container_keyring_dir}"

    # Commands to copy each specific keyring file
    copy_commands = " && ".join(
        [f"cp /usr/share/keyrings/{keyring} {container_keyring_dir}/" for keyring in DEBIAN_KEYRINGS]
    )

    # Command to update APT sources.list to use these keyrings with the signed-by option
    # Here you'd specify your actual Debian mirror and distribution details
    setup_apt_sources_commands = " && ".join(
        [
            f'echo "deb [signed-by={container_keyring_dir}/{keyring}] http://deb.debian.org/debian bullseye main" > /etc/apt/sources.list.d/{keyring}.list'
            for keyring in DEBIAN_KEYRINGS]
    )

    # Full command to create directory, copy files, and update APT configuration
    full_command = f"{create_directory_command} && {copy_commands} && {setup_apt_sources_commands}"

    # Assemble the Docker command with the entire current directory mounted
    current_directory = os.getcwd()
    cmd = [
        'docker', 'run', '--rm', '-a', 'stdout', '-a', 'stderr',
        '-v', f'{current_directory}:/app',  # Mount the current directory to /app in the container
        '-v', '/usr/share/keyrings:/usr/share/keyrings',  # Mount the host's keyrings directory
        '-w', '/app',  # Set working directory to /app
        '--entrypoint', '/bin/zsh',
        'debrebuild',
        '-c', full_command  # Execute command to set up keyrings and APT configuration inside the container
    ]

    # Execute the Docker command
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("Running command in Docker:", ' '.join(cmd))
    print("Command output:", result.stdout)
    if result.stderr:
        print("Command error output:", result.stderr)

    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)


class PackageException(Exception):
    pass


class BuildInfoException(Exception):
    pass


class RebuilderException(Exception):
    pass


class RebuilderInTotoError(Exception):
    pass


class RebuilderChecksumsError(Exception):
    pass


DEFAULT_DOCKERFILE_CONTENT = """
FROM debian:stable

# Install necessary system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    sudo \
    debootstrap \
    schroot \
    python3 \
    python3-pip \
    python3-venv \
    python3-debian \
    python3-apt \
    git \
    build-essential \
    gnupg \
    curl \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    mmdebstrap \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Set up sudo privileges
RUN echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Set the working directory
WORKDIR /app

# Create a virtual environment
RUN python3 -m venv /app/venv

# Set the virtual environment path as the primary for all operations
ENV PATH="/app/venv/bin:$PATH"

# Optionally, add system site-packages to the PYTHONPATH
ENV PYTHONPATH="/usr/lib/python3/dist-packages:$PYTHONPATH"

# Upgrade pip to the latest version using the absolute path to ensure the correct pip is used
RUN /app/venv/bin/pip install --upgrade pip

# Install necessary Python libraries using the virtual environment’s pip
RUN /app/venv/bin/pip install requests beautifulsoup4 python-debian python-dateutil rstr google-auth httpx tenacity flask

# Copy all application files
COPY . /app

# Set permissions for the copied files
RUN chmod -R a+rX /app

# Ensure zsh is executable and set as the default shell
RUN chmod +x /bin/zsh
SHELL ["/bin/zsh", "-c"]

# Entry point
ENTRYPOINT ["/bin/zsh"]
"""

def write_dockerfile(dockerfile_content):
    with open('Dockerfile', 'w') as f:
        f.write(dockerfile_content)
    logger.debug("Dockerfile written.")


def build_docker_image():
    subprocess.run(['docker', 'build', '-t', 'debrebuild', '.'], check=True)
    logger.debug("Docker image built.")


def run_in_docker(command):
    # Assemble the Docker command
    cmd = [
        'docker', 'run', '--rm', '--privileged', '-a', 'stdout', '-a', 'stderr',
        #*volume_args,  # Spread the volume arguments
        '-w', '/app',  # Set working directory to /app inside the container
        '--entrypoint', '/bin/bash', 'debrebuild',  # Assuming bash is available and image name is debrebuild
        '-c', command  # Command to run inside Docker
    ]

    # Execute the Docker command
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("Running command in Docker:", ' '.join(cmd))
    print("Command output:", result.stdout)
    if result.stderr:
        print("Command error output:", result.stderr)

    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)


def create_directory_in_docker(directory_path):
    # Construct the command to create the directory
    command = f"mkdir -p {directory_path}"
    # Call the function to run this command in Docker
    run_in_docker(command)


def copy_to_docker(source, destination):
    current_directory = os.getcwd()

    # Ensure the source file path is correct
    source_path = os.path.join(current_directory, source)

    # Check if the source file exists
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"The source file does not exist: {source_path}")

    # Assemble the Docker command to copy the file
    cmd = [
        'docker', 'run', '--rm', '--privileged', '-a', 'stdout', '-a', 'stderr',
        '-v', f"{current_directory}:/app/host",  # Mount the current directory to /app/host
        '--entrypoint', '/bin/bash', 'debrebuild',  # Using bash as the entrypoint and debrebuild as the image name
        '-c', f"cp /app/host/{source} /app/{destination}"  # Ensure the destination is correctly specified
    ]

    # Execute the Docker command
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Logging the command and results
    print("Copying file to Docker:", ' '.join(cmd))
    print("Command output:", result.stdout)
    if result.stderr:
        print("Command error output:", result.stderr)

    # Check if the command was successful
    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)


def copy_from_docker(source, destination):
    current_directory = os.getcwd()

    # Ensure the destination file path is correct
    destination_path = os.path.join(current_directory, destination)

    # Assemble the Docker command to copy the file
    cmd = [
        'docker', 'run', '--rm', '--privileged', '-a', 'stdout', '-a', 'stderr',
        '-v', f"{current_directory}:/app/host",  # Mount the current directory to /app/host
        '--entrypoint', '/bin/bash', 'debrebuild',  # Assuming bash is available and image name is debrebuild
        '-c', f"cp {source} /app/host/{destination}"  # Command to copy the file inside Docker
    ]

    # Execute the Docker command
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("Copying file from Docker:", ' '.join(cmd))
    print("Command output:", result.stdout)
    if result.stderr:
        print("Command error output:", result.stderr)

    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)


def run_python_in_docker(command, artifacts_dir):
    current_directory = os.getcwd()
    build_checkpoint_path = os.path.join(current_directory, 'build_checkpoint')
    output_directory_path = os.path.join(build_checkpoint_path, artifacts_dir)
    package_repo_path = "/home/arun/Desktop/other/package_repo"  # Adjust this path as needed

    # Ensure both the general build_checkpoint directory and the specific output directory are mounted
    volume_mounts = [
        f"{build_checkpoint_path}:/app/build_checkpoint",  # Mount the whole build_checkpoint directory
        f"{output_directory_path}:/app/build_checkpoint/{artifacts_dir}",  # Mount the specific artifacts directory
        f"{package_repo_path}:/app/package_repo"  # Mount the package repository directory inside the container
    ]

    # Assemble the Docker command with volume mounts
    cmd = [
        'docker', 'run', '--rm', '--privileged', '-a', 'stdout', '-a', 'stderr',
        '-v', volume_mounts[0],  # Mount the general build_checkpoint directory
        '-v', volume_mounts[1],  # Mount the specific output directory
        '-v', volume_mounts[2],  # Mount the package repository directory
        '-w', '/app',  # Set working directory to /app inside the container
        '--entrypoint', '/bin/bash', 'debrebuild',  # Using bash and debrebuild as the image name
        '-c', f"source /app/venv/bin/activate && python3 {command}"  # Activate venv and run the specified Python command
    ]

    # Execute the Docker command
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("Running command in Docker:", ' '.join(cmd))
    print("Command output:", result.stdout)
    if result.stderr:
        print("Command error output:", result.stderr)

    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)

def debug_docker():
    logger.debug("Starting Docker container in interactive mode for debugging...")
    subprocess.run(['docker', 'run', '--rm', '-it', '-v', f'{os.getcwd()}:/app', '-w', '/app', 'debrebuild', 'bash'],
                   check=True)


def setup_directories():
    if not os.path.exists('temp_apt_cache'):
        os.makedirs('temp_apt_cache')
    if not os.path.exists('chroot_env'):
        os.makedirs('chroot_env')
    logger.debug("Directories setup complete.")


def setup_directories_in_docker():
    # Bash commands to create directories inside the Docker container
    command = "mkdir -p /app/temp_apt_cache /app/chroot_env && echo 'Directories setup complete.'"

    # Run the command inside Docker
    run_in_docker(command)


def initialize_configurations():
    os.environ['APT_CACHE_DIR'] = os.path.abspath('temp_apt_cache')
    os.environ['CHROOT_ENV'] = os.path.abspath('chroot_env')
    logger.debug("Configurations initialized.")


def initialize_configurations_in_docker():
    command = "export APT_CACHE_DIR=/app/temp_apt_cache && export CHROOT_ENV=/app/chroot_env && echo $APT_CACHE_DIR && echo $CHROOT_ENV"
    run_in_docker(command)


def install_core_dependencies():
    max_retries = 10
    delay = 5  # seconds

    for attempt in range(max_retries):
        try:
            result = subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True, text=True)
            break
        except subprocess.CalledProcessError as e:
            stderr_output = e.stderr if e.stderr else ""
            if "E: Unable to lock directory /var/lib/apt/lists/" in stderr_output:
                logger.warning(f"Attempt {attempt + 1}/{max_retries}: APT lock is held, retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                raise e
    else:
        raise RebuilderException("Failed to acquire APT lock after multiple attempts")

def prepare_execution_environment():
    chroot_env = os.environ['CHROOT_ENV']

    # Clean the target directory with sudo
    if os.path.exists(chroot_env):
        subprocess.run(['sudo', 'rm', '-rf', chroot_env], check=True)
    os.makedirs(chroot_env)

    subprocess.run(['sudo', 'debootstrap', '--variant=minbase', 'stable', chroot_env], check=True)
    logger.debug("Execution environment prepared.")


def prepare_execution_environment_in_docker():
    # Bash commands to clean and prepare the chroot environment inside the Docker container
    chroot_env = "/app/chroot_env"  # Ensure this matches with Docker's internal paths used in other functions
    command = (f"rm -rf {chroot_env} && mkdir -p {chroot_env} && debootstrap --variant=minbase stable {chroot_env} "
               f"&& echo 'Execution environment prepared.'")

    # Run the command inside Docker
    run_in_docker(command)


def bootstrap_build_base_system():
    setup_directories_in_docker()
    initialize_configurations_in_docker()
    install_core_dependencies()
    prepare_execution_environment_in_docker()
    logger.debug("Build base system bootstrapped successfully.")


def get_source_name_from_buildinfo(buildinfo_file):
    with open(buildinfo_file) as fd:
        parsed_info = debian.deb822.BuildInfo(fd)
        source_name, _ = parsed_info.get_source()
    return source_name

def prepare_volume(directory_name):
    current_directory = os.getcwd()
    path = os.path.join(current_directory, directory_name)

    # Ensure the directory exists
    if not os.path.exists(path):
        os.makedirs(path)
        logger.debug(f"'{directory_name}' directory created at: {path}")

    return f"{path}:/app/{directory_name}"


def run_docker_container(output_dir):
    build_checkpoint_volume = prepare_volume('build_checkpoint')
    output_dir_volume = prepare_volume(output_dir)

    # Docker command to create a test file in each mounted directory
    cmd = [
        'docker', 'run', '--rm', '-a', 'stdout', '-a', 'stderr',
        '--privileged',  # Run the container with extended privileges
        '-v', build_checkpoint_volume,  # Mount the build_checkpoint directory
        '-v', output_dir_volume,  # Mount the output_dir directory
        '-w', '/app',  # Set working directory to /app
        '--entrypoint', '/bin/bash', 'debrebuild',  # Use bash in the debrebuild image
        '-c', f"touch /app/build_checkpoint/test_file.txt && echo 'Test content' > /app/build_checkpoint/test_file.txt && \
               ls -l /app/build_checkpoint /app/{output_dir}"  # Create and list test files
    ]

    # Execute the Docker command
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.debug("Running command in Docker:", ' '.join(cmd))
    logger.debug("Command output:", result.stdout)
    if result.stderr:
        logger.error("Command error output:", result.stderr)

    if result.returncode != 0:
        logger.debug(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)


def create_persistent_json_file(builder_args):
    # Use the current directory or a specific path to store the JSON file
    current_directory = os.getcwd()
    json_file_path = os.path.join(current_directory, "persistent_args.json")

    # Remove the existing persistent_args.json file if it exists
    if os.path.exists(json_file_path):
        os.remove(json_file_path)
        logger.debug(f"Removed existing file: {json_file_path}")

    # Create a JSON file with example data in the current directory
    with open(json_file_path, 'w') as jf:
        json.dump(builder_args, jf)

    # Print the file path and confirm the contents of the file
    logger.debug(f"Persistent JSON file path: {json_file_path}")
    with open(json_file_path, 'r') as jf:
        file_contents = json.load(jf)
        logger.debug("Contents of the persistent JSON file:")
        logger.debug(json.dumps(file_contents, indent=4))
def run_shell_command(command):
    result = subprocess.run(command, shell=True, capture_output=True)
    if result.returncode != 0:
        logger.error(f"Command failed with error: {result.stderr.decode().strip()}")
        raise subprocess.CalledProcessError(result.returncode, command)

def ignore_errors(func, path, exc_info):
    logger.warning(f"Ignoring error: {exc_info} for path: {path}")

def archive_and_cleanup_checkpoint(checkpoint_dir):
    # Create the archive directory and timestamped subdirectory
    archive_dir = os.path.join(os.getcwd(), "archive")
    if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamped_dir = os.path.join(archive_dir, timestamp)

    # Ensure the timestamped directory does not exist
    if not os.path.exists(timestamped_dir):
        os.makedirs(timestamped_dir)
    else:
        logger.error(f"Timestamped directory already exists: {timestamped_dir}")
        raise FileExistsError(f"Timestamped directory already exists: {timestamped_dir}")

    # Copy the contents of the build_checkpoint directory to the timestamped directory
    try:
        shutil.copytree(checkpoint_dir, timestamped_dir, dirs_exist_ok=True, ignore_dangling_symlinks=True)
    except shutil.Error as e:
        logger.warning(f"Encountered errors during copytree: {e}")
        for src, dst, error in e.args[0]:
            logger.warning(f"Error copying {src} to {dst}: {error}")
            if isinstance(error, FileNotFoundError):
                continue
            else:
                raise

    # Remove the build_checkpoint directory
    try:
        shutil.rmtree(checkpoint_dir, onerror=ignore_errors)
    except PermissionError as e:
        logger.warning(f"PermissionError: {e}. Trying with sudo.")
        run_shell_command(f"sudo rm -rf {checkpoint_dir}")

    logger.debug("Build checkpoint archived and removed successfully.")

def run(builder_args):
    logger.debug("Starting the run function")

    continue_from_checkpoint = builder_args.get("continue_from_checkpoint")
    output_dir = builder_args["output_dir"]


    buildinfo_file_path = builder_args["buildinfo_file"]
    with open(buildinfo_file_path) as fd:
        parsed_info = debian.deb822.BuildInfo(fd)

    source, source_version = parsed_info.get_source()

    version = parsed_info["version"]

    if is_source_package_info_required(builder_args, source, version):
        logger.error(f"Unable to find URLs automatically, "
                     f"Please provide source package information "
                     f"(--dsc_url, --orig_tar_url, --debian_tar_url) arguments and re-run.")
        return False

    if continue_from_checkpoint:
        build_checkpoint_dir = "build_checkpoint"
        logger.debug(f"Continuing from checkpoint: {continue_from_checkpoint}")

        if os.path.exists(build_checkpoint_dir):
            shutil.rmtree(build_checkpoint_dir)

        shutil.copytree(continue_from_checkpoint, build_checkpoint_dir, dirs_exist_ok=True, ignore_dangling_symlinks=True)
        logger.debug("Checkpoint copied to build_checkpoint directory")

    if not continue_from_checkpoint:
        bootstrap_build_base_system()
        setup_keyrings_in_docker()

        # List of packages to install
        packages = [
            'requests', 'beautifulsoup4', 'python-debian', 'python-dateutil', 'rstr', 'google-auth', 'httpx', 'tenacity'
        ]

        # Construct the command to create a virtual environment and install the packages
        venv_command = (
            "mkdir -p /app && "  # Ensure /app directory exists
            "apt-get update && apt-get install -y python3-pip python3-venv && "
            "rm -rf /app/venv && "  # Ensure any previous virtual environment is removed
            "python3 -m venv /app/venv && "
            "/app/venv/bin/pip install " + " ".join(packages)
        )

        # Run the virtual environment creation and package installation command in the Docker container
        run_in_docker(venv_command)

        create_persistent_json_file(builder_args)

        json_file_path = os.path.join(os.getcwd(), "persistent_args.json")
        try:
            run_python_in_docker(f"initialize_and_find_dependencies.py /app/{os.path.basename(json_file_path)}", output_dir)
        except Exception as e:
            logger.error("Error running command in Docker:", e)
            debug_docker()
            raise RebuilderException("Failed to initialize and find dependencies")

    source_name = get_source_name_from_buildinfo(builder_args["buildinfo_file"])
    checkpoint_dir = os.path.join("build_checkpoint", source_name)
    final_output_dir = os.path.join(checkpoint_dir, output_dir)

    # Create the output directory inside the Docker container
    create_directory_in_docker(final_output_dir)
    checkpoint_file = f"checkpoint_find_dep_{source_name}.json"
    checkpoint_json_path = os.path.join(checkpoint_dir, checkpoint_file)

    # if continue_from_checkpoint is not empty (it is set to a directory path (say archive/202428)
    # create a new directory build_checkpoint and copy all the contents from the above directory into this directory
    # and then continue
    try:
        run_python_in_docker(f"execute_build.py /app/{checkpoint_json_path} /app/{final_output_dir}", output_dir)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute build: {e}")
        debug_docker()
        raise RebuilderException("Failed to execute build")

    try:
        run_python_in_docker(f"post_build_actions.py /app/{checkpoint_json_path} /app/{final_output_dir}", output_dir)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to perform post-build actions: {e}")
        debug_docker()
        raise RebuilderException("Failed to perform post-build actions")

    logger.debug("Post-build actions completed successfully.")

    if not continue_from_checkpoint:
        # Archive and clean up the build checkpoint directory
        archive_and_cleanup_checkpoint("build_checkpoint")

def get_args():
    parser = argparse.ArgumentParser(
        description="Given a buildinfo file from a Debian package, generate instructions for attempting to reproduce the binary packages built from the associated source and build information."
    )
    parser.add_argument("buildinfo", help="Input buildinfo file. Local or remote file.")
    parser.add_argument("--output", help="Directory for the build artifacts")
    parser.add_argument("--builder", help="Which building software should be used. (default: none)", default="none")
    parser.add_argument("--query-url",
                        help="API url for querying package and binary information (default: http://snapshot.notset.fr).",
                        default="http://snapshot.notset.fr")
    parser.add_argument("--snapshot-mirror", help="Snapshot mirror to use (default: http://snapshot.notset.fr)",
                        default="http://snapshot.notset.fr")
    parser.add_argument("--metasnap-url", help="Metasnap service url (default: https://metasnap.debian.net).",
                        default="https://metasnap.debian.net")
    parser.add_argument("--use-metasnap",
                        help="Service to query the minimal set of timestamps containing all package versions referenced in a buildinfo file.",
                        action="store_true")
    parser.add_argument("--builder_json_file", help="Build process to resume from", default="")
    parser.add_argument("--extra-repository-file",
                        help="Add repository file content to the list of apt sources during the package build.",
                        action="append")
    parser.add_argument("--extra-repository-key",
                        help="Add key file (.asc) to the list of trusted keys during the package build.",
                        action="append")
    parser.add_argument("--gpg-sign-keyid", help="GPG keyid to use for signing in-toto metadata.")
    parser.add_argument("--gpg-verify", help="Verify buildinfo GPG signature.", action="store_true")
    parser.add_argument("--gpg-verify-key", help="GPG key to use for buildinfo GPG check.")
    parser.add_argument("--proxy", help="Proxy address to use.")
    parser.add_argument("--build-options-nocheck", action="store_true", help="Disable build tests.")
    parser.add_argument("--verbose", action="store_true", help="Display logger info messages.")
    parser.add_argument("--debug", action="store_true", help="Display logger debug messages.")
    parser.add_argument("--custom-deb", help="List of paths to custom .deb files to include in the build",
                        action="append")
    parser.add_argument("--build_env", help="Path to a custom Dockerfile to use for the build environment")
    parser.add_argument("--continue-from-checkpoint", help="Directory path to continue from a previous checkpoint")
    parser.add_argument("--dsc_url", help="URL for the .dsc file", default="")
    parser.add_argument("--orig_tar_url", help="URL for the original tarball", default="")
    parser.add_argument("--debian_tar_url", help="URL for the Debian tarball", default="")

    return parser.parse_args()

def realpath(path):
    return os.path.abspath(os.path.expanduser(path))

def is_source_available(source, source_version):
    """
    Check if the source package and version are available.
    """
    source_check_cmd = [
        "apt-get",
        "source",
        "--only-source",
        "-d",
        "{}={}".format(source, source_version)
    ]
    result = subprocess.run(source_check_cmd, capture_output=True, text=True)
    return result.returncode == 0

def fetch_debian_package_urls(package_name, version):
    print(f"package name is {package_name}")
    print(f"version name is {version}")
    base_url = "http://ftp.de.debian.org/debian/pool/main/"
    if package_name.startswith("lib"):
        package_url = f"{base_url}{package_name[:4]}/{package_name}/"
    else:
        package_url = f"{base_url}{package_name[0]}/{package_name}/"

    logger.debug(f"fetch_debian_package_urls has {package_url}")

    try:
        response = requests.get(package_url)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch the package page: {e}")
        return None, None, None

    soup = BeautifulSoup(response.text, 'html.parser')
    dsc_url = None
    orig_tar_url = None
    debian_tar_url = None

    for link in soup.find_all('a'):
        href = link.get('href')
        if href and href.endswith(f"{version}.dsc"):
            dsc_url = f"{package_url}{href}"
        elif href and href.endswith(".orig.tar.gz") and version.split('-')[0] in href:
            orig_tar_url = f"{package_url}{href}"
        elif href and href.endswith(f"{version}.debian.tar.xz"):
            debian_tar_url = f"{package_url}{href}"

    return dsc_url, orig_tar_url, debian_tar_url

def is_source_package_info_required(builder_args, source, source_version):
    """
    Check if the source is available, fetch it if not, and handle errors if fetching fails.
    """
    if not is_source_available(source, source_version):
        logger.debug("Source is unavailable")

        if not builder_args["dsc_url"] and not builder_args["debian_tar_url"] and not builder_args["orig_tar_url"]:
            dsc_url, orig_tar_url, debian_tar_url = fetch_debian_package_urls(source, source_version)

            if not dsc_url or not orig_tar_url or not debian_tar_url:
                logger.error(
                    "Unable to find URLs automatically. "
                    "Please provide source package information "
                    "(--dsc_url, --orig_tar_url, --debian_tar_url) arguments and re-run."
                )
                return True
        return False
    return False

def main():
    args = get_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.ERROR)

    if args.builder not in ("none", "mmdebstrap"):
        logger.error(f"Unknown builder: {args.builder}")
        return 1

    if args.gpg_verify_key:
        args.gpg_verify_key = realpath(args.gpg_verify_key)

    if args.extra_repository_file:
        args.extra_repository_file = [
            realpath(repo_file) for repo_file in args.extra_repository_file
        ]

    if args.extra_repository_key:
        args.extra_repository_key = [
            realpath(key_file) for key_file in args.extra_repository_key
        ]

    if args.gpg_verify and not args.gpg_verify_key:
        logger.error("Cannot verify buildinfo signature without GPG keyring provided")
        return 1

    if not args.output:
        logger.error("Please provide output directory")
        return 1

    try:
        rebuilder_args = {
            "buildinfo_file": args.buildinfo,
            "snapshot_url": args.query_url,
            "snapshot_mirror": args.snapshot_mirror,
            "extra_repository_files": args.extra_repository_file,
            "extra_repository_keys": args.extra_repository_key,
            "gpg_sign_keyid": args.gpg_sign_keyid,
            "gpg_verify": args.gpg_verify,
            "gpg_verify_key": args.gpg_verify_key,
            "proxy": args.proxy,
            "use_metasnap": args.use_metasnap,
            "metasnap_url": args.metasnap_url,
            "build_options_nocheck": args.build_options_nocheck,
            "builder_json_file": args.builder_json_file,
            "output_dir": args.output,
            "custom_deb": args.custom_deb,
            "continue_from_checkpoint": args.continue_from_checkpoint,
            "dsc_url": args.dsc_url,
            "orig_tar_url": args.orig_tar_url,
            "debian_tar_url": args.debian_tar_url,
        }

        if args.build_env:
            with open(args.build_env, 'r') as f:
                dockerfile_content = f.read()
        else:
            dockerfile_content = DEFAULT_DOCKERFILE_CONTENT

        write_dockerfile(dockerfile_content)
        build_docker_image()

        # Run the Python scripts inside the Docker container
        run(rebuilder_args)
    except RebuilderChecksumsError:
        # Handle specific exception
        try:
            subprocess.run("docker stop $(docker ps -q --filter 'ancestor=debrebuild')", shell=True, check=True)
            subprocess.run("docker rm $(docker ps -a -q --filter 'ancestor=debrebuild')", shell=True, check=True)
        except subprocess.CalledProcessError as cleanup_error:
            logger.error(f"Failed to cleanup Docker containers: {cleanup_error}")
        sys.exit(2)
    except RebuilderException as e:
        logger.error(str(e))
        # Handle specific exception
        try:
            subprocess.run("docker stop $(docker ps -q --filter 'ancestor=debrebuild')", shell=True, check=True)
            subprocess.run("docker rm $(docker ps -a -q --filter 'ancestor=debrebuild')", shell=True, check=True)
        except subprocess.CalledProcessError as cleanup_error:
            logger.error(f"Failed to cleanup Docker containers: {cleanup_error}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logger.error("Error running command in Docker: %s", e)
        try:
            subprocess.run("docker stop $(docker ps -q --filter 'ancestor=debrebuild')", shell=True, check=True)
            subprocess.run("docker rm $(docker ps -a -q --filter 'ancestor=debrebuild')", shell=True, check=True)
        except subprocess.CalledProcessError as cleanup_error:
            logger.error(f"Failed to cleanup Docker containers: {cleanup_error}")
        sys.exit(1)
    finally:
        # Ensure all debrebuild containers are removed in case of any other issues
        subprocess.run("docker ps -q --filter 'ancestor=debrebuild' | xargs -r docker stop", shell=True)
        subprocess.run("docker ps -a -q --filter 'ancestor=debrebuild' | xargs -r docker rm", shell=True)

if __name__ == "__main__":
    sys.exit(main())
