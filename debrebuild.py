import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import glob
from datetime import time

import debian.deb822

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
        [f'echo "deb [signed-by={container_keyring_dir}/{keyring}] http://deb.debian.org/debian bullseye main" > /etc/apt/sources.list.d/{keyring}.list'
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

def setup_custom_zgrep_in_docker():
    # Define the custom zgrep script content
    custom_zgrep_script = """
#!/bin/bash

# Custom zgrep to avoid process substitution issues
# Usage: zgrep -h -f <pattern_file> <compressed_files...>

if [ "$1" = "-h" ] && [ "$2" = "-f" ]; then
    pattern_file=$2
    shift 2
    tmp_pattern_file=$(mktemp)

    # Read the pattern from the input file descriptor and write it to a temporary file
    cat "$pattern_file" > "$tmp_pattern_file"

    # Execute the original zgrep with the temporary pattern file
    /bin/zgrep -h -f "$tmp_pattern_file" "$@"

    # Clean up the temporary file
    rm -f "$tmp_pattern_file"
else
    # Fallback to the original zgrep for other usages
    /bin/zgrep "$@"
fi
"""

    # Create a temporary script file to be copied into the Docker container
    script_path = os.path.join(os.getcwd(), "custom_zgrep.sh")
    with open(script_path, "w") as script_file:
        script_file.write(custom_zgrep_script)

    # Make the script executable
    os.chmod(script_path, 0o755)

    # Docker command to copy the script to the virtual environment's bin directory and set it up
    setup_script_command = """
mkdir -p /app/venv/bin &&
cp /app/custom_zgrep.sh /app/venv/bin/zgrep &&
chmod +x /app/venv/bin/zgrep
"""

    # Assemble the Docker command with the entire current directory mounted
    current_directory = os.getcwd()
    cmd = [
        'docker', 'run', '--rm', '-a', 'stdout', '-a', 'stderr',
        '--privileged',  # Run the container with extended privileges
        '-v', f'{current_directory}:/app',  # Mount the current directory to /app in the container
        '-w', '/app',  # Set working directory to /app
        '--entrypoint', '/bin/bash',
        'debrebuild',
        '-c', setup_script_command  # Execute command to set up the custom zgrep inside the container
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
RUN apt-get update && \
    apt-get install -y \
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
    zsh

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
RUN /app/venv/bin/pip install requests beautifulsoup4 python-debian python-dateutil rstr google-auth

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
    current_directory = os.getcwd()
    volumes = []

    # # List all directories within the current directory and prepare volume mounts
    # for item in os.listdir(current_directory):
    #     item_path = os.path.join(current_directory, item)
    #     if os.path.isdir(item_path):
    #         volumes.append(f"{item_path}:/app/{item}")
    #
    # # Convert list of volumes to Docker volume arguments
    # volume_args = sum([['-v', volume] for volume in volumes], [])

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


def run_python_in_docker(command):
    current_directory = os.getcwd()
    build_checkpoint_path = os.path.join(current_directory, 'build_checkpoint')

    # Ensure the build_checkpoint directory is mounted
    volume_mount = f"{build_checkpoint_path}:/app/build_checkpoint"

    # Assemble the Docker command with volume mounts
    cmd = [
        'docker', 'run', '--rm', '--privileged', '-a', 'stdout', '-a', 'stderr',
        '-v', volume_mount,  # Mount the build_checkpoint directory to /app/build_checkpoint in the container
        '-w', '/app',  # Set working directory to /app inside the container
        '--entrypoint', '/bin/bash', 'debrebuild',  # Using bash and debrebuild as the image name
        '-c', f"python3 {command}"  # Run the specified Python command
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
    subprocess.run(['docker', 'run', '--rm', '-it', '-v', f'{os.getcwd()}:/app', '-w', '/app', 'debrebuild', 'bash'], check=True)

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
    # Commands to set environment variables inside Docker
    command = "export APT_CACHE_DIR=/app/temp_apt_cache && export CHROOT_ENV=/app/chroot_env && echo $APT_CACHE_DIR && echo $CHROOT_ENV"

    # Run the command inside Docker
    run_in_docker(command)

def install_core_dependencies():
    subprocess.run(['sudo', 'apt-get', 'update'], check=True)
    subprocess.run(['sudo', 'apt-get', 'install', '-y', 'debootstrap', 'schroot'], check=True)
    logger.debug("Core dependencies installed.")

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

def find_dependencies(buildinfo_file, custom_debs):
    dependencies = []
    setup_local_repo(custom_debs)
    install_dependencies(dependencies)

def setup_local_repo(custom_debs):
    for deb in custom_debs:
        shutil.copy(deb, 'temp_apt_cache')
    os.system('dpkg-scanpackages temp_apt_cache /dev/null | gzip -9c > temp_apt_cache/Packages.gz')
    logger.debug("Local repository set up complete.")

def install_dependencies(dependencies):
    for dep in dependencies:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', dep], check=True)
    logger.debug("Dependencies installed.")

def execute_build(chroot_env, package_name):
    subprocess.run(['sudo', 'chroot', chroot_env, 'apt-get', 'source', package_name], check=True)
    subprocess.run(['sudo', 'chroot', chroot_env, 'dpkg-buildpackage', '-us', '-uc'], check=True)

def verify_checksum(package_name, expected_checksum):
    built_package = f"{package_name}.deb"
    checksum = subprocess.check_output(['sha256sum', built_package]).split()[0]
    assert checksum == expected_checksum, "Checksum does not match!"


def prepare_volume(directory_name):
    current_directory = os.getcwd()
    path = os.path.join(current_directory, directory_name)

    # Ensure the directory exists
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"'{directory_name}' directory created at: {path}")

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
        '-c', "touch /app/build_checkpoint/test_file.txt && echo 'Test content' > /app/build_checkpoint/test_file.txt && \
               touch /app/output_dir/test_file.txt && echo 'Test content' > /app/output_dir/test_file.txt && \
               ls -l /app/build_checkpoint /app/output_dir"  # Create and list test files
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

    # Verify the file's existence on the host for both directories
    for volume in [build_checkpoint_volume, output_dir_volume]:
        host_dir = volume.split(':')[0]
        test_file_path = os.path.join(host_dir, "test_file.txt")
        if os.path.exists(test_file_path):
            with open(test_file_path, 'r') as file:
                contents = file.read()
            print(f"Verified file in '{host_dir}': {contents}")
        else:
            print(f"File not found in '{host_dir}'.")

def check_host_file(directory):
    test_file_path = os.path.join(directory, "test_file.txt")
    try:
        with open(test_file_path, 'r') as file:
            print(f"Contents of test file on host: {file.read()}")
    except FileNotFoundError:
        print("Test file not found on the host. Check volume mount.")

def create_persistent_json_file(builder_args):
    # Use the current directory or a specific path to store the JSON file
    current_directory = os.getcwd()
    json_file_path = os.path.join(current_directory, "persistent_args.json")

    # Create a JSON file with example data in the current directory
    with open(json_file_path, 'w') as jf:
        json.dump(builder_args, jf)

    # Print the file path and confirm the contents of the file
    print(f"Persistent JSON file path: {json_file_path}")
    with open(json_file_path, 'r') as jf:
        file_contents = json.load(jf)
        print("Contents of the persistent JSON file:")
        print(json.dumps(file_contents, indent=4))

def run(builder_args):
    logger.debug("Starting the run function")

    bootstrap_build_base_system()
    setup_keyrings_in_docker()
    setup_custom_zgrep_in_docker()

    # List of packages to install
    packages = [
        'requests', 'beautifulsoup4', 'python-debian', 'python-dateutil', 'rstr', 'google-auth'
    ]

    # Construct the command to create a virtual environment and install the packages
    venv_command = (
        "apt-get update && apt-get install -y python3-pip python3-venv && "
        "python3 -m venv /app/venv && "
#        "/app/venv/bin/pip install --upgrade pip && "
        f"/app/venv/bin/pip install {' '.join(packages)}"
    )
    output_dir = builder_args["output_dir"]
    # Run the virtual environment creation and package installation command in the Docker container
    run_in_docker(venv_command)

    run_docker_container(output_dir)
    create_persistent_json_file(builder_args)

    # # Copy the temp file into /app directory inside the Docker container
    # copy_to_docker("temp_args.json", "temp_args.json")
    #
    # time(5)
    # Call to run the command in Docker with the file accessible
    json_file_path = os.path.join(os.getcwd(), "persistent_args.json")
    try:
        run_python_in_docker(f"initialize_and_find_dependencies.py /app/{os.path.basename(json_file_path)}")
    except Exception as e:
        print("Error running command in Docker:", e)
        # Assuming debug_docker() is a function you've defined to help with debugging
        debug_docker()
        # Assuming RebuilderException is a custom exception you've defined
        raise RebuilderException("Failed to initialize and find dependencies")

    source_name = get_source_name_from_buildinfo(builder_args["buildinfo_file"])
    checkpoint_dir = os.path.join("build_checkpoint", source_name)
    checkpoint_file = f"checkpoint_find_dep_{source_name}.json"
    checkpoint_json_path = os.path.join(checkpoint_dir, checkpoint_file)

    # if not os.path.exists(checkpoint_json_path):
    #     logger.error(f"Checkpoint JSON file not found: {checkpoint_json_path}")
    #     raise RebuilderException("Checkpoint JSON file not found")

    try:
        run_python_in_docker(f"execute_build.py"
                      f" /app/{checkpoint_json_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute build: {e}")
        debug_docker()
        raise RebuilderException("Failed to execute build")

    logger.debug("Finding buildinfo files in output directory...")
    buildinfo_files = glob.glob(os.path.join(output_dir, "*.buildinfo"))
    if not buildinfo_files:
        logger.error("No buildinfo file found in the output directory.")
        raise BuildInfoException("Cannot find any buildinfo file in the specified directory.")

    new_buildinfo_file = max(buildinfo_files, key=os.path.getmtime)
    logger.debug(f"Using buildinfo file: {new_buildinfo_file}")

    try:
        run_python_in_docker(f"post_build_actions.py"
                      f" {checkpoint_json_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to perform post-build actions: {e}")
        debug_docker()
        raise RebuilderException("Failed to perform post-build actions")

    logger.debug("Post-build actions completed successfully.")

def get_args():
    parser = argparse.ArgumentParser(
        description="Given a buildinfo file from a Debian package, generate instructions for attempting to reproduce the binary packages built from the associated source and build information."
    )
    parser.add_argument("buildinfo", help="Input buildinfo file. Local or remote file.")
    parser.add_argument("--output", help="Directory for the build artifacts")
    parser.add_argument("--builder", help="Which building software should be used. (default: none)", default="none")
    parser.add_argument("--query-url", help="API url for querying package and binary information (default: http://snapshot.notset.fr).", default="http://snapshot.notset.fr")
    parser.add_argument("--snapshot-mirror", help="Snapshot mirror to use (default: http://snapshot.notset.fr)", default="http://snapshot.notset.fr")
    parser.add_argument("--metasnap-url", help="Metasnap service url (default: https://metasnap.debian.net).", default="https://metasnap.debian.net")
    parser.add_argument("--use-metasnap", help="Service to query the minimal set of timestamps containing all package versions referenced in a buildinfo file.", action="store_true")
    parser.add_argument("--builder_json_file", help="Build process to resume from", default="")
    parser.add_argument("--extra-repository-file", help="Add repository file content to the list of apt sources during the package build.", action="append")
    parser.add_argument("--extra-repository-key", help="Add key file (.asc) to the list of trusted keys during the package build.", action="append")
    parser.add_argument("--gpg-sign-keyid", help="GPG keyid to use for signing in-toto metadata.")
    parser.add_argument("--gpg-verify", help="Verify buildinfo GPG signature.", action="store_true")
    parser.add_argument("--gpg-verify-key", help="GPG key to use for buildinfo GPG check.")
    parser.add_argument("--proxy", help="Proxy address to use.")
    parser.add_argument("--build-options-nocheck", action="store_true", help="Disable build tests.")
    parser.add_argument("--verbose", action="store_true", help="Display logger info messages.")
    parser.add_argument("--debug", action="store_true", help="Display logger debug messages.")
    parser.add_argument("--custom-deb", help="List of paths to custom .deb files to include in the build", action="append")
    parser.add_argument("--build_env", help="Path to a custom Dockerfile to use for the build environment")
    return parser.parse_args()

def realpath(path):
    return os.path.abspath(os.path.expanduser(path))

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
        return 2
    except RebuilderException as e:
        logger.error(str(e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
