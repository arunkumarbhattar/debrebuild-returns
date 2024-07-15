import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import glob

import debian.deb822

# Configure logging
logger = logging.getLogger("debrebuild")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

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
    zlib1g-dev

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

# Ensure bash is executable and set as the default shell
RUN chmod +x /bin/bash
SHELL ["/bin/bash", "-c"]
"""

def write_dockerfile(dockerfile_content):
    with open('Dockerfile', 'w') as f:
        f.write(dockerfile_content)
    logger.debug("Dockerfile written.")

def build_docker_image():
    subprocess.run(['docker', 'build', '-t', 'debrebuild', '.'], check=True)
    logger.debug("Docker image built.")

def run_in_docker(command, *file_paths):
    # Prepare mounts for each file path provided
    mounts = []
    for file_path in file_paths:
        filename = os.path.basename(file_path)
        mount = f'{file_path}:/tmp/{filename}'
        mounts.append('-v')
        mounts.append(mount)

    # Assemble the full Docker command
    cmd = [
        'docker', 'run', '--rm', '-a', 'stdout', '-a', 'stderr',
        *mounts,  # Add all file mounts to the command
        '-v', f'{os.getcwd()}:/app',
        '-w', '/app',
        '--entrypoint', '/bin/bash',
        'debrebuild',
        '-c', f"mkdir -p /tmp && {command}"  # Ensure /tmp exists and run the command
    ]

    # Execute the Docker command
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.debug(f"Running command in Docker: {' '.join(cmd)}")
    logger.debug("Command output: " + result.stdout)
    logger.error("Command error output: " + result.stderr)

    if result.returncode != 0:
        logger.error(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)

def debug_docker():
    logger.debug("Starting Docker container in interactive mode for debugging...")
    subprocess.run(['docker', 'run', '--rm', '-it', '-v', f'{os.getcwd()}:/app', '-w', '/app', 'debrebuild', 'sh'], check=True)

def setup_directories():
    if not os.path.exists('temp_apt_cache'):
        os.makedirs('temp_apt_cache')
    if not os.path.exists('chroot_env'):
        os.makedirs('chroot_env')
    logger.debug("Directories setup complete.")

def initialize_configurations():
    os.environ['APT_CACHE_DIR'] = os.path.abspath('temp_apt_cache')
    os.environ['CHROOT_ENV'] = os.path.abspath('chroot_env')
    logger.debug("Configurations initialized.")

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

def bootstrap_build_base_system():
    setup_directories()
    initialize_configurations()
    install_core_dependencies()
    prepare_execution_environment()
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

def run(builder_args):
    logger.debug("Starting the run function")

    bootstrap_build_base_system()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode='w') as tf:
        json.dump(builder_args, tf)
        builder_args_json_file = tf.name

    try:
        run_in_docker(f'source /app/venv/bin/activate && python3 initialize_and_find_dependencies.py {builder_args_json_file}')
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to initialize and find dependencies: {e}")
        debug_docker()
        raise RebuilderException("Failed to initialize and find dependencies")

    output_dir = builder_args["output_dir"]

    source_name = get_source_name_from_buildinfo(builder_args["buildinfo_file"])
    checkpoint_dir = os.path.join("build_checkpoint", source_name)
    checkpoint_file = f"checkpoint_find_dep_{source_name}.json"
    checkpoint_json_path = os.path.join(checkpoint_dir, checkpoint_file)

    if not os.path.exists(checkpoint_json_path):
        logger.error(f"Checkpoint JSON file not found: {checkpoint_json_path}")
        raise RebuilderException("Checkpoint JSON file not found")

    try:
        run_in_docker(f'source /app/venv/bin/activate && python3 execute_build.py {checkpoint_json_path} {output_dir}')
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
        run_in_docker(f'source /app/venv/bin/activate && python3 post_build_actions.py {checkpoint_json_path} {output_dir}')
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
