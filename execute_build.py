import json
import logging
import os
import shutil
import subprocess
from shlex import quote, join

import requests

from bs4 import BeautifulSoup
from rstr import rstr
import requests
import debian.deb822
import debian.debian_support
from initialize_and_find_dependencies import Rebuilder, RebuilderBuildInfo, Package

import logging
import sys

# Configure logging
logger = logging.getLogger("execute_build")
logger.setLevel(logging.DEBUG)  # Set logger level to DEBUG
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.DEBUG)  # Set handler level to DEBUG
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logger = logging.getLogger("execute_build")
logger.setLevel(logging.DEBUG)  # Set logger level to DEBUG

DEBIAN_KEYRINGS = [
    "/app/keyrings/debian-archive-bullseye-automatic.gpg",
    "/app/keyrings/debian-archive-bullseye-security-automatic.gpg",
    "/app/keyrings/debian-archive-bullseye-stable.gpg",
    "/app/keyrings/debian-archive-buster-automatic.gpg",
    "/app/keyrings/debian-archive-buster-security-automatic.gpg",
    "/app/keyrings/debian-archive-buster-stable.gpg",
    "/app/keyrings/debian-archive-keyring.gpg",
    "/app/keyrings/debian-archive-removed-keys.gpg",
    "/app/keyrings/debian-archive-stretch-automatic.gpg",
    "/app/keyrings/debian-archive-stretch-security-automatic.gpg",
    "/app/keyrings/debian-archive-stretch-stable.gpg",
    "/app/keyrings/debian-ports-archive-keyring-removed.gpg",
    "/app/keyrings/debian-ports-archive-keyring.gpg",
    "/app/keyrings/debian-keyring.gpg",
]


class PackageException(Exception):
    pass


class BuildInfoException(Exception):
    pass


class RebuilderException(Exception):
    pass


class Package:
    def __init__(
            self,
            name,
            version,
            architecture=None,
            archive_name="debian",
            suite_name="unstable",
            component_name="main",
    ):
        self.name = name
        self.version = version
        self.architecture = architecture
        self.archive_name = archive_name
        self.timestamp = None
        self.suite_name = suite_name
        self.component_name = component_name
        self.hash = None

    def to_index_format(self):
        if self.architecture:
            result = f"{self.name} {self.version} {self.architecture}"
        else:
            result = f"{self.name} {self.version}"
        return result

    def to_apt_install_format(self, build_arch=None):
        result = f"{self.name}={self.version}"
        if build_arch and self.architecture in ("all", build_arch):
            result = f"{self.name}:{self.architecture}={self.version}"
        return result

    def __repr__(self):
        return f"Package({self.name}, {self.version}, architecture={self.architecture})"


def execute_build(rebuilder, builder, output):
    # Execute the build
    logger.debug("Starting the actual rebuild...")
    if builder == "none":
        logger.debug("No builder specified, skipping build.")
        return
    if builder == "mmdebstrap":
        logger.debug("Using mmdebstrap for building.")
        mmdebstrap(rebuilder, output)


def mmdebstrap(rebuilder, output):
    # Define the build directory at the beginning of the function
    build_dir = f"{rebuilder.tmpdir}/build"
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(build_dir, exist_ok=True)

    # Prepare mmdebstrap command
    cmd = generate_mmdebstrap_cmd(rebuilder, output)

    logger.debug("Final mmdebstrap command: " + " ".join(cmd))

    # Execute the initial mmdebstrap command
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    logger.debug(f"mmdebstrap completed successfully: {result.stdout}")
    if result.stdout:
        logger.debug("STDOUT:", result.stdout)
    if result.stderr:
        logger.debug("STDERR:", result.stderr)

    if result.returncode != 0:
        # Handle failure in finding the source package or version
        logger.error(f"mmdebstrap failed with error: {result.stderr}")
        raise RebuilderException("mmdebstrap failed")
    else:
        logger.debug(f"mmdebstrap completed successfully: {result.stdout}")
        print_output_directory_tree(build_dir)


def print_output_directory_tree(directory):
    # Helper function to print the directory tree
    for root, dirs, files in os.walk(directory):
        level = root.replace(directory, '').count(os.sep)
        indent = ' ' * 4 * (level)
        logger.debug(f"{indent}{os.path.basename(root)}/")
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            logger.debug(f"{subindent}{f}")


def is_source_available(self):
    # Implement the logic to check if the source package and version are available
    source_check_cmd = [
        "apt-get",
        "source",
        "--only-source",
        "-d",
        "{}={}".format(self.buildinfo.source, self.buildinfo.source_version)
    ]
    result = subprocess.run(source_check_cmd, capture_output=True, text=True)
    return result.returncode == 0


def get_build_depends(self):
    # Storing self.build_depends is needed as we refresh information
    # from apt cache
    if not self.build_depends:
        installed = self.parsed_info.relations["installed-build-depends"]
        for dep in installed:
            name = dep[0]["name"]
            _, version = dep[0]["version"]
            self.build_depends.append(Package(name, version))
    return self.build_depends


def get_apt_build_depends(rebuilder):
    apt_build_depends = []
    for pkg in get_build_depends(rebuilder.buildinfo):
        apt_build_depends.append(pkg.to_apt_install_format(rebuilder.buildinfo.build_arch))
    return apt_build_depends


def get_build_dependency(rebuilder, name):
    build_dependency = None
    for pkg in get_build_depends(rebuilder.buildinfo):
        if pkg.name == name:
            build_dependency = pkg
            break
    return build_dependency


def get_src_date(self):
    if all(
            [
                self.buildinfo.archive_name,
                self.buildinfo.source_date,
                self.buildinfo.suite_name,
                self.buildinfo.component_name,
            ]
    ):
        return (
            self.buildinfo.archive_name,
            self.buildinfo.source_date,
            self.buildinfo.suite_name,
            self.buildinfo.component_name,
        )

    srcpkgname = self.buildinfo.source
    srcpkgver = self.buildinfo.source_version
    json_url = f"{self.snapshot_url}/mr/package/{srcpkgname}/{srcpkgver}/srcfiles?fileinfo=1"
    logger.debug(f"Get source package info: {srcpkgname}={srcpkgver}")
    logger.debug(f"Source URL: {json_url}")
    resp = get_response(self, json_url)
    try:
        data = resp.json()
    except json.decoder.JSONDecodeError:
        raise RebuilderException(
            f"Cannot parse response for source: {self.buildinfo.source}"
        )

    source_info = None
    for h in data.get("fileinfo", {}).values():
        # We pick the first dsc found.
        for f in h:
            if f["name"].endswith(".dsc"):
                source_info = f
                break
            if source_info:
                break
    if not source_info:
        raise RebuilderException(
            f"No source info found for {srcpkgname}-{srcpkgver}"
        )

    logger.debug(f"Source info retrieved: {source_info}")  # Print the source info

    # Mapping the retrieved source_info fields to buildinfo object
    self.buildinfo.archive_name = "debian"
    #self.buildinfo.archive_name = source_info["archive_name"]
    self.buildinfo.source_date = source_info["first_seen"]

    # Assuming 'buster' and 'main' as defaults if they cannot be determined from the path
    self.buildinfo.suite_name = "sid"  # Replace with actual logic if available
    self.buildinfo.component_name = "main"  # Replace with actual logic if available

    return (
        self.buildinfo.archive_name,
        self.buildinfo.source_date,
        self.buildinfo.suite_name,
        self.buildinfo.component_name,
    )


def get_sources_list(self):
    sources_list = self.newly_added_sources
    archive_name, source_date, dist, component = get_src_date(self)
    base_url = f"{self.base_mirror}/archive/{archive_name}/{source_date}"

    # Adding  to the repository entries
    build_repo = f"deb  {base_url} {dist} {component} \n"
    sources_list.append(build_repo)

    source_repo = f"deb-src  {base_url} {dist} {component} \n"
    sources_list.append(source_repo)

    if self.extra_repository_files:
        for repo_file in self.extra_repository_files:
            try:
                with open(repo_file) as fd:
                    for line in fd:
                        if not line.startswith("#") and not line.startswith("\n"):
                            cleaned_line = line.rstrip('\n')  # Handle outside the f-string
                            sources_list.append(f"deb  {cleaned_line}")
            except FileNotFoundError:
                raise RebuilderException(
                    f"Cannot find repository file: {repo_file}"
                )

    # Custom package directory handled with
    if self.custom_package and self.custom_package_dir:
        sources_list.append(f"deb  file:{self.custom_package_dir} ./")

    return sources_list


def get_sources_list_timestamps(self):
    """
    Returns all timestamp inline Debian repositories for all archives
    """
    sources_list = []
    for sources in self.required_timestamp_sources.values():
        sources_list += sources
    return sources_list


def generate_mmdebstrap_cmd(rebuilder, output_dir):
    # Determine build type
    if rebuilder.buildinfo.build_archany and rebuilder.buildinfo.build_archall:
        build = "any,all"
    elif rebuilder.buildinfo.build_archall:
        build = "all"
    elif rebuilder.buildinfo.build_archany:
        build = "any"
    elif rebuilder.buildinfo.build_source:
        build = "source"
    else:
        raise RebuilderException("Cannot determine what to build")

    logger.debug(f"Determined build type: {build}")

    checkpoint_files = rebuilder.checkpoint_files
    temp_dir = os.path.join(rebuilder.checkpoint_dir, os.path.basename(rebuilder.tempaptdir))

    # Ensure TMPDIR is correctly set
    rebuilder.tmpdir = "/app/build_checkpoint/tmp/mmdebstrap_tmp"
    if not os.path.exists(rebuilder.tmpdir):
        os.makedirs(rebuilder.tmpdir)

    # Copy all files from temp_dir to rebuilder.tmpdir
    subprocess.run(["cp", "-r", temp_dir, rebuilder.tmpdir], check=True)

    cmd = [
        "env",
        "-i",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        f"TMPDIR={rebuilder.tmpdir}",
        "mmdebstrap",
        f"--arch={rebuilder.buildinfo.build_arch}",
        f"--include={' '.join(get_apt_build_depends(rebuilder))}",
        "--variant=apt",
        '--aptopt=Acquire::Check-Valid-Until "false"',
        '--aptopt=Acquire::http::Dl-Limit "1000";',
        '--aptopt=Acquire::https::Dl-Limit "1000";',
        '--aptopt=Acquire::Retries "5";',
        '--aptopt=APT::Get::allow-downgrades "true";'
    ]

    logger.debug(f"Initial mmdebstrap command: {' '.join(cmd)}")

    if rebuilder.proxy:
        cmd += ['--aptopt=Acquire::http::proxy "{}";'.format(rebuilder.proxy)]
        logger.debug(f"Added proxy to mmdebstrap command: {rebuilder.proxy}")

    cmd += ["--keyring=/usr/share/keyrings/"]

    if not get_build_dependency(rebuilder, "build-essential"):
        cmd += ['--essential-hook=chroot "$1" sh -c "apt-get --yes install build-essential"']
        logger.debug("Added build-essential installation to mmdebstrap command")

    cmd += [
        '--essential-hook=chroot "$1" sh -c "apt-get --yes install fakeroot util-linux gnupg dirmngr zsh"',
        # Install zsh here
        '--essential-hook=chroot "$1" sh -c "apt-get update && apt-get --yes install -f"',
        '--essential-hook=chroot "$1" sh -c "apt-get --yes install wget"',
        # Ensure /dev/fd is correctly symlinked to /proc/self/fd
        '--essential-hook=chroot "$1" sh -c "rm -rf /dev/fd && ln -s /proc/self/fd /dev/fd"'
    ]
    logger.debug(
        "Added fakeroot, util-linux, gnupg, wget, zsh installation, and /dev/fd symlink fix to mmdebstrap command")

    # Add Debian keyrings into mmdebstrap trusted keys after init phase
    cmd += [
        "--essential-hook=copy-in {} /etc/apt/trusted.gpg.d/".format(
            join(DEBIAN_KEYRINGS)
        )
    ]

    # Copy extra keys and repository files
    if rebuilder.extra_repository_keys:
        cmd += [
            "--essential-hook=copy-in {} /etc/apt/trusted.gpg.d/".format(
                join(rebuilder.extra_repository_keys)
            )
        ]
        logger.debug("Added extra repository keys to mmdebstrap command")

    if rebuilder.extra_repository_files:
        cmd += [
            '--essential-hook=chroot "$1" sh -c "apt-get --yes install apt-transport-https ca-certificates"'
        ]
        logger.debug("Added installation of apt-transport-https and ca-certificates to mmdebstrap command")

    if rebuilder.consider_local_repo or rebuilder.custom_deb:
        logger.debug("DEBBIE")
        # Ensure the local repository directory exists
        local_repo_dir = "/app/build_checkpoint/tmp/local_repo"
        packages_file_src = os.path.join(local_repo_dir, "Packages")

        # Modify the Filename field in the Packages file to reflect the new path
        try:
            with open(packages_file_src, "r") as f:
                lines = f.readlines()

            # Debug: Log the original contents of the Packages file
            logger.debug("Original Packages file contents:\n" + ''.join(lines))

            with open(packages_file_src, "w") as f:
                for line in lines:
                    if line.startswith("Filename: "):
                        # Ensure the Filename field uses the correct relative path
                        relative_path = line.split('/')[-1].strip()
                        f.write(f"Filename: /mnt/local_repo/{relative_path}\n")
                    else:
                        f.write(line)

            # Recompress the Packages file
            subprocess.run(["gzip", "-kf", packages_file_src], check=True)

            # Debug: Verify the updated Packages file contents
            with open(packages_file_src, "r") as f:
                updated_lines = f.readlines()
            logger.debug("Updated Packages file contents:\n" + ''.join(updated_lines))

            # Debug: Verify the compressed Packages.gz file contents
            packages_gz_path = packages_file_src + ".gz"
            if os.path.exists(packages_gz_path):
                with open(packages_gz_path, "rb") as f:
                    compressed_contents = f.read()
                logger.debug(
                    f"Compressed Packages.gz file contents: {compressed_contents[:200]}... (truncated for brevity)")
            else:
                logger.error(f"Compressed Packages.gz file does not exist at {packages_gz_path}")

            logger.debug(f"Updated Filename paths in Packages file and recompressed it.")
        except Exception as e:
            logger.error(f"Failed to update the Filename paths in the Packages file: {e}")
            return False

        cmd += [
            '--essential-hook=chroot "$1" sh -c "{}"'.format(
                " && ".join(
                    [
                        "rm /etc/apt/sources.list",
                        "echo 'deb [trusted=yes] http://localhost:5000 ./' >> /etc/apt/sources.list",
                    ]
                )
            )
        ]

        # Ensure the directory exists inside the chroot before copying the local repository
        cmd += [
            '--essential-hook=chroot "$1" mkdir -p /mnt/local_repo',
            '--essential-hook=ls /app/build_checkpoint/tmp/local_repo',  # Verify the contents of the source directory
            '--essential-hook=cp -r /app/build_checkpoint/tmp/local_repo/* "$1"/mnt/local_repo/',
            '--essential-hook=ls "$1"/mnt/local_repo',  # Verify the contents of the target directory after copying
            '--essential-hook=chroot "$1" sh -c "echo \'\ndeb [trusted=yes] file:///mnt/local_repo ./\' >> '
            '/etc/apt/sources.list"',
            '--essential-hook=chroot "$1" sh -c "cd /mnt/local_repo && dpkg-scanpackages . | gzip -c > Packages.gz"',
            # Generate Packages.gz
            '--essential-hook=chroot "$1" sh -c "apt-get update"',  # Update apt after generating Packages.gz
        ]

        logger.debug("Added local repository setup to mmdebstrap command")

    else:
        logger.debug("Not DEBBIE")
        # Update APT cache with provided sources.list
        cmd += [
            '--essential-hook=chroot "$1" sh -c "{}"'.format(
                " && ".join(
                    [
                        "rm /etc/apt/sources.list",
                        "echo 'deb [trusted=yes] http://localhost:5000 ./' >> /etc/apt/sources.list",
                        "apt-get update",
                    ]
                )
            )
        ]

    logger.debug("Added apt-key update to mmdebstrap command")

    cmd += [
        '--customize-hook=chroot "$1" useradd --no-create-home -d /nonexistent -p "" builduser -s /bin/zsh'
    ]
    logger.debug("Added creation of builduser to mmdebstrap command")

    # In case of binNMU build, we add the changelog entry from buildinfo
    binnmucmds = []
    if rebuilder.buildinfo.logentry:
        binnmucmds += [
            "cd {}".format(quote(get_build_path(rebuilder.buildinfo))),
            "{{ printf '%s' {}; cat debian/changelog; }} > debian/changelog.debrebuild".format(
                quote(rebuilder.buildinfo.logentry)
            ),
            "mv debian/changelog.debrebuild debian/changelog",
        ]

    # Specify the custom directory names
    custom_unpack_dir = "/build/src_dir"

    # Add preparation of build directory and source package download
    if not is_source_available(rebuilder):
        build_path = quote(get_build_path(rebuilder.buildinfo))
        env_vars = " ".join(get_env(rebuilder))
        host_arch = rebuilder.buildinfo.host_arch
        build = "binary"  # Replace with appropriate build type if needed
        logger.debug("Source is unavailable")

        # dsc_url = "http://ftp.de.debian.org/debian/pool/main/g/gzip/gzip_1.10-4+deb11u1.dsc"
        # orig_tar_url = "http://ftp.de.debian.org/debian/pool/main/g/gzip/gzip_1.10.orig.tar.gz"
        # debian_tar_url = "http://ftp.de.debian.org/debian/pool/main /g/gzip/gzip_1.10-4+deb11u1.debian.tar.xz"

        if not rebuilder.dsc_url and not rebuilder.debian_tar_url and not rebuilder.orig_tar_url:
            dsc_url, orig_tar_url, debian_tar_url = fetch_debian_package_urls(rebuilder, rebuilder.buildinfo.source,
                                                                          rebuilder.buildinfo.version)

            if not dsc_url or not orig_tar_url or not debian_tar_url:
                # Prompt the user to provide source URLs for fallback
                logger.error(f"Unable to find URLs automatically, "
                             f"Please provide source package information "
                             f"(--dsc_url, --orig_tar_url, --debian_tar_url) arguments and re-run.")
                return False
            else:
                rebuilder.dsc_url = dsc_url
                rebuilder.orig_tar_url = orig_tar_url
                rebuilder.debian_tar_url = debian_tar_url

        # Hooks for setting up and downloading packages
        cmd += [
            '--customize-hook=chroot "$1" sh -c "mkdir -p /build"',
            '--customize-hook=chroot "$1" env sh -c "wget -P /build {dsc_url}"'.format(
                dsc_url=rebuilder.dsc_url),
            '--customize-hook=chroot "$1" env sh -c "wget -P /build {orig_tar_url}"'.format(
                orig_tar_url=rebuilder.orig_tar_url),
            '--customize-hook=chroot "$1" env sh -c "wget -P /build {debian_tar_url}"'.format(
                debian_tar_url=rebuilder.debian_tar_url),
            '--customize-hook=chroot "$1" env sh -c "cd /build && dpkg-source --no-check -x $(basename {dsc_url}) '
            'src_dir"'.format(dsc_url=rebuilder.dsc_url),
            '--customize-hook=chroot "$1" sh -c "chown -R builduser:builduser /build"',
            '--customize-hook=chroot "$1" sh -c "ls -lR /build/src_dir; echo Listing contents of /build/src_dir"',
            '--customize-hook=chroot "$1" env --unset=TMPDIR runuser builduser -c "{}"'.format(
                " && ".join([
                    "cd /build/src_dir",
                    "env {} dpkg-buildpackage -uc -d -a {} --build={}".format(env_vars, host_arch, build)
                ])
            ),
            '--customize-hook=chroot "$1" sh -c "find /build -mindepth 1 -maxdepth 1 ! -name src_dir -exec mv {} '
            '/build/src_dir/ \\;"'
        ]

        # Sync-out command with post-operation logging
        cmd += [
            '--customize-hook=sync-out {custom_unpack_dir} {output_dir}'.format(custom_unpack_dir="/build/src_dir",
                                                                                output_dir=output_dir),
            rebuilder.buildinfo.get_debian_suite(),
            "/dev/null",
            get_chroot_basemirror(rebuilder),  # Ensure this method is defined and returns a valid URL
            '--customize-hook=sh -c "ls -lR {output_dir}; echo Listing contents of {output_dir}"'.format(
                output_dir=output_dir)
        ]

        logger.debug("Added sync-out and final setup to mmdebstrap command")
    else:
        logger.debug("Source is available")
        # Prepare build directory and get package source
        cmd += [
            '--customize-hook=chroot "$1" env sh -c "{}"'.format(
                " && ".join(
                    [
                        "apt-get source --only-source -d {}={}".format(
                            rebuilder.buildinfo.source, rebuilder.buildinfo.source_version
                        ),
                        "mkdir -p {}".format(
                            os.path.dirname(quote(get_build_path(rebuilder.buildinfo)))
                        ),
                        "dpkg-source --no-check -x /*.dsc {}".format(
                            quote(get_build_path(rebuilder.buildinfo))
                        ),
                    ]
                    + binnmucmds
                    + [
                        "chown -R builduser:builduser {}".format(
                            os.path.dirname(quote(get_build_path(rebuilder.buildinfo)))
                        ),
                    ]
                )
            )
        ]

        # Prepare build command
        cmd += [
            '--customize-hook=chroot "$1" env --unset=TMPDIR runuser builduser -c "{}"'.format(
                " && ".join(
                    [
                        "cd {}".format(quote(get_build_path(rebuilder.buildinfo))),
                        "env {} dpkg-buildpackage -uc -a {} --build={}".format(
                            " ".join(get_env(rebuilder)), rebuilder.buildinfo.host_arch, build
                        ),
                    ]
                )
            )
        ]

        cmd += [
            "--customize-hook=sync-out {} {}".format(
                os.path.dirname(quote(get_build_path(rebuilder.buildinfo))), output_dir
            ),
            get_debian_suite(rebuilder.buildinfo),
            "/dev/null",
            get_chroot_basemirror(rebuilder),
        ]

    if rebuilder.create_docker_image:
        create_docker_snapshot(rebuilder, cmd)

    return cmd


def get_debian_suite(self):
    """Returns the Debian suite suited for debootstraping the build
    environment as described by the .buildinfo file.
    (For *re*building we cannot base upon packages from buster as else
    we might be forced to downgrades which are not supported.)
    This is then used by rebuilders usage of debootstrap for
    rebuilding the underling packages.
    """
    debian_suite = "sid"
    for pkg in self.parsed_info.relations["installed-build-depends"]:
        if pkg[0]["name"] == "base-files":
            _, version = pkg[0]["version"]
            try:
                version = str(int(float(version)))
            except ValueError:
                break
            for rel in debian.debian_support._release_list.values():
                if rel and rel.version == version:
                    debian_suite = str(rel)
                    break
    return debian_suite


def get_build_path(self):
    if not self.build_path:
        self.build_path = f"/build/{self.source}-{rstr.letters(10)}"
    self.build_path = self.build_path.replace("~", "-")
    return self.build_path


def get_env(self):
    env = []
    for key, val in self.buildinfo.env.items():
        env.append(f'{key}="{val}"')
    if self.build_options_nocheck:
        env.append("DEB_BUILD_OPTIONS=nocheck")
    return env


def fetch_debian_package_urls(self, package_name, version):
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


def get_base_image(c):
    with open('/etc/os-release') as f:
        lines = f.readlines()

    version = None
    for line in lines:
        if line.startswith('VERSION_ID='):
            version = line.split('=')[1].strip().strip('"')
            break

    if not version:
        raise RebuilderException("Unable to determine Debian version from /etc/os-release")

    return f"debian:{version}-slim"


def create_docker_snapshot(rebuilder, cmd):
    base_image = get_base_image(rebuilder)  # Determine the base Debian image from the current system

    dockerfile_content = f"""
    FROM {base_image}
    RUN apt-get update && apt-get install -y fakeroot util-linux gnupg dirmngr wget
    RUN {" && ".join(cmd)}
    """
    dockerfile_path = os.path.join(rebuilder.tmpdir, "Dockerfile")
    with open(dockerfile_path, "w") as dockerfile:
        dockerfile.write(dockerfile_content)

    image_name = input("Please provide a name for the Docker image: ")

    build_cmd = ["docker", "build", "-t", image_name, rebuilder.tmpdir]
    result = subprocess.run(build_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logger.error(f"Docker build failed with error: {result.stderr}")
        raise RebuilderException("Docker build failed")
    else:
        logger.debug(f"Docker image {image_name} created successfully: {result.stdout}")


def get_chroot_basemirror(rebuilder):
    logger.debug("Starting get_chroot_basemirror")

    # Workaround for standard method. libc6 should be the parent of all the packages.
    for pkg in ["libc6", "dpkg", "build-essential", "util-linux"]:
        dependency = get_build_dependency(rebuilder, pkg)
        if dependency:
            logger.debug(f"Found dependency for package '{pkg}': {dependency}")
            break
    else:
        logger.debug("No dependency found among the checked packages")
        dependency = None

    if not rebuilder.use_metasnap and dependency:
        logger.debug("Using non-metasnap approach with found dependency")
        archive_name = dependency.archive_name
        suite_name = dependency.suite_name
        component_name = dependency.component_name
        sorted_timestamp_sources = [dependency.timestamp]
    else:
        logger.debug("Using metasnap or no dependency found")
        reference_key = f"debian+{get_debian_suite(rebuilder.buildinfo)}+main"
        if rebuilder.buildinfo.required_timestamps.get(reference_key, None):
            timestamps = rebuilder.buildinfo.required_timestamps[reference_key]
            logger.debug(f"Found timestamps for reference key {reference_key}: {timestamps}")
        else:
            reference_key, timestamps = list(
                rebuilder.buildinfo.required_timestamps.items()
            )[0]
            logger.debug(f"Using first available reference key {reference_key} with timestamps: {timestamps}")
        sorted_timestamp_sources = sorted(timestamps)
        archive_name, suite_name, component_name = reference_key.split("+", 3)

    logger.debug(f"Using archive: {archive_name}, suite: {suite_name}, component: {component_name}")
    logger.debug(f"Sorted timestamp sources: {sorted_timestamp_sources}")

    for timestamp in sorted_timestamp_sources:
        url = f"{rebuilder.base_mirror}/archive/{archive_name}/{timestamp}"
        basemirror = f"deb  {url} {suite_name} {component_name}"
        release_url = f"{url}/dists/{suite_name}/Release"
        logger.debug(f"Checking release URL: {release_url}")

        resp = get_response(rebuilder, release_url)
        if resp.ok:
            logger.debug(f"Found valid base mirror: {basemirror}")
            return basemirror
        else:
            logger.debug(f"Release URL {release_url} is not valid")

    logger.error("Cannot determine base mirror to use")
    raise RebuilderException("Cannot determine base mirror to use")


def get_response(rebuilder, url):
    try:
        resp = rebuilder.session.get(url)
    except requests.exceptions.ConnectionError as e:
        # logger.error(f"Failed to get URL {url}: {str(e)}")
        # WIP: forge a better response?
        resp = requests.models.Response()
        resp.status_code = 503
        resp.reason = str(e)
    return resp


def main():
    import sys

    if len(sys.argv) != 3:
        logger.debug("Usage: python execute_build.py <rebuilder_json_file> <artifacts_dir>")
        sys.exit(1)

    rebuilder_json_file = sys.argv[1]
    artifacts_dir = sys.argv[2]
    # Load the Rebuilder instance from the JSON file
    with open(rebuilder_json_file, 'r') as f:
        rebuilder_data = json.load(f)

    rebuilder = Rebuilder.from_dict(rebuilder_data, rebuilder_json_file)

    # Call the execute_build function with the Rebuilder instance
    builder = "mmdebstrap"  # or get this from some config if needed

    execute_build(rebuilder, builder, artifacts_dir)


if __name__ == "__main__":
    main()
