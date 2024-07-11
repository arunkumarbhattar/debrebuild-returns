import glob
import json
import logging
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import time
import debian.debian_support

import requests
import apt
import apt_pkg
from apport.crashdb_impl import debian
from bs4 import BeautifulSoup
import debian.deb822
from dateutil.parser import parse as parsedate
from rstr import rstr

from lib.openpgp import OpenPGPException, OpenPGPEnvironment
import logging
import sys

logger = logging.getLogger("debrebuild")
console_handler = logging.StreamHandler(sys.stderr)
logger.addHandler(console_handler)

logger = logging.getLogger("initialize_and_find_dependencies")

DEBIAN_KEYRINGS = [
    "/usr/share/keyrings/debian-archive-bullseye-automatic.gpg",
    "/usr/share/keyrings/debian-archive-bullseye-security-automatic.gpg",
    "/usr/share/keyrings/debian-archive-bullseye-stable.gpg",
    "/usr/share/keyrings/debian-archive-buster-automatic.gpg",
    "/usr/share/keyrings/debian-archive-buster-security-automatic.gpg",
    "/usr/share/keyrings/debian-archive-buster-stable.gpg",
    "/usr/share/keyrings/debian-archive-keyring.gpg",
    "/usr/share/keyrings/debian-archive-removed-keys.gpg",
    "/usr/share/keyrings/debian-archive-stretch-automatic.gpg",
    "/usr/share/keyrings/debian-archive-stretch-security-automatic.gpg",
    "/usr/share/keyrings/debian-archive-stretch-stable.gpg",
    "/usr/share/keyrings/debian-ports-archive-keyring-removed.gpg",
    "/usr/share/keyrings/debian-ports-archive-keyring.gpg",
    "/usr/share/keyrings/debian-keyring.gpg",
]


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

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "architecture": self.architecture,
            "archive_name": self.archive_name,
            "timestamp": self.timestamp,
            "suite_name": self.suite_name,
            "component_name": self.component_name,
            "hash": self.hash,
        }

    def __repr__(self):
        return f"Package({self.name}, {self.version}, architecture={self.architecture})"


class PackageNotFoundException(Exception):
    def __init__(self, package_name):
        self.package_name = package_name
        super().__init__(f"Desired package '{self.package_name}' not found in the traditional way.")


class RebuilderBuildInfo:
    def __init__(self, buildinfo_file, use_fallback=False):
        logging.debug(f"Initializing RebuilderBuildInfo with file: {buildinfo_file}, use_fallback={use_fallback}")
        if use_fallback:
            directory = os.path.dirname(buildinfo_file) if not os.path.isdir(buildinfo_file) else buildinfo_file
            self.buildinfo_path = self.find_new_buildinfo(directory)
        else:
            self.buildinfo_path = buildinfo_file

        if not os.path.exists(self.buildinfo_path):
            logging.error(f"Buildinfo file does not exist: {self.buildinfo_path}")
            raise BuildInfoException(f"Cannot find buildinfo file: {self.buildinfo_path}")

        with open(self.buildinfo_path) as fd:
            self.parsed_info = debian.deb822.BuildInfo(fd)

        self.process_buildinfo()

    def __getstate__(self):
        state = self.__dict__.copy()
        # Exclude non-pickleable attributes
        state['parsed_info'] = None
        state['checksums'] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Reinitialize non-pickled attributes if necessary
        if 'buildinfo_path' in state:
            with open(self.buildinfo_path) as fd:
                self.parsed_info = debian.deb822.BuildInfo(fd)
        # Restore checksums
        self.checksums = {}
        for alg in ("md5", "sha1", "sha256", "sha512"):
            if self.parsed_info.get(f"checksums-{alg}", None):
                self.checksums[alg] = self.parsed_info[f"checksums-{alg}"]

    def to_pickle_file(self, filepath):
        """Serialize the RebuilderBuildInfo object to a pickle file."""
        with open(filepath, 'wb') as f:
            pickle.dump(self, f)

    @classmethod
    def from_pickle_file(cls, filepath):
        """Deserialize a RebuilderBuildInfo object from a pickle file."""
        with open(filepath, 'rb') as f:
            return pickle.load(f)

    @staticmethod
    def find_new_buildinfo(directory):
        logging.debug(f"Searching for new buildinfo files in directory: {directory}")
        buildinfo_files = glob.glob(os.path.join(directory, "*.buildinfo"))
        if not buildinfo_files:
            logging.error("No buildinfo file found in the specified directory.")
            raise BuildInfoException("No buildinfo file found in the specified directory.")
        return max(buildinfo_files, key=os.path.getmtime)

    def process_buildinfo(self):
        logging.debug("Processing buildinfo content.")
        self.source, self.source_version = self.parsed_info.get_source()
        self.architecture = [arch for arch in self.parsed_info.get_architecture() if arch not in ("source", "all")]
        if len(self.architecture) > 1:
            logging.error("Multiple architectures found in Architecture field.")
            raise BuildInfoException("More than one architecture in Architecture field")
        self.binary = self.parsed_info.get_binary()
        self.version = self.parsed_info["version"]
        self.source_version = self.version if not self.source_version else self.source_version
        if ":" in self.version:
            self.version = self.version.split(":")[1]
        self.build_path = self.parsed_info.get("build-path", None)
        self.build_arch = self.parsed_info.get("build-architecture", None)
        if not self.build_arch:
            logging.error("Build-Architecture field is missing.")
            raise BuildInfoException("Need Build-Architecture field")
        self.build_date = self.parsed_info.get_build_date().strftime("%Y%m%dT%H%M%SZ")
        self.host_arch = self.parsed_info.get("host-architecture", self.build_arch)
        self.env = self.parsed_info.get_environment()
        self.build_source = self.parsed_info.is_build_source()
        self.build_archall = self.parsed_info.is_build_arch_all()
        self.build_archany = self.parsed_info.is_build_arch_any()

        self.checksums = {}
        for alg in ("md5", "sha1", "sha256", "sha512"):
            if self.parsed_info.get(f"checksums-{alg}", None):
                self.checksums[alg] = self.parsed_info[f"checksums-{alg}"]
                logging.debug(f"Checksums for {alg} loaded: {self.checksums[alg]}")

        self.logentry = self.parsed_info.get_changelog()
        if self.logentry:
            self.logentry = str(self.logentry).lstrip("\n") + "\n"
            logging.debug("Processed changelog entry from binNMU.")

        self.build_depends = []
        self.required_timestamps = {}
        self.archive_name = None
        self.source_date = None
        self.suite_name = None
        self.component_name = None

        logging.debug("RebuilderBuildInfo initialization complete.")

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


class Rebuilder:
    def __init__(self, custom_deb, builder_json_file, buildinfo_file, snapshot_url, snapshot_mirror,
                 extra_repository_files=None,
                 extra_repository_keys=None, gpg_sign_keyid=None, gpg_verify=False, gpg_verify_key=None, proxy=None,
                 use_metasnap=False, metasnap_url="http://snapshot.notset.fr", build_options_nocheck=False,
                 custom_package=None):
        self.custom_deb = custom_deb
        self.rebuilder_buildinfo_metadata_path = None
        self.builder_json_file = builder_json_file
        self.buildinfo_pickle_file = ""
        self.checkpoint_files = []
        self.checkpoint_dir = None
        self.consider_local_repo = False
        self.create_docker_image = None
        self.use_docker_image = None
        self.fallback_dsc_url = None
        self.buildinfo = None
        self.snapshot_url = snapshot_url
        self.base_mirror = f"{snapshot_mirror}/"
        self.extra_repository_files = extra_repository_files
        self.extra_repository_keys = extra_repository_keys
        self.gpg_sign_keyid = gpg_sign_keyid
        self.proxy = proxy
        self.session = requests.Session()
        self.session.proxies = {"http:": self.proxy, "https": self.proxy}
        self.use_metasnap = use_metasnap
        self.metasnap_url = metasnap_url
        self.build_options_nocheck = build_options_nocheck
        self.tempaptdir = None
        self.tempaptcache = None
        self.required_timestamp_sources = {}
        self.tmpdir = os.environ.get("TMPDIR", "/tmp")
        self.buildinfo_file = None
        self.custom_package = custom_package
        self.custom_package_dir = None  # Directory where custom package is prepared
        self.downloaded_packages = []  # Initialize downloaded_packages as an empty list
        self.bypassed_packages = set()
        self.updated_packages = {}
        self.newly_added_sources = []

        logger.debug(f"Input buildinfo: {buildinfo_file}")

        if buildinfo_file.startswith("http://") or buildinfo_file.startswith("https://"):
            resp = get_response(self, buildinfo_file)
            if not resp.ok:
                raise RebuilderException(f"Cannot get buildinfo: {resp.reason}")

            handle, self.buildinfo_file = tempfile.mkstemp(prefix="buildinfo-", dir=self.tmpdir)
            with open(handle, "w") as fd:
                fd.write(resp.text)
        else:
            self.buildinfo_file = os.path.realpath(buildinfo_file)

        if gpg_verify and gpg_verify_key:
            gpg_env = OpenPGPEnvironment()
            try:
                gpg_env.import_key(gpg_verify_key)
                data = gpg_env.verify_file(self.buildinfo_file)
                logger.info(f"GPG ({data.primary_key_fingerprint}): OK")
            except OpenPGPException as e:
                raise RebuilderException(f"Failed to verify buildinfo: {str(e)}")
            finally:
                gpg_env.close()

        self.buildinfo = RebuilderBuildInfo(self.buildinfo_file)

        # Prepare the custom package
        self.prepare_custom_package()

    def to_dict(self):
        """Serialize the Rebuilder object to a dictionary."""
        return {
            "buildinfo_file": self.buildinfo_file,
            "buildinfo_path": self.buildinfo.buildinfo_path,
            "snapshot_url": self.snapshot_url,
            "base_mirror": self.base_mirror,
            "extra_repository_files": self.extra_repository_files,
            "extra_repository_keys": self.extra_repository_keys,
            "gpg_sign_keyid": self.gpg_sign_keyid,
            "proxy": self.proxy,
            "use_metasnap": self.use_metasnap,
            "metasnap_url": self.metasnap_url,
            "build_options_nocheck": self.build_options_nocheck,
            "tempaptdir": self.tempaptdir,
            "required_timestamp_sources": self.required_timestamp_sources,
            "tmpdir": self.tmpdir,
            "custom_package": self.custom_package,
            "custom_package_dir": self.custom_package_dir,
            "downloaded_packages": self.downloaded_packages,
            "bypassed_packages": list(self.bypassed_packages),
            "updated_packages": self.updated_packages,
            "newly_added_sources": self.newly_added_sources,
            "checkpoint_dir": self.checkpoint_dir,
            "checkpoint_files": self.checkpoint_files,
            "rebuilder_buildinfo_metadata_path": self.rebuilder_buildinfo_metadata_path,
            "buildinfo_pickle_file": self.buildinfo_pickle_file,
            "custom_deb": self.custom_deb
        }

    @staticmethod
    def get_host_architecture():
        try:
            builder_architecture = (
                subprocess.check_output(["dpkg", "--print-architecture"])
                .decode("utf8")
                .rstrip("\n")
            )
        except FileNotFoundError:
            raise RebuilderException("Cannot determinate builder host architecture")
        return builder_architecture

    @classmethod
    def from_dict(cls, data, filepath):
        """Deserialize a Rebuilder object from a dictionary."""
        instance = cls(
            custom_deb=data["custom_deb"],
            builder_json_file=filepath,
            buildinfo_file=data["buildinfo_file"],
            snapshot_url=data["snapshot_url"],
            snapshot_mirror=data["base_mirror"],
            extra_repository_files=data["extra_repository_files"],
            extra_repository_keys=data["extra_repository_keys"],
            gpg_sign_keyid=data["gpg_sign_keyid"],
            gpg_verify=data.get("gpg_verify", False),
            gpg_verify_key=data.get("gpg_verify_key"),
            proxy=data["proxy"],
            use_metasnap=data["use_metasnap"],
            metasnap_url=data["metasnap_url"],
            build_options_nocheck=data["build_options_nocheck"],
            custom_package=data["custom_package"]
        )
        instance.tempaptdir = data["tempaptdir"]
        instance.required_timestamp_sources = data["required_timestamp_sources"]
        instance.tmpdir = data["tmpdir"]
        instance.custom_package_dir = data["custom_package_dir"]
        instance.downloaded_packages = data["downloaded_packages"]
        instance.bypassed_packages = set(data["bypassed_packages"])
        instance.updated_packages = data["updated_packages"]
        instance.newly_added_sources = data["newly_added_sources"]
        instance.checkpoint_dir = data["checkpoint_dir"]
        instance.checkpoint_files = data["checkpoint_files"]
        instance.rebuilder_buildinfo_metadata_path = data["rebuilder_buildinfo_metadata_path"]
        instance.buildinfo_pickle_file = data["buildinfo_pickle_file"]
        instance.buildinfo = RebuilderBuildInfo.from_pickle_file(instance.buildinfo_pickle_file)
        instance.custom_deb = data["custom_deb"]
        return instance

    def to_json_file(self, filepath):
        """Serialize the Rebuilder object to a JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)

    @classmethod
    def from_json_file(cls, filepath):
        """Deserialize a Rebuilder object from a JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data, filepath)

    def prepare_custom_package(self):
        if not self.custom_package:
            return

        if self.custom_package.endswith(".dsc"):
            subprocess.run(["dpkg-source", "-x", self.custom_package, "/tmp/custom-package"], check=True)
            self.custom_package_dir = "/tmp/custom-package"
        elif self.custom_package.endswith(".deb"):
            self.custom_package_dir = os.path.dirname(self.custom_package)
        else:
            raise RebuilderException(f"Unsupported custom package format: {self.custom_package}")

    def setup_local_repository(self):
        local_repo_dir = "/tmp/local_repo"
        os.makedirs(local_repo_dir, exist_ok=True)

        # Copy user-provided .deb files to the local repository directory
        for deb_path in self.custom_deb:
            if os.path.isfile(deb_path):
                shutil.copy(deb_path, local_repo_dir)
                logging.debug(f"Copied user-provided .deb file to {local_repo_dir}")
            else:
                logging.error(f"User-provided .deb file does not exist: {deb_path}")

        packages_file = os.path.join(local_repo_dir, "Packages")
        temp_packages_file = os.path.join(local_repo_dir, "Packages.temp")

        # Generate entries for the new .deb files
        try:
            with open(temp_packages_file, "w") as f:
                subprocess.run(["dpkg-scanpackages", local_repo_dir, "/dev/null"], stdout=f, check=True)
                logging.debug(f"Generated temp Packages file at {temp_packages_file}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to generate the temp Packages file: {e}")
            return False

        # Ensure the Packages file exists and is properly updated
        try:
            if os.path.exists(packages_file):
                with open(packages_file, "a") as f:
                    with open(temp_packages_file, "r") as temp_f:
                        f.write(temp_f.read())
                os.remove(temp_packages_file)
            else:
                os.rename(temp_packages_file, packages_file)
            logging.debug(f"Updated Packages file at {packages_file}")
        except Exception as e:
            logging.error(f"Failed to update the Packages file: {e}")
            return False

        # Compress the Packages file and overwrite if it exists
        try:
            subprocess.run(["gzip", "-kf", packages_file], check=True)
            logging.debug(f"Compressed Packages file to {packages_file}.gz")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to compress the Packages file: {e}")
            return False

        # Verify the Packages.gz file exists
        if not os.path.exists(packages_file + ".gz"):
            logging.error(f"Packages file {packages_file}.gz does not exist.")
            return False

        local_repo_entry = f"deb [trusted=yes] file://{local_repo_dir} ./"
        temp_sources_list = os.path.join(self.tempaptdir, "etc/apt/sources.list")

        # Reading the sources list file
        with open(temp_sources_list, "r") as fd:
            lines = fd.readlines()

        # Add the local repo entry if not already present
        if local_repo_entry not in lines:
            with open(temp_sources_list, "a") as fd:
                fd.write(f"{local_repo_entry}\n")
                self.newly_added_sources.append(local_repo_entry)

        # Remove duplicate entries from the sources list
        seen = set()
        unique_lines = []
        for line in lines + [local_repo_entry + '\n']:
            if line not in seen:
                unique_lines.append(line)
                seen.add(line)

        # Write back the unique lines
        with open(temp_sources_list, "w") as fd:
            fd.writelines(unique_lines)

        # Update the APT cache
        try:
            self.tempaptcache.close()  # Ensure cache is closed before updating
            logging.debug("APT cache closed successfully.")
            self.tempaptcache.update(sources_list=temp_sources_list)
            logging.debug("APT cache update called.")
            self.tempaptcache.open()  # Reopen cache after update
            logging.debug("APT cache reopened successfully.")
        except Exception as e:
            logging.error(f"Error updating APT cache: {e}")
            return False

        logging.debug(f"Local repository setup completed successfully.")
        return True

    def try_direct_through_deb(self, notfound_pkg):
        package_name_version = notfound_pkg.to_apt_install_format()
        package_name, version = package_name_version.split('=')
        package_url = f"https://packages.debian.org/sid/amd64/{package_name}/download"

        try:
            response = requests.get(package_url)
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"Failed to fetch the package download page: {e}")
            return False

        soup = BeautifulSoup(response.text, 'html.parser')
        deb_link = None
        deb_file_name = None
        for link in soup.find_all('a'):
            href = link.get('href')
            if "ftp.us.debian.org/debian" in href:
                deb_link = href
                deb_file_name = href.split('/')[-1]
                break

        if not deb_link:
            logging.error("Failed to find the .deb file link on the download page.")
            return False

        # Use a common local repository directory
        local_repo_dir = "/tmp/local_repo"
        os.makedirs(local_repo_dir, exist_ok=True)
        deb_file_path = os.path.join(local_repo_dir, deb_file_name)

        try:
            with requests.get(deb_link, stream=True) as r:
                r.raise_for_status()
                with open(deb_file_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            logging.debug(f"Downloaded .deb file to {deb_file_path}")
        except requests.RequestException as e:
            logging.error(f"Failed to download the .deb file: {e}")
            return False

        packages_file = os.path.join(local_repo_dir, "Packages")
        temp_packages_file = os.path.join(local_repo_dir, "Packages.temp")

        # Generate entries for the new .deb file
        try:
            with open(temp_packages_file, "w") as f:
                subprocess.run(["dpkg-scanpackages", local_repo_dir, "/dev/null"], stdout=f, check=True)
            logging.debug(f"Generated temp Packages file at {temp_packages_file}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to generate the temp Packages file: {e}")
            return False

        # Ensure the Packages file exists and is properly updated
        try:
            if os.path.exists(packages_file):
                with open(packages_file, "a") as f:
                    with open(temp_packages_file, "r") as temp_f:
                        f.write(temp_f.read())
                os.remove(temp_packages_file)
            else:
                os.rename(temp_packages_file, packages_file)
            logging.debug(f"Updated Packages file at {packages_file}")
        except Exception as e:
            logging.error(f"Failed to update the Packages file: {e}")
            return False

        # Compress the Packages file and overwrite if it exists
        try:
            subprocess.run(["gzip", "-kf", packages_file], check=True)
            logging.debug(f"Compressed Packages file to {packages_file}.gz")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to compress the Packages file: {e}")
            return False

        # Verify the Packages.gz file exists
        if not os.path.exists(packages_file + ".gz"):
            logging.error(f"Packages file {packages_file}.gz does not exist.")
            return False

        local_repo_entry = f"deb [trusted=yes] file://{local_repo_dir} ./"
        temp_sources_list = os.path.join(self.tempaptdir, "etc/apt/sources.list")

        # Reading the sources list file
        with open(temp_sources_list, "r") as fd:
            lines = fd.readlines()

        # Add the local repo entry if not already present
        if local_repo_entry not in lines:
            with open(temp_sources_list, "a") as fd:
                fd.write(f"{local_repo_entry}\n")
                self.newly_added_sources.append(local_repo_entry)

        # Remove duplicate entries from the sources list
        seen = set()
        unique_lines = []
        for line in lines + [local_repo_entry + '\n']:
            if line not in seen:
                unique_lines.append(line)
                seen.add(line)

        # Write back the unique lines
        with open(temp_sources_list, "w") as fd:
            fd.writelines(unique_lines)

        # Update the APT cache
        try:
            self.tempaptcache.close()  # Ensure cache is closed before updating
            logging.debug("APT cache closed successfully.")
            self.tempaptcache.update(sources_list=temp_sources_list)
            logging.debug("APT cache update called.")
            self.tempaptcache.open()  # Reopen cache after update
            logging.debug("APT cache reopened successfully.")
        except Exception as e:
            logging.error(f"Error updating APT cache: {e}")
            return False

        # Check if the package is found in the updated cache
        try:
            pkg = self.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")
            if pkg and notfound_pkg.version in pkg.versions.keys():
                logging.debug(f"Package {notfound_pkg.to_apt_install_format()} found in APT cache.")
                # Remove the added source list entry if the package is found
                with open(temp_sources_list, "r+") as fd:
                    lines = fd.readlines()
                    fd.seek(0)
                    fd.writelines([line for line in lines if line.strip() != local_repo_entry])
                    fd.truncate()
                self.newly_added_sources.remove(local_repo_entry)
                return True  # Package found, return True
        except Exception as e:
            logging.error(f"Error checking APT cache for package: {e}")

        # Remove the added source list entry if the package is not found
        with open(temp_sources_list, "r+") as fd:
            lines = fd.readlines()
            fd.seek(0)
            fd.writelines([line for line in lines if line.strip() != local_repo_entry])
            fd.truncate()
            self.newly_added_sources.remove(local_repo_entry)
        logging.debug(
            f"try_direct_through_deb::Package {notfound_pkg.to_apt_install_format()} not found. Reverting changes.")

        return True

    def try_snapshot_sources(self, notfound_pkg):
        # Dynamically generate snapshot source links, add to sources list, check, and clean up if not found
        years = range(2024, 2018, -1)  # Example range, adjust as needed
        for year in years:
            temp_sources_list = self.tempaptdir + "/etc/apt/sources.list"
            logging.debug(f"try_snapshot_sources::temp_sources_list is {temp_sources_list}.")

            for month in range(1, 13, 3):  # Iterate over all every 3 months
                snapshot_sources = self.find_packages_in_snapshots(year, month)
                if snapshot_sources:
                    with open(temp_sources_list, "a") as fd:
                        for source in snapshot_sources:
                            fd.write(f"{source}\n")  # Write each source with a newline
                            fd.flush()
                            self.newly_added_sources.append(source)

                    # Update the APT cache after adding each month's sources
                    try:
                        self.tempaptcache.close()  # Ensure cache is closed before updating
                        logger.debug(f"try_snapshot_sources::APT cache closed successfully for {year}-{month}.")
                        self.tempaptcache.update(sources_list=temp_sources_list)
                        logger.debug(f"try_snapshot_sources::APT cache update called for {year}-{month}.")
                        self.tempaptcache.open()  # Reopen cache after update
                        logger.debug(f"try_snapshot_sources::APT cache reopened successfully for {year}-{month}.")
                    except Exception as e:
                        logging.error(f"Error updating APT cache for {year}-{month}: {e}")
                        raise  # Re-raise the exception to handle it at a higher level or to halt the program

                    # Attempt to find the package in the updated cache
                    pkg = self.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")
                    if pkg and notfound_pkg.version in pkg.versions.keys():
                        logger.debug(
                            f"try_snapshot_sources::Package {notfound_pkg.to_apt_install_format()} found in APT cache for {year}-{month}.")
                        return True  # Package found, return True and the current year

                    # If package is not found, close the cache and revert the sources list
                    self.tempaptcache.close()
                    with open(temp_sources_list, "r+") as fd:
                        lines = fd.readlines()
                        fd.seek(0)
                        # Remove the entries added for this month only
                        fd.writelines(lines[:-len(snapshot_sources)])
                        fd.truncate()
                        fd.flush()
                        self.newly_added_sources = self.newly_added_sources[:-len(snapshot_sources)]
                    logger.debug(
                        f"try_snapshot_sources::Package {notfound_pkg.to_apt_install_format()} not found for {year}-{month}. Reverting changes.")

        return False  # Return False and the decremented year

    def fetch_all_available_timestamps(self, year, month):
        # Construct URL to fetch the page that lists all snapshots for a given month and year
        url = f"https://snapshot.debian.org/archive/debian/?year={year}&month={month}"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Find all <a> tags which might contain the timestamps
            links = soup.find_all('a', href=True)  # Find all <a> tags with href attributes
            # Extract timestamps and limit the number to 5
            timestamps = [link['href'].strip('/') for link in links if 'T' in link['href']][:3]
            if timestamps:
                logger.debug(f"Available timestamps for {year}-{month} (limited to 6 or fewer): {timestamps}")
                return timestamps
            else:
                logger.debug(f"No timestamps found for {year}-{month}")
                return []
        else:
            logging.error(f"Failed to retrieve data from snapshot.debian.org with status code: {response.status_code}")
            return []

    def check_release_file_exists(self, url):
        try:
            response = requests.head(url)
            return response.status_code == 200
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")
            return False

    def find_packages_in_snapshots(self, year, month):
        if year == 2024 and month >= 7:
            return []
        timestamps = self.fetch_all_available_timestamps(year, month)
        all_entries = []
        if timestamps:
            base_url = "http://snapshot.debian.org/archive/debian"

            # Distribution and components are typical for Debian repositories
            distribution = "sid"
            component = "main"

            for timestamp in timestamps:
                timestamp = timestamp.strip('/')  # Clean up timestamp
                # Construct the source entries
                deb_entry = f"deb {base_url}/{timestamp}/ {distribution} {component}"
                deb_src_entry = f"deb-src {base_url}/{timestamp}/ {distribution} {component}"
                #logger.debug("deb_entry:", deb_entry)

                release_url = f"{base_url}/{timestamp}/dists/{distribution}/Release"
                all_entries.extend([deb_entry, deb_src_entry])

                logging.info("Constructed package source entries for all timestamps.")
                return all_entries
        else:
            logging.error(f"Unable to find any snapshots for {year}-{month}")
            return []


def add_checkpoint_file(self, file_path, description):
    relative_path = os.path.relpath(file_path, self.checkpoint_dir)
    self.checkpoint_files.append({
        "path": relative_path,
        "description": description
    })


def initialize_and_find_dependencies(rebuilder):
    logger.debug("Starting the initialization and dependency finding process")

    # Determine build architecture
    logger.debug("Determining build architecture...")
    if rebuilder.buildinfo.architecture:
        build_arch = rebuilder.get_host_architecture()
        logger.debug(f"Determined build architecture from buildinfo: {build_arch}")
    elif rebuilder.buildinfo.build_archall:
        build_arch = "all"
        logger.debug("Building for all architectures.")
    elif rebuilder.buildinfo.build_source:
        build_arch = "source"
        logger.debug("Building from source.")
    else:
        logger.error("Failed to determine what to build.")
        raise RebuilderException("Nothing to build")

    # Perform pre-checks
    logger.debug("Performing pre-checks for keyrings...")
    for key in DEBIAN_KEYRINGS:
        if not os.path.exists(key):
            logger.error(f"Keyring not found: {key}")
            raise RebuilderException(
                f"Cannot find {key}. Ensure to have installed debian-keyring, debian-archive-keyring, and debian-ports-archive-keyring.")
    logger.debug("Keyring pre-checks completed successfully.")

    # Initialize and find build dependencies
    logger.debug("Initializing and finding build dependencies...")
    try:
        if rebuilder.use_metasnap:
            logger.debug("Using metasnap for getting required timestamps.")
            find_build_dependencies_from_metasnap(rebuilder)
        if not rebuilder.required_timestamp_sources:
            logger.debug("Using standard snapshot method for getting required timestamps.")
            find_build_dependencies(rebuilder)
    except (apt_pkg.Error, apt.cache.FetchFailedException, requests.exceptions.ConnectionError) as e:
        logger.error(f"Failed to fetch packages: {str(e)}")
        raise RebuilderException(f"Failed to fetch packages: {str(e)}")
    except KeyboardInterrupt:
        logger.error("Operation interrupted by user.")
        raise RebuilderException("Interruption")

    # Clean up and create checkpoint
    logger.debug("Cleaning up temporary directories...")
    if rebuilder.tempaptdir and rebuilder.tempaptdir.startswith(os.path.join(rebuilder.tmpdir, "debrebuild-")):
        if rebuilder.tempaptcache:
            rebuilder.tempaptcache.close()
        checkpoint_dir = os.path.join("build_checkpoint", rebuilder.buildinfo.source)
        os.makedirs(checkpoint_dir, exist_ok=True)
        dest_dir = os.path.join(checkpoint_dir, os.path.basename(rebuilder.tempaptdir))
        shutil.copytree(rebuilder.tempaptdir, dest_dir)
        add_checkpoint_file(rebuilder, dest_dir, "tempaptdir")
        shutil.rmtree(rebuilder.tempaptdir)
        logger.debug("Temporary directories cleaned up.")
        rebuilder.checkpoint_dir = checkpoint_dir
        rebuilder.checkpoint_files = [os.path.relpath(os.path.join(root, file), checkpoint_dir)
                                      for root, _, files in os.walk(dest_dir) for file in files]

    # Save the updated state
    if not rebuilder.builder_json_file:
        new_json_file = os.path.join(rebuilder.checkpoint_dir, f"checkpoint_find_dep_{rebuilder.buildinfo.source}.json")
        new_buildinfo_pickle_file = os.path.join(rebuilder.checkpoint_dir,
                                                 f"checkpoint_find_dep_{rebuilder.buildinfo.source}.pkl")
        rebuilder.buildinfo_pickle_file = new_buildinfo_pickle_file
        rebuilder.builder_json_file = new_json_file
        rebuilder.to_json_file(new_json_file)
        rebuilder.buildinfo.to_pickle_file(new_buildinfo_pickle_file)
        logger.debug(f"Rebuilder state saved to {new_json_file}")
        logger.debug(f"Rebuilder Buildinfo state saved to {new_buildinfo_pickle_file}")
    else:
        rebuilder.to_json_file(rebuilder.builder_json_file)
        rebuilder.buildinfo.to_pickle_file(rebuilder.buildinfo_pickle_file)
        logger.debug(f"Rebuilder state saved to {rebuilder.builder_json_file}")
        logger.debug(f"Rebuilder Buildinfo state saved to {rebuilder.buildinfo_pickle_file}")


def find_build_dependencies(rebuilder):
    # Prepare APT cache for finding dependencies
    if rebuilder.checkpoint_files:
        for checkpoint in rebuilder.checkpoint_files:
            relative_name = checkpoint["path"]
            src_path = os.path.join(rebuilder.checkpoint_dir, relative_name)
            dest_path = os.path.join(rebuilder.tempaptdir, relative_name)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy(str(src_path), str(dest_path))

        # Open and update the APT cache
        rebuilder.prepare_aptcache()
        notfound_packages = [pkg for pkg in rebuilder.buildinfo.get_build_depends()]
        for notfound_pkg in notfound_packages.copy():
            pkg = rebuilder.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")
            if pkg is not None and pkg.versions.get(notfound_pkg.version) is not None:
                notfound_packages.remove(notfound_pkg)

        if not notfound_packages:
            return
        else:
            logger.debug("Some packages are missing, proceeding to resolve dependencies.")

    prepare_aptcache(rebuilder)

    notfound_packages = [pkg for pkg in rebuilder.buildinfo.get_build_depends()]
    temp_sources_list = rebuilder.tempaptdir + "/etc/apt/sources.list"
    with open(temp_sources_list, "a") as fd:
        for location, repositories in get_sources_list_from_timestamp(rebuilder).items():
            for timestamp_source, pkgs in repositories:
                if not notfound_packages:
                    break
                if not any(
                        pkg.to_apt_install_format()
                        in [p.to_apt_install_format() for p in notfound_packages]
                        for pkg in pkgs
                ):
                    logger.info(f"Skipping snapshot: {timestamp_source}")
                    continue
                logger.info(f"Remaining packages to be found: {len(notfound_packages)}")
                rebuilder.required_timestamp_sources.setdefault(location, []).append(timestamp_source)
                logger.debug(f"Timestamp source ({len(pkgs)} packages): {timestamp_source}")
                fd.write(f"\n{timestamp_source}")
                fd.flush()

                # provides sources.list explicitly, otherwise `update()`
                # doesn't reload it until the next `open()`
                rebuilder.tempaptcache.update(sources_list=temp_sources_list)
                rebuilder.tempaptcache.open()

                for notfound_pkg in notfound_packages.copy():
                    pkg = rebuilder.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")
                    if pkg is not None and pkg.versions.get(notfound_pkg.version) is not None:
                        notfound_packages.remove(notfound_pkg)

                if rebuilder.custom_deb:
                    rebuilder.setup_local_repository()
                rebuilder.tempaptcache.close()

    if notfound_packages:
        for notfound_pkg in notfound_packages:
            logger.debug(f"{notfound_pkg.name}-{notfound_pkg.version}.{notfound_pkg.architecture}")
        raise RebuilderException("Cannot locate the following packages via snapshots or the current repo/mirror")


def prepare_aptcache(rebuilder):
    # create a temporary directory where all APT configuration files will be stored
    rebuilder.tempaptdir = tempfile.mkdtemp(prefix="debrebuild-", dir=rebuilder.tmpdir)
    logger.debug(f"Temporary APT directory: {rebuilder.tempaptdir}")

    # Define paths for APT config and sources list within the temp directory
    temp_apt_conf = f"{rebuilder.tempaptdir}/etc/apt/apt.conf"
    logger.debug(f"APT config file: {temp_apt_conf}")

    temp_sources_list = f"{rebuilder.tempaptdir}/etc/apt/sources.list"
    logger.debug(f"APT sources list file: {temp_sources_list}")

    apt_dirs = ["/etc/apt", "/etc/apt/trusted.gpg.d"]
    for directory in apt_dirs:
        full_path = f"{rebuilder.tempaptdir}{directory}"
        os.makedirs(full_path, exist_ok=True)
        logger.debug(f"Created directory: {full_path}")

    # write a custom APT configuration to handle packages without standard security measures
    # like GPG.
    with open(temp_apt_conf, "w") as fd:
        apt_conf = """
            Apt {{
               Architecture "{build_arch}";
               Architectures "{build_arch}";
            }};
            
            Acquire::Check-Valid-Until "false";
            Acquire::Languages "none";
            Acquire::http::Dl-Limit "1000";
            Acquire::https::Dl-Limit "1000";
            Acquire::Retries "5";
            Binary::apt::APT::Get::AllowUnauthenticated "true";
            Binary::apt::APT::Get::AllowInsecureRepositories "true";
            APT::Get::AllowUnauthenticated "true";
            APT::Acquire::AllowInsecureRepositories "true";
            APT::Authentication::TrustCDROM "true";
            """.format(build_arch=rebuilder.buildinfo.build_arch, tempdir=rebuilder.tempaptdir)
        if rebuilder.proxy:
            apt_conf += f'\nAcquire::http::proxy "{rebuilder.proxy}";\n'
        fd.write(apt_conf)
        logger.debug(f"Written APT config: {apt_conf}")

    with open(temp_sources_list, "w") as fd:
        sources_list_content = "\n".join(get_sources_list(rebuilder))
        fd.write(sources_list_content)
    logger.debug(f"Written APT sources list: {sources_list_content}")

    keyrings = DEBIAN_KEYRINGS
    if rebuilder.extra_repository_keys:
        keyrings += rebuilder.extra_repository_keys
    for keyring_src in keyrings:
        keyring_dst = f"{rebuilder.tempaptdir}/etc/apt/trusted.gpg.d/{os.path.basename(keyring_src)}"
        os.symlink(keyring_src, keyring_dst)
        logger.debug(f"Linked keyring: {keyring_src} to {keyring_dst}")

    try:
        logger.debug("Initializing APT cache")
        # Initialze an APT cache object pointed at the temporary directory which allows manipulation
        # of package states (like installation and removal) from the host's package system
        rebuilder.tempaptcache = apt.Cache(rootdir=rebuilder.tempaptdir, memonly=True)
        rebuilder.tempaptcache.close()
    except (PermissionError, apt_pkg.Error) as e:
        logger.error(f"Error initializing APT cache: {e}")
        raise RebuilderException("Failed to initialize APT cache")


def find_build_dependencies_from_metasnap(rebuilder):
    status = False
    files = {"buildinfo": open(rebuilder.buildinfo_file, "rb")}

    # It means someone wants to use original metasnap service which is not
    # compatible with the default JSON layout from snapshot.notset.fr
    if "metasnap.debian.net" in rebuilder.metasnap_url:
        metasnap_endpoint = f"{rebuilder.metasnap_url}/cgi-bin/api"
    else:
        metasnap_endpoint = f"{rebuilder.metasnap_url}/mr/buildinfo"

    try:
        resp = rebuilder.session.post(metasnap_endpoint, files=files)
        if not resp.ok:
            msg = f"{resp.status_code} ({resp.reason})"
        else:
            status = True
    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        pass

    if not status:
        logger.error(f"Cannot get timestamps from metasnap: {msg}")
        return

    if "metasnap.debian.net" in rebuilder.metasnap_url:
        # It means someone wants to use original metasnap service which is not
        # compatible with the default JSON layout from snapshot.notset.fr

        # latest first
        content = reversed(resp.text.strip("\n").split("\n"))
        for line in content:
            arch, timestamp = line.split()
            if arch != rebuilder.buildinfo.build_arch:
                raise RebuilderException("Unable to handle multiple architectures")
            rebuilder.required_timestamp_sources.setdefault(
                "debian+unstable+main", []
            ).append(f"deb  {rebuilder.base_mirror}/archive/debian/{timestamp}/ unstable main")

            # We store timestamp value itself for the base mirror used for creating chroot
            rebuilder.buildinfo.required_timestamps.setdefault(
                "debian+unstable+main", []
            ).append(timestamp)
    else:
        try:
            content = resp.json()["results"]
        except Exception as e:
            logger.error(f"Cannot get timestamps from metasnap: {str(e)}")
            return

        timestamps_sets = sorted(content, key=lambda x: len(x["timestamps"]))
        archive = timestamps_sets[0]["archive_name"]
        suite = timestamps_sets[0]["suite_name"]
        component = timestamps_sets[0]["component_name"]
        key = f"{archive}+{suite}+{component}"
        for timestamp in timestamps_sets[0]["timestamps"]:
            rebuilder.required_timestamps.setdefault(key, []).append(
                f"deb  {rebuilder.base_mirror}/archive/{archive}/{timestamp}/ {suite} {component}"
            )
            rebuilder.buildinfo.required_timestamps.setdefault(key, []).append(timestamp)


def get_response(self, url):
    try:
        resp = self.session.get(url)
    except requests.exceptions.ConnectionError as e:
        # logger.error(f"Failed to get URL {url}: {str(e)}")
        # WIP: forge a better response?
        resp = requests.models.Response()
        resp.status_code = 503
        resp.reason = str(e)
    return resp


# TODO: refactor get_src_date and get_bin_date. Do a better distinction between "BuildInfo"
#  and the source package which as to be defined.
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


def get_bin_date(self, package):
    pkgname = package.name
    pkgver = package.version
    pkgarch = package.architecture
    json_url = (
        f"{self.snapshot_url}/mr/binary/{pkgname}/{pkgver}/binfiles?fileinfo=1"
    )
    logger.debug(f"Get binary package info: {pkgname}={pkgver}")
    logger.debug(f"Binary URL: {json_url}")

    data = None
    for attempt in range(10):  # Retry up to 10 times
        resp = get_response(self, json_url)
        try:
            data = resp.json()
            break  # Exit the loop if parsing is successful
        except json.decoder.JSONDecodeError:
            logger.warning(
                f"Attempt {attempt + 1}: Cannot parse response for package: {pkgname}. Retrying in 3 seconds...")
            time.sleep(3)

    if data is None:
        raise RebuilderException(
            f"Cannot parse response for package: {pkgname} after 10 attempts"
        )

    pkghash = None
    if len(data.get("result", [])) == 1:
        pkghash = data["result"][0]["hash"]
        package.architecture = data["result"][0]["architecture"]
        if pkgarch and pkgarch != package.architecture:
            raise RebuilderException(
                f"Package {pkgname} was explicitly requested "
                f"{pkgarch} but only {package.architecture} was found"
            )
        if (
                not pkgarch
                and self.buildinfo.build_arch != package.architecture
                and "all" != package.architecture
        ):
            raise RebuilderException(
                f"Package {pkgname} was implicitly requested "
                f"{self.buildinfo.build_arch} but only "
                f"{package.architecture} was found"
            )
        pkgarch = package.architecture
    else:
        if not pkgarch:
            pkgarch = self.buildinfo.build_arch
        for result in data.get("result", []):
            if result["architecture"] == pkgarch:
                pkghash = result["hash"]
                break
        if not pkghash:
            raise RebuilderException(
                f"Cannot find package in architecture {pkgarch}"
            )
        package.architecture = pkgarch

    binary_info = [pkg for pkg in data["fileinfo"].get(pkghash, [])]
    if not binary_info:
        raise RebuilderException(
            f"No binary info found for {pkgname}:{pkgarch}-{pkgver}"
        )
    package.hash = pkghash
    package.archive_name = "debian"
    package.timestamp = binary_info[0]["first_seen"]
    package.suite_name = "sid"
    package.component_name = "main"
    return (
        package.archive_name,
        package.timestamp,
        package.suite_name,
        package.component_name,
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


def get_build_depends_timestamps(self):
    """
    Returns a dict with keys Debian archives and
    values lists of tuple(timestamp, pkgs)
    where pkgs is a list of packages living there
    """
    required_timestamps = {}
    for pkg in self.buildinfo.get_build_depends():
        if not pkg.timestamp:
            get_bin_date(self, pkg)
        timestamp = parsedate(pkg.timestamp).strftime("%Y%m%dT%H%M%SZ")
        location = f"{pkg.archive_name}+{pkg.suite_name}+{pkg.component_name}"
        required_timestamps.setdefault(location, {}).setdefault(
            timestamp, []
        ).append(pkg)

        # We store timestamp value itself for the base mirror used for creating chroot
        self.buildinfo.required_timestamps.setdefault(location, []).append(
            timestamp
        )

    location_required_timestamps = {}
    for location, timestamps in required_timestamps.items():
        # sort by the number of packages found there, convert to list of tuples
        timestamps = sorted(
            timestamps.items(), key=lambda x: len(x[1]), reverse=True
        )
        location_required_timestamps[location] = timestamps
    return location_required_timestamps


def get_sources_list_from_timestamp(self):
    """
    Returns a dict with keys archive+suite+component and
    values lists inline Debian repositories
    """
    sources_list = {}
    for location, timestamps in get_build_depends_timestamps(self).items():
        for timestamp, pkgs in timestamps:
            archive, suite, component = location.split("+", 3)
            # Adjust URL structure to fit Debian archive layout
            sources_list.setdefault(location, []).append(
                (
                    f"deb  {self.base_mirror}/archive/{archive}/{timestamp}/ {suite} {component}",
                    pkgs,
                )
            )
    return sources_list


if __name__ == "__main__":
    builder_json_file = sys.argv[1]

    # Load the builder arguments from the JSON file
    with open(builder_json_file, 'r') as f:
        builder_args = json.load(f)

    # Create the Rebuilder instance using the arguments dictionary
    rebuilder = Rebuilder(
        custom_deb=builder_args["custom_deb"],
        builder_json_file=builder_args["builder_json_file"],
        buildinfo_file=builder_args["buildinfo_file"],
        snapshot_url=builder_args["snapshot_url"],
        snapshot_mirror=builder_args["snapshot_mirror"],
        extra_repository_files=builder_args["extra_repository_files"],
        extra_repository_keys=builder_args["extra_repository_keys"],
        gpg_sign_keyid=builder_args["gpg_sign_keyid"],
        gpg_verify=builder_args["gpg_verify"],
        gpg_verify_key=builder_args["gpg_verify_key"],
        proxy=builder_args["proxy"],
        use_metasnap=builder_args["use_metasnap"],
        metasnap_url=builder_args["metasnap_url"],
        build_options_nocheck=builder_args["build_options_nocheck"]
    )

    initialize_and_find_dependencies(rebuilder)
