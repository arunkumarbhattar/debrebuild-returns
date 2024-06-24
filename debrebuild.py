#!/usr/bin/python3
#
# Copyright (C) 2021 Frédéric Pierret (fepitre) <frederic.pierret@qubes-os.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from shlex import quote, join

import apt
import apt_pkg
import debian.deb822
import debian.debian_support
import requests
import rstr
from dateutil.parser import parse as parsedate

from lib.downloads import download_with_retry
from lib.openpgp import OpenPGPEnvironment, OpenPGPException

logger = logging.getLogger("debrebuild")
console_handler = logging.StreamHandler(sys.stderr)
logger.addHandler(console_handler)

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


# Adapted from reproducible-builds/reprotest
def run_or_tee(progargs, filename, store_dir, *args, **kwargs):
    if store_dir:
        tee = subprocess.Popen(
            ["tee", filename],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            cwd=store_dir,
        )
        r = subprocess.run(progargs, *args, stdout=tee.stdin, **kwargs)
        tee.communicate()
        return r
    else:
        return subprocess.run(progargs, *args, **kwargs)


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


class RebuilderBuildInfo:
    def __init__(self, buildinfo_file):

        if not os.path.exists(buildinfo_file):
            raise BuildInfoException(f"Cannot find buildinfo file: {buildinfo_file}")

        with open(buildinfo_file) as fd:
            self.parsed_info = debian.deb822.BuildInfo(fd)

        # in case of binnmu we have e.g.
        #   Source: 0ad (0.0.23-1)
        self.source, self.source_version = self.parsed_info.get_source()
        self.architecture = [
            arch
            for arch in self.parsed_info.get_architecture()
            if arch not in ("source", "all")
        ]
        if len(self.architecture) > 1:
            raise BuildInfoException("More than one architecture in Architecture field")
        self.binary = self.parsed_info.get_binary()
        self.version = self.parsed_info["version"]
        if not self.source_version:
            self.source_version = self.version
        if ":" in self.version:
            self.version = self.version.split(":")[1]
        self.build_path = self.parsed_info.get("build-path", None)
        self.build_arch = self.parsed_info.get("build-architecture", None)
        if not self.build_arch:
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

        self.logentry = self.parsed_info.get_changelog()
        if self.logentry:
            # Due to storing the binnmu changelog entry in deb822 buildinfo,
            # the first character is an unwanted newline
            self.logentry = str(self.logentry).lstrip("\n")
            # while the linebreak at the beginning is wrong, there are one
            # missing at the end
            self.logentry += "\n"

        self.build_depends = []
        self.required_timestamps = {}
        self.archive_name = None
        self.source_date = None
        self.suite_name = None
        self.component_name = None

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
    def __init__(self, buildinfo_file, snapshot_url, snapshot_mirror, extra_repository_files=None, extra_repository_keys=None, gpg_sign_keyid=None, gpg_verify=False, gpg_verify_key=None, proxy=None, use_metasnap=False, metasnap_url="http://snapshot.notset.fr", build_options_nocheck=False, custom_package=None):
        self.buildinfo = None
        self.snapshot_url = snapshot_url
        self.base_mirror = f"{snapshot_mirror}/archive/"
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

        logger.debug(f"Input buildinfo: {buildinfo_file}")

        if buildinfo_file.startswith("http://") or buildinfo_file.startswith("https://"):
            resp = self.get_response(buildinfo_file)
            if not resp.ok:
                raise RebuilderException(f"Cannot get buildinfo: {resp.reason}")

            handle, self.buildinfo_file = tempfile.mkstemp(prefix="buildinfo-", dir=self.tmpdir)
            with open(handle, "w") as fd:
                fd.write(resp.text)
        else:
            self.buildinfo_file = realpath(buildinfo_file)

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

    def get_env(self):
        env = []
        for key, val in self.buildinfo.env.items():
            env.append(f'{key}="{val}"')
        if self.build_options_nocheck:
            env.append("DEB_BUILD_OPTIONS=nocheck")
        return env

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

    def download_from_snapshot(self, path, sha256):
        url = f"{self.snapshot_url}/mr/file/{sha256}/download"
        if not requests.head(url, timeout=10).ok:
            raise RebuilderException(f"Cannot find URL: {url}")
        return download_with_retry(url, path, sha256)

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
        resp = self.get_response(json_url)
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
        self.buildinfo.source_date = source_info["first_seen"]

        # Assuming 'sid' and 'main' as defaults if they cannot be determined from the path
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
            resp = self.get_response(json_url)
            try:
                data = resp.json()
                break  # Exit the loop if parsing is successful
            except json.decoder.JSONDecodeError:
                logger.warning(f"Attempt {attempt + 1}: Cannot parse response for package: {pkgname}. Retrying in 3 seconds...")
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
        sources_list = []
        archive_name, source_date, dist, component = self.get_src_date()
        base_url = f"{self.base_mirror}/{archive_name}/{source_date}"

        # Adding [trusted=yes] to the repository entries
        build_repo = f"deb [trusted=yes] {base_url} {dist} {component}"
        sources_list.append(build_repo)

        source_repo = f"deb-src [trusted=yes] {base_url} {dist} {component}"
        sources_list.append(source_repo)

        if self.extra_repository_files:
            for repo_file in self.extra_repository_files:
                try:
                    with open(repo_file) as fd:
                        for line in fd:
                            if not line.startswith("#") and not line.startswith("\n"):
                                cleaned_line = line.rstrip('\n')  # Handle outside the f-string
                                sources_list.append(f"deb [trusted=yes] {cleaned_line}")
                except FileNotFoundError:
                    raise RebuilderException(
                        f"Cannot find repository file: {repo_file}"
                    )

        # Custom package directory handled with [trusted=yes]
        if self.custom_package and self.custom_package_dir:
            sources_list.append(f"deb [trusted=yes] file:{self.custom_package_dir} ./")

        return sources_list

    def get_sources_list_timestamps(self):
        """
        Returns all timestamp inline Debian repositories for all archives
        """
        sources_list = []
        for sources in self.required_timestamp_sources.values():
            sources_list += sources
        return sources_list

    def find_build_dependencies_from_metasnap(self):
        status = False
        files = {"buildinfo": open(self.buildinfo_file, "rb")}

        # It means someone wants to use original metasnap service which is not
        # compatible with the default JSON layout from snapshot.notset.fr
        if "metasnap.debian.net" in self.metasnap_url:
            metasnap_endpoint = f"{self.metasnap_url}/cgi-bin/api"
        else:
            metasnap_endpoint = f"{self.metasnap_url}/mr/buildinfo"

        try:
            resp = self.session.post(metasnap_endpoint, files=files)
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

        if "metasnap.debian.net" in self.metasnap_url:
            # It means someone wants to use original metasnap service which is not
            # compatible with the default JSON layout from snapshot.notset.fr

            # latest first
            content = reversed(resp.text.strip("\n").split("\n"))
            for line in content:
                arch, timestamp = line.split()
                if arch != self.buildinfo.build_arch:
                    raise RebuilderException("Unable to handle multiple architectures")
                self.required_timestamp_sources.setdefault(
                    "debian+unstable+main", []
                ).append(f"deb {self.base_mirror}/debian/{timestamp}/ unstable main")

                # We store timestamp value itself for the base mirror used for creating chroot
                self.buildinfo.required_timestamps.setdefault(
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
                self.required_timestamp_sources.setdefault(key, []).append(
                    f"deb {self.base_mirror}/{archive}/{timestamp}/ {suite} {component}"
                )
                self.buildinfo.required_timestamps.setdefault(key, []).append(timestamp)

    def get_build_depends_timestamps(self):
        """
        Returns a dict with keys Debian archives and
        values lists of tuple(timestamp, pkgs)
        where pkgs is a list of packages living there
        """
        required_timestamps = {}
        for pkg in self.buildinfo.get_build_depends():
            if not pkg.timestamp:
                self.get_bin_date(pkg)
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
        for location, timestamps in self.get_build_depends_timestamps().items():
            for timestamp, pkgs in timestamps:
                archive, suite, component = location.split("+", 3)
                # Adjust URL structure to fit Debian archive layout
                sources_list.setdefault(location, []).append(
                    (
                        f"deb {self.base_mirror}/{archive}/{timestamp}/ {suite} {component}",
                        pkgs,
                    )
                )
        return sources_list

    # def find_build_dependencies(self):
    #     logger.debug("Starting find_build_dependencies")
    #
    #     logger.debug("Preparing APT cache")
    #     self.prepare_aptcache()
    #     logger.debug("APT cache prepared")
    #
    #     notfound_packages = [pkg for pkg in self.buildinfo.get_build_depends()]
    #     logger.debug(f"Initial not found packages: {[pkg.to_apt_install_format() for pkg in notfound_packages]}")
    #
    #     temp_sources_list = self.tempaptdir + "/etc/apt/sources.list"
    #     batch_sources = []
    #
    #     with open(temp_sources_list, "a") as fd:
    #         for location, repositories in self.get_sources_list_from_timestamp().items():
    #             for timestamp_source, pkgs in repositories:
    #                 logger.info(f"Checking snapshot: {timestamp_source}")
    #                 self.required_timestamp_sources.setdefault(location, []).append(timestamp_source)
    #                 logger.debug(f"Timestamp source ({len(pkgs)} packages): {timestamp_source}")
    #
    #                 trusted_source = f"deb [trusted=yes] {timestamp_source.split()[1]} {timestamp_source.split()[2]} {timestamp_source.split()[3]}"
    #                 batch_sources.append(trusted_source)
    #
    #                 if len(batch_sources) >= 10 or timestamp_source == repositories[-1][0]:
    #                     for source in batch_sources:
    #                         fd.write(f"{source}\n")
    #                     fd.flush()
    #                     logger.debug(f"Added {len(batch_sources)} sources to APT sources list: {batch_sources}")
    #                     batch_sources = []
    #
    #                     logger.debug("Updating APT cache with new sources list")
    #                     self.tempaptcache.update(sources_list=temp_sources_list)
    #                     self.tempaptcache.open()
    #                     logger.debug("APT cache updated and opened")
    #
    #                     for notfound_pkg in notfound_packages.copy():
    #                         logger.debug(f"Searching for package: {notfound_pkg.to_apt_install_format()} in APT cache")
    #                         pkg = self.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")
    #
    #                         if pkg is not None:
    #                             available_versions = pkg.versions.keys()
    #                             if notfound_pkg.version in available_versions:
    #                                 logger.debug(f"Exact package {notfound_pkg.to_apt_install_format()} found in APT cache")
    #                                 notfound_packages.remove(notfound_pkg)
    #                             else:
    #                                 logger.debug(f"Exact package {notfound_pkg.to_apt_install_format()} not found. Using latest version available.")
    #                                 latest_version = max(available_versions, default=None)
    #                                 if latest_version:
    #                                     logger.debug(f"Using latest version {latest_version} for package {notfound_pkg.name}")
    #                                     notfound_pkg.version = latest_version
    #                                     notfound_packages.remove(notfound_pkg)
    #                         else:
    #                             logger.debug(f"Package {notfound_pkg.to_apt_install_format()} not found in APT cache")
    #
    #                     self.tempaptcache.close()
    #                     logger.debug("Closed APT cache")
    #
    #         if notfound_packages:
    #             logger.debug("Final attempt to find packages in current sources")
    #             self.tempaptcache.update()
    #             self.tempaptcache.open()
    #             for notfound_pkg in notfound_packages.copy():
    #                 logger.debug(f"Searching for package: {notfound_pkg.to_apt_install_format()} in APT cache")
    #                 pkg = self.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")
    #
    #                 if pkg is not None:
    #                     available_versions = pkg.versions.keys()
    #                     if notfound_pkg.version in available_versions:
    #                         logger.debug(f"Exact package {notfound_pkg.to_apt_install_format()} found in APT cache")
    #                         notfound_packages.remove(notfound_pkg)
    #                     else:
    #                         logger.debug(f"Exact package {notfound_pkg.to_apt_install_format()} not found. Using latest version available.")
    #                         latest_version = max(available_versions, default=None)
    #                         if latest_version:
    #                             logger.debug(f"Using latest version {latest_version} for package {notfound_pkg.name}")
    #                             notfound_pkg.version = latest_version
    #                             notfound_packages.remove(notfound_pkg)
    #                 else:
    #                     logger.debug(f"Package {notfound_pkg.to_apt_install_format()} not found in APT cache")
    #             self.tempaptcache.close()
    #
    #     if notfound_packages:
    #         for notfound_pkg in notfound_packages:
    #             logger.debug(f"Cannot locate package: {notfound_pkg.name}-{notfound_pkg.version}.{notfound_pkg.architecture}")
    #         raise RebuilderException("Cannot locate the following packages via snapshots or the current repo/mirror")
    #
    #     logger.debug("Completed find_build_dependencies")
    #
    #     if self.custom_package and self.custom_package.endswith(".deb"):
    #         custom_pkg_name = os.path.basename(self.custom_package).split('_')[0]
    #         subprocess.run(["apt-get", "install", "--reinstall", "-y", custom_pkg_name], check=True, env={"APT_CONFIG": f"{self.tempaptdir}/etc/apt/apt.conf"})

    def find_build_dependencies(self):
        logger.debug("Starting find_build_dependencies")

        logger.debug("Preparing APT cache")
        self.prepare_aptcache()
        logger.debug("APT cache prepared")

        notfound_packages = [pkg for pkg in self.buildinfo.get_build_depends()]
        logger.debug(f"Initial not found packages: {[pkg.to_apt_install_format() for pkg in notfound_packages]}")

        temp_sources_list = self.tempaptdir + "/etc/apt/sources.list"
        batch_sources = []

        with open(temp_sources_list, "a") as fd:
            for location, repositories in self.get_sources_list_from_timestamp().items():
                for timestamp_source, pkgs in repositories:
                    if not notfound_packages:
                        break

                    if not any(pkg.to_apt_install_format() in [p.to_apt_install_format() for p in notfound_packages] for pkg in pkgs):
                        logger.info(f"Skipping snapshot: {timestamp_source}")
                        continue

                    logger.info(f"Remaining packages to be found: {len(notfound_packages)}")
                    self.required_timestamp_sources.setdefault(location, []).append(timestamp_source)
                    logger.debug(f"Timestamp source ({len(pkgs)} packages): {timestamp_source}")

                    trusted_source = f"deb [trusted=yes] {timestamp_source.split()[1]} {timestamp_source.split()[2]} {timestamp_source.split()[3]}"
                    batch_sources.append(trusted_source)

                    if len(batch_sources) >= 10 or timestamp_source == repositories[-1][0]:
                        for source in batch_sources:
                            fd.write(f"{source}\n")
                        fd.flush()
                        logger.debug(f"Added {len(batch_sources)} sources to APT sources list: {batch_sources}")
                        batch_sources = []

                        logger.debug("Updating APT cache with new sources list")
                        self.tempaptcache.update(sources_list=temp_sources_list)
                        self.tempaptcache.open()
                        logger.debug("APT cache updated and opened")

                        for notfound_pkg in notfound_packages.copy():
                            logger.debug(f"Searching for package: {notfound_pkg.to_apt_install_format()} in APT cache")
                            pkg = self.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")

                            if pkg is not None:
                                available_versions = pkg.versions.keys()
                                if notfound_pkg.version in available_versions:
                                    logger.debug(f"Exact package {notfound_pkg.to_apt_install_format()} found in APT cache")
                                    notfound_packages.remove(notfound_pkg)
                                else:
                                    logger.debug(f"Exact package {notfound_pkg.to_apt_install_format()} not found. Using latest version available.")
                                    latest_version = max(available_versions, default=None)
                                    if latest_version:
                                        logger.debug(f"Using latest version {latest_version} for package {notfound_pkg.name}")
                                        notfound_pkg.version = latest_version
                                        notfound_packages.remove(notfound_pkg)
                            else:
                                logger.debug(f"Package {notfound_pkg.to_apt_install_format()} not found in APT cache")

                        self.tempaptcache.close()
                        logger.debug("Closed APT cache")

        # Fallback to a mirror if packages are still not found
        if notfound_packages:
            logger.debug("Trying to find packages in the specified mirror")
            for notfound_pkg in notfound_packages.copy():
                first_letter = notfound_pkg.name[0]
                package_url = f"http://ftp.de.debian.org/debian/pool/main/{first_letter}/{notfound_pkg.name}/"
                logger.debug(f"Constructed package URL: {package_url}")

                # Fetch the page content and parse for package versions
                response = requests.get(package_url)
                if response.status_code == 200:
                    # Parse the HTML content
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')
                    links = soup.find_all('a')
                    for link in links:
                        href = link.get('href')
                        if notfound_pkg.version in href:
                            logger.debug(f"Found matching package version in mirror: {href}")
                            pkg_url = f"{package_url}{href}"
                            response = requests.get(pkg_url)
                            if response.status_code == 200:
                                with open(f"/tmp/{href}", 'wb') as f:
                                    f.write(response.content)
                                # Instead of installing here, add to the list of downloaded packages
                                self.downloaded_packages.append(f"/tmp/{href}")
                                notfound_packages.remove(notfound_pkg)
                                break
                    else:
                        logger.debug(f"No matching package version found for {notfound_pkg.name} in mirror")
                else:
                    logger.debug(f"Failed to fetch the package URL: {package_url}")

        if notfound_packages:
            for notfound_pkg in notfound_packages:
                logger.debug(f"Cannot locate package: {notfound_pkg.name}-{notfound_pkg.version}.{notfound_pkg.architecture}")
                user_input = input(f"Cannot locate package: {notfound_pkg.name}-{notfound_pkg.version}.{notfound_pkg.architecture}. Do you want to provide a .deb URL for this package? (y/n): ")
                if user_input.lower() == 'y':
                    deb_url = input("Please provide the URL of the .deb file: ")
                    pkg_name = input("Please provide the package name: ")
                    pkg_version = input("Please provide the package version: ")
                    pkg_arch = notfound_pkg.architecture

                    # Download the .deb file
                    response = requests.get(deb_url)
                    if response.status_code == 200:
                        deb_filename = f"/tmp/{pkg_name}_{pkg_version}_{pkg_arch}.deb"
                        with open(deb_filename, 'wb') as f:
                            f.write(response.content)
                        # Add to the list of downloaded packages
                        self.downloaded_packages.append(deb_filename)
                        # Update the package info
                        self.updated_packages[pkg_name] = f"{pkg_name}={pkg_version}"
                        notfound_packages.remove(notfound_pkg)
                    else:
                        logger.error(f"Failed to download the .deb file from {deb_url}")
                        raise RebuilderException(f"Failed to download the .deb file from {deb_url}")
                else:
                    raise RebuilderException("Cannot locate the following packages via snapshots or the current repo/mirror")

        logger.debug("Completed find_build_dependencies")

        if self.custom_package and self.custom_package.endswith(".deb"):
            custom_pkg_name = os.path.basename(self.custom_package).split('_')[0]
            subprocess.run(["apt-get", "install", "--reinstall", "-y", custom_pkg_name], check=True, env={"APT_CONFIG": f"{self.tempaptdir}/etc/apt/apt.conf"})

    def prepare_aptcache(self):
        # create a temporary directory where all APT configuration files will be stored
        self.tempaptdir = tempfile.mkdtemp(prefix="debrebuild-", dir=self.tmpdir)
        logger.debug(f"Temporary APT directory: {self.tempaptdir}")

        #Define paths for APT config and sources list within the temp directory
        temp_apt_conf = f"{self.tempaptdir}/etc/apt/apt.conf"
        logger.debug(f"APT config file: {temp_apt_conf}")

        temp_sources_list = f"{self.tempaptdir}/etc/apt/sources.list"
        logger.debug(f"APT sources list file: {temp_sources_list}")

        apt_dirs = ["/etc/apt", "/etc/apt/trusted.gpg.d"]
        for directory in apt_dirs:
            full_path = f"{self.tempaptdir}{directory}"
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
""".format(
                build_arch=self.buildinfo.build_arch, tempdir=self.tempaptdir
            )
            if self.proxy:
                apt_conf += f'\nAcquire::http::proxy "{self.proxy}";\n'
            fd.write(apt_conf)
        logger.debug(f"Written APT config: {apt_conf}")

        with open(temp_sources_list, "w") as fd:
            sources_list_content = "\n".join(self.get_sources_list())
            fd.write(sources_list_content)
        logger.debug(f"Written APT sources list: {sources_list_content}")

        keyrings = DEBIAN_KEYRINGS
        if self.extra_repository_keys:
            keyrings += self.extra_repository_keys
        for keyring_src in keyrings:
            keyring_dst = f"{self.tempaptdir}/etc/apt/trusted.gpg.d/{os.path.basename(keyring_src)}"
            os.symlink(keyring_src, keyring_dst)
            logger.debug(f"Linked keyring: {keyring_src} to {keyring_dst}")

        try:
            logger.debug("Initializing APT cache")
            # Initialze an APT cache object pointed at the temporary directory which allows manipulation
            # of package states (like installation and removal) from the host's package system
            self.tempaptcache = apt.Cache(rootdir=self.tempaptdir, memonly=True)
            self.tempaptcache.close()
        except (PermissionError, apt_pkg.Error) as e:
            logger.error(f"Error initializing APT cache: {e}")
            raise RebuilderException("Failed to initialize APT cache")

    def get_apt_build_depends(self):
        apt_build_depends = []
        for pkg in self.buildinfo.get_build_depends():
            apt_build_depends.append(
                pkg.to_apt_install_format(self.buildinfo.build_arch)
            )
        return apt_build_depends

    def get_chroot_basemirror(self):
        logger.debug("Starting get_chroot_basemirror")

        # Workaround for standard method. libc6 should be the parent of all the packages.
        for pkg in ["libc6", "dpkg", "build-essential", "util-linux"]:
            dependency = self.get_build_dependency(pkg)
            if dependency:
                logger.debug(f"Found dependency for package '{pkg}': {dependency}")
                break
        else:
            logger.debug("No dependency found among the checked packages")
            dependency = None

        if not self.use_metasnap and dependency:
            logger.debug("Using non-metasnap approach with found dependency")
            archive_name = dependency.archive_name
            suite_name = dependency.suite_name
            component_name = dependency.component_name
            sorted_timestamp_sources = [dependency.timestamp]
        else:
            logger.debug("Using metasnap or no dependency found")
            reference_key = f"debian+{self.buildinfo.get_debian_suite()}+main"
            if self.buildinfo.required_timestamps.get(reference_key, None):
                timestamps = self.buildinfo.required_timestamps[reference_key]
                logger.debug(f"Found timestamps for reference key {reference_key}: {timestamps}")
            else:
                reference_key, timestamps = list(
                    self.buildinfo.required_timestamps.items()
                )[0]
                logger.debug(f"Using first available reference key {reference_key} with timestamps: {timestamps}")
            sorted_timestamp_sources = sorted(timestamps)
            archive_name, suite_name, component_name = reference_key.split("+", 3)

        logger.debug(f"Using archive: {archive_name}, suite: {suite_name}, component: {component_name}")
        logger.debug(f"Sorted timestamp sources: {sorted_timestamp_sources}")

        for timestamp in sorted_timestamp_sources:
            url = f"{self.base_mirror}/{archive_name}/{timestamp}"
            basemirror = f"deb [trusted=yes] {url} {suite_name} {component_name}"
            release_url = f"{url}/dists/{suite_name}/Release"
            logger.debug(f"Checking release URL: {release_url}")

            resp = self.get_response(release_url)
            if resp.ok:
                logger.debug(f"Found valid base mirror: {basemirror}")
                return basemirror
            else:
                logger.debug(f"Release URL {release_url} is not valid")

        logger.error("Cannot determine base mirror to use")
        raise RebuilderException("Cannot determine base mirror to use")

    def get_build_dependency(self, name):
        build_dependency = None
        for pkg in self.buildinfo.get_build_depends():
            if pkg.name == name:
                build_dependency = pkg
                break
        return build_dependency

    def mmdebstrap(self, output):
        if self.buildinfo.build_archany and self.buildinfo.build_archall:
            build = "any,all"
        elif self.buildinfo.build_archall:
            build = "all"
        elif self.buildinfo.build_archany:
            build = "any"
        elif self.buildinfo.build_source:
            build = "source"
        else:
            raise RebuilderException("Cannot determine what to build")

        logger.debug(f"Determined build type: {build}")

        # Prepare mmdebstrap command
        cmd = [
            "env",
            "-i",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "TMPDIR={}".format(self.tmpdir),
            "mmdebstrap",
            "--arch={}".format(self.buildinfo.build_arch),
            "--include={}".format(" ".join(self.get_apt_build_depends())),
            "--variant=apt",
            '--aptopt=Acquire::AllowInsecureRepositories "true"',
            '--aptopt=Acquire::AllowUnauthenticated "true"',
            '--aptopt=Acquire::Check-Valid-Until "false"',
            '--aptopt=Acquire::http::Dl-Limit "1000";',
            '--aptopt=Acquire::https::Dl-Limit "1000";',
            '--aptopt=Acquire::Retries "5";',
            '--aptopt=APT::Get::allow-downgrades "true";',
        ]

        logger.debug(f"Initial mmdebstrap command: {' '.join(cmd)}")

        # Support for proxy
        if self.proxy:
            cmd += ['--aptopt=Acquire::http::proxy "{}";'.format(self.proxy)]
            logger.debug(f"Added proxy to mmdebstrap command: {self.proxy}")

        # Use all Debian keyrings at the mmdebstrap initial phase
        cmd += ["--keyring=/usr/share/keyrings/"]

        # Workaround for missing build-essential in buildinfo dependencies
        if not self.get_build_dependency("build-essential"):
            cmd += [
                '--essential-hook=chroot "$1" sh -c "apt-get --yes install build-essential"'
            ]
            logger.debug("Added build-essential installation to mmdebstrap command")

        # Add dependencies for running build as builduser
        cmd += [
            '--essential-hook=chroot "$1" sh -c "apt-get --yes install fakeroot util-linux"'
        ]
        logger.debug("Added fakeroot and util-linux installation to mmdebstrap command")

        # Add Debian keyrings into mmdebstrap trusted keys after init phase
        cmd += [
            "--essential-hook=copy-in {} /etc/apt/trusted.gpg.d/".format(
                join(DEBIAN_KEYRINGS)
            )
        ]
        logger.debug("Added Debian keyrings to mmdebstrap command")

        # Update APT cache with provided sources.list
        sources_list_update_cmds = [
            "rm /etc/apt/sources.list",
            "echo '{}' >> /etc/apt/sources.list".format(
                "\n".join(
                    self.get_sources_list()
                    + self.get_sources_list_timestamps()
                )
            ),
            "apt-get update"
        ]

        cmd += [
            '--essential-hook=chroot "$1" sh -c "{}"'.format(
                " && ".join(sources_list_update_cmds)
            )
        ]
        logger.debug("Added APT sources list update to mmdebstrap command")

        # Add step to refresh keyrings inside the chroot
        cmd += [
            '--essential-hook=chroot "$1" sh -c "apt-key update"'
        ]
        logger.debug("Added apt-key update to mmdebstrap command")

        # Create builduser for running the build in mmdebstrap as builduser
        cmd += [
            '--customize-hook=chroot "$1" useradd --no-create-home -d /nonexistent -p "" builduser -s /bin/bash'
        ]
        logger.debug("Added creation of builduser to mmdebstrap command")

        # In case of binNMU build, we add the changelog entry from buildinfo
        binnmucmds = []
        if self.buildinfo.logentry:
            binnmucmds += [
                "cd {}".format(quote(self.buildinfo.get_build_path())),
                "{{ printf '%s' {}; cat debian/changelog; }} > debian/changelog.debrebuild".format(
                    quote(self.buildinfo.logentry)
                ),
                "mv debian/changelog.debrebuild debian/changelog",
            ]
            logger.debug("Added binNMU changelog entry to mmdebstrap command")

        # Prepare build directory and get package source
        cmd += [
            '--customize-hook=chroot "$1" env sh -c "{}"'.format(
                " && ".join(
                    [
                        "apt-get source --only-source -d {}={}".format(
                            self.buildinfo.source, self.buildinfo.source_version
                        ),
                        "mkdir -p {}".format(
                            os.path.dirname(quote(self.buildinfo.get_build_path()))
                        ),
                        "dpkg-source --no-check -x /*.dsc {}".format(
                            quote(self.buildinfo.get_build_path()))
                    ]
                    + binnmucmds
                    + [
                        "chown -R builduser:builduser {}".format(
                            os.path.dirname(quote(self.buildinfo.get_build_path()))
                        ),
                    ]
                )
            )
        ]
        logger.debug("Added preparation of build directory and source package download to mmdebstrap command")

        # Install downloaded packages
        if self.downloaded_packages:
            cmd += [
                '--customize-hook=copy-in {} /tmp/'.format(
                    " ".join(self.downloaded_packages)
                ),
                '--customize-hook=chroot "$1" sh -c "dpkg -i /tmp/*.deb && apt-get install -f -y"'
            ]
            logger.debug(f"Added installation of downloaded packages to mmdebstrap command")

        # Prepare build command
        cmd += [
            '--customize-hook=chroot "$1" env --unset=TMPDIR runuser builduser -c "{}"'.format(
                " && ".join(
                    [
                        "cd {}".format(quote(self.buildinfo.get_build_path())),
                        "env {} dpkg-buildpackage -uc -a {} --build={}".format(
                            " ".join(self.get_env()), self.buildinfo.host_arch, build
                        ),
                    ]
                )
            )
        ]
        logger.debug("Added build command to mmdebstrap command")

        cmd += [
            "--customize-hook=sync-out {} {}".format(
                os.path.dirname(quote(self.buildinfo.get_build_path())), output
            ),
            self.buildinfo.get_debian_suite(),
            "/dev/null",
            self.get_chroot_basemirror(),  # Ensure this method is defined and returns a valid URL
        ]
        logger.debug("Added sync-out and final setup to mmdebstrap command")

        logger.debug("Final mmdebstrap command: " + " ".join(cmd))

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if 'Unable to find a source package for' in result.stderr or 'Cannot find version' in result.stderr:
                logger.error(f"mmdebstrap failed to find the source package: {result.stderr}")
                print("mmdebstrap failed to find the source package.")
                source_url = input("Please provide the URL to the source tarball (e.g., http://ftp.de.debian.org/debian/pool/main/g/gzip/gzip_1.10.orig.tar.gz): ")
                package_version = input("Please provide the package version: ")

                # Download the source tarball
                source_tarball = f"/tmp/{os.path.basename(source_url)}"
                subprocess.run(["wget", "-O", source_tarball, source_url])

                # Extract the tarball
                extract_dir = f"/build/{os.path.basename(source_tarball).split('.orig.tar.gz')[0]}"
                subprocess.run(["mkdir", "-p", extract_dir])
                subprocess.run(["tar", "-xzf", source_tarball, "-C", extract_dir])

                # Update buildinfo with the new version
                self.buildinfo.source_version = package_version

                # Retry the mmdebstrap command without the failing package version command
                cmd = [part for part in cmd if 'apt-get source --only-source -d' not in part]
                cmd += [
                    '--customize-hook=chroot "$1" env sh -c "chown -R builduser:builduser /build"'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logger.error(f"mmdebstrap failed again with error: {result.stderr}")
                    raise RebuilderException("mmdebstrap failed again")
                else:
                    logger.info(f"mmdebstrap completed successfully after manual source tarball specification: {result.stdout}")
            else:
                logger.error(f"mmdebstrap failed with error: {result.stderr}")
                raise RebuilderException("mmdebstrap failed")
        else:
            logger.info(f"mmdebstrap completed successfully: {result.stdout}")

    def verify_checksums(self, output, new_buildinfo):
        status = True
        summary = {}
        changed_packages = set()

        # Identify changed packages
        for pkg in self.buildinfo.build_depends + [self.buildinfo.source]:
            new_pkg = next((npkg for npkg in new_buildinfo.build_depends if npkg['name'] == pkg['name']), None)
            if new_pkg and new_pkg['version'] != pkg['version']:
                changed_packages.add(pkg['name'])

        for alg in self.buildinfo.checksums.keys():
            checksums = self.buildinfo.checksums[alg]
            new_checksums = new_buildinfo.checksums[alg]
            files = [f for f in checksums if not f["name"].endswith(".dsc")]
            new_files = [f for f in new_checksums if not f["name"].endswith(".dsc")]
            summary.setdefault(alg, {})

            if len(files) != len(new_files):
                logger.debug(f"old buildinfo: {' '.join(files)}")
                logger.debug(f"new buildinfo: {' '.join(new_files)}")
                raise RebuilderException(
                    f"New buildinfo contains a different number of files in {alg} checksums."
                )

            for f in files:
                new_file = None
                for nf in new_files:
                    if nf["name"] == f["name"]:
                        new_file = nf
                        break
                if not new_file:
                    raise RebuilderException(
                        f"{alg}: Cannot find {f['name']} in new files"
                    )
                summary[alg].setdefault(f["name"], {})
                cur_status = True
                for prop in f.keys():
                    if prop not in new_file.keys():
                        raise RebuilderException(
                            f"{alg}: '{prop}' is not used in both buildinfo files"
                        )
                    if prop != "name":
                        summary[alg][f["name"]][prop] = {
                            "old": f[prop],
                            "new": new_file[prop],
                        }
                    if prop == "size":
                        if f["size"] != new_file["size"]:
                            logger.error(f"{alg}: Size differs for {f['name']}")
                            cur_status = False
                        continue
                    if f[prop] != new_file[prop]:
                        logger.error(
                            f"{alg}: Value of '{prop}' differs for {f['name']}"
                        )
                        cur_status = False
                if cur_status:
                    logger.info(f"{alg}: {f['name']}: OK")
                else:
                    status = False

            # Remove checksums related to changed packages from summary
            summary[alg] = {k: v for k, v in summary[alg].items() if k.split('/')[0] not in changed_packages}

        if not status:
            logger.error("Checksums: FAIL")
        else:
            logger.info("Checksums: OK")

        return status, summary

    def generate_intoto_metadata(self, output, new_buildinfo):
        new_files = [
            f["name"]
            for f in new_buildinfo.checksums["sha256"]
            if not f["name"].endswith(".dsc")
        ]
        cmd = [
            "in-toto-run",
            "--step-name=rebuild",
            "--no-command",
            "--products",
        ] + list(new_files)
        if self.gpg_sign_keyid:
            cmd += ["--gpg", self.gpg_sign_keyid]
        else:
            cmd += ["--gpg"]
        try:
            result = subprocess.run(cmd, cwd=output)
            returncode = result.returncode
        except FileNotFoundError:
            logger.error("in-toto-run not found!")
            returncode = 1

        if returncode != 0:
            raise RebuilderInTotoError("in-toto metadata generation failed!")
        logger.info("in-toto metadata generation passed")

    @staticmethod
    def run_diffoscope(output, file1, file2):
        cmd = ["diffoscope", file1, file2]
        try:
            run_or_tee(cmd, filename="diffoscope.out", store_dir=output, cwd=output)
            returncode = 0
        except FileNotFoundError:
            logger.error("diffoscope not found!")
            returncode = 1
        if returncode != 0:
            raise RebuilderInTotoError("diffoscope run failed!")
        logger.info("diffoscope run passed")

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

    def generate_diffoscope(self, output, summary):
        # fixme: propose alternative methods to get file from Debian instead of
        #  using sha256 reference.
        if not summary.get("sha256", None):
            logger.error(f"Cannot generate diffoscope: missing sha256 entries!")
        files = summary["sha256"]
        for f in files.keys():
            if files[f]["sha256"]["old"] != files[f]["sha256"]["new"]:
                debian_file = f"{output}/debian/{f}"
                os.makedirs(os.path.dirname(debian_file), exist_ok=True)
                try:
                    self.download_from_snapshot(debian_file, files[f]["sha256"]["old"])
                    self.run_diffoscope(output, debian_file, f)
                except Exception as e:
                    logger.error(f"Cannot generate diffoscope for {f}: {str(e)}")

    def run(self, builder, output):
        logger.debug("Starting the run function")

        # Determine build architecture
        if self.buildinfo.architecture:
            build_arch = self.get_host_architecture()
        elif self.buildinfo.build_archall:
            build_arch = "all"
        elif self.buildinfo.build_source:
            build_arch = "source"
        else:
            raise RebuilderException("Nothing to build")
        logger.debug(f"Build architecture determined: {build_arch}")

        # Perform pre-checks
        logger.debug("Starting pre-checks")
        for key in DEBIAN_KEYRINGS:
            if not os.path.exists(key):
                logger.error(f"Cannot find keyring: {key}")
                raise RebuilderException(f"Cannot find {key}. Ensure to have installed debian-keyring, debian-archive-keyring, and debian-ports-archive-keyring.")
        logger.debug("Pre-checks completed")

        # Initialize and find build dependencies
        try:
            if self.use_metasnap:
                logger.debug("Use metasnap for getting required timestamps")
                self.find_build_dependencies_from_metasnap()
            if not self.required_timestamp_sources:
                logger.debug("Use snapshot for getting required timestamps")
                # If we failed at getting required timestamps from metasnap, we fallback
                # to standard method. It means the code needs to know that we don't use metasnap
                # to solve some dependency issues.
                self.use_metasnap = False
                self.find_build_dependencies()
        except (
            apt_pkg.Error,
            apt.cache.FetchFailedException,
            requests.exceptions.ConnectionError,
        ) as e:
            raise RebuilderException(f"Failed to fetch packages: {str(e)}")
        except KeyboardInterrupt:
            raise RebuilderException("Interruption")
        finally:
            if self.tempaptdir and self.tempaptdir.startswith(
                os.path.join(self.tmpdir, "debrebuild-")
            ):
                if self.tempaptcache:
                    self.tempaptcache.close()
                shutil.rmtree(self.tempaptdir)
            if self.buildinfo_file.startswith(os.path.join(self.tmpdir, "buildinfo-")):
                os.remove(self.buildinfo_file)

        # for older version of dpkg <= 1.19.0, binNMU version is not included in the generate
        # buildinfo filename (see: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869236)
        dpkg = self.get_build_dependency("dpkg")
        if self.buildinfo.logentry and dpkg and dpkg.version < "1.19.0":
            buildinfo_version = self.buildinfo.source_version
        else:
            buildinfo_version = self.buildinfo.version

        # path of the new buildinfo file generated by the rebuild in artifacts directory
        new_buildinfo_file = f"{output}/{self.buildinfo.source}_{buildinfo_version}_{build_arch}.buildinfo"
        if os.path.exists(new_buildinfo_file):
            raise RebuilderException(
                f"Refusing to overwrite existing buildinfo file: {new_buildinfo_file}"
            )

        # Execute the build
        logger.debug("Starting stage 2: Run the actual rebuild of provided buildinfo file")
        if builder == "none":
            return
        if builder == "mmdebstrap":
            self.mmdebstrap(output)

        # Stage 3: Everything post-build actions with rebuild artifacts
        new_buildinfo = RebuilderBuildInfo(realpath(new_buildinfo_file))
        status, summary = self.verify_checksums(output, new_buildinfo)
        with open(f"{output}/summary.out", "w") as fd:
            fd.write(json.dumps(summary))
        if not status:
            self.generate_diffoscope(output, summary)
            logger.error("Checksum verification failed")
            raise RebuilderChecksumsError
        if self.gpg_sign_keyid:
            self.generate_intoto_metadata(output, new_buildinfo)
        logger.debug("Post-build actions completed")



def get_args():
    parser = argparse.ArgumentParser(
        description="Given a buildinfo file from a Debian package, "
        "generate instructions for attempting to reproduce "
        "the binary packages built from the associated source "
        "and build information."
    )
    parser.add_argument("buildinfo", help="Input buildinfo file. Local or remote file.")
    parser.add_argument(
        "--output",
        help="Directory for the build artifacts",
    )
    parser.add_argument(
        "--builder",
        help="Which building software should be used. (default: none)",
        default="none",
    )
    parser.add_argument(
        "--query-url",
        help="API url for querying package and binary information "
        "(default: http://snapshot.notset.fr).",
        default="http://snapshot.notset.fr",
    )
    parser.add_argument(
        "--snapshot-mirror",
        help="Snapshot mirror to use (default: http://snapshot.notset.fr)",
        default="http://snapshot.notset.fr",
    )
    parser.add_argument(
        "--metasnap-url",
        help="Metasnap service url (default: https://metasnap.debian.net).",
        default="https://metasnap.debian.net",
    )
    parser.add_argument(
        "--use-metasnap",
        help="Service to query the minimal set of timestamps containing all"
        " package versions referenced in a buildinfo file.",
        action="store_true",
    )
    parser.add_argument(
        "--extra-repository-file",
        help="Add repository file content to the list of apt sources during "
        "the package build.",
        action="append",
    )
    parser.add_argument(
        "--extra-repository-key",
        help="Add key file (.asc) to the list of trusted keys during "
        "the package build.",
        action="append",
    )
    parser.add_argument(
        "--gpg-sign-keyid", help="GPG keyid to use for signing in-toto metadata."
    )
    parser.add_argument(
        "--gpg-verify", help="Verify buildinfo GPG signature.", action="store_true"
    )
    parser.add_argument(
        "--gpg-verify-key", help="GPG key to use for buildinfo GPG check."
    )
    parser.add_argument("--proxy", help="Proxy address to use.")
    parser.add_argument(
        "--build-options-nocheck", action="store_true", help="Disable build tests."
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Display logger info messages."
    )
    parser.add_argument(
        "--debug", action="store_true", help="Display logger debug messages."
    )
    parser.add_argument(
        "--custom-package",
        help="Path to a custom package (source or binary) to use in the build",
    )
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
        rebuilder = Rebuilder(
            buildinfo_file=args.buildinfo,
            snapshot_url=args.query_url,
            snapshot_mirror=args.snapshot_mirror,
            extra_repository_files=args.extra_repository_file,
            extra_repository_keys=args.extra_repository_key,
            gpg_sign_keyid=args.gpg_sign_keyid,
            gpg_verify=args.gpg_verify,
            gpg_verify_key=args.gpg_verify_key,
            proxy=args.proxy,
            use_metasnap=args.use_metasnap,
            metasnap_url=args.metasnap_url,
            build_options_nocheck=args.build_options_nocheck,
        )
        rebuilder.run(builder=args.builder, output=realpath(args.output))
    except RebuilderChecksumsError:
        return 2
    except RebuilderException as e:
        logger.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
