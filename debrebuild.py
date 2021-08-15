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

import os
import sys
import requests
import tempfile
import json
import subprocess
import shutil
import argparse
import logging
import apt
import apt_pkg
import debian.deb822
import debian.debian_support
import rstr

from dateutil.parser import parse as parsedate
from libs.openpgp import OpenPGPEnvironment, OpenPGPException
from shlex import quote, join

logger = logging.getLogger('debrebuild')
console_handler = logging.StreamHandler(sys.stderr)
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


class Package:
    def __init__(self, name, version, architecture=None, archive_name="debian", suite_name="unstable", component_name="main"):
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
        return f'Package({self.name}, {self.version}, architecture={self.architecture})'


class BuildInfo:
    def __init__(self, buildinfo_file):

        if not os.path.exists(buildinfo_file):
            raise BuildInfoException(f"Cannot find buildinfo file: {buildinfo_file}")

        with open(buildinfo_file) as fd:
            self.parsed_info = debian.deb822.BuildInfo(fd)

        # in case of binnmu we have e.g.
        #   Source: 0ad (0.0.23-1)
        self.source, self.source_version = self.parsed_info.get_source()
        self.architecture = [arch for arch in self.parsed_info.get_architecture()
                             if arch not in ("source", "all")]
        if len(self.architecture) > 1:
            raise BuildInfoException(
                "More than one architecture in Architecture field")
        self.binary = self.parsed_info.get_binary()
        self.version = self.parsed_info['version']
        if not self.source_version:
            self.source_version = self.version
        if ':' in self.version:
            self.version = self.version.split(':')[1]
        self.build_path = self.parsed_info.get('build-path', None)
        self.build_arch = self.parsed_info.get('build-architecture', None)
        if not self.build_arch:
            raise BuildInfoException("Need Build-Architecture field")
        self.build_date = self.parsed_info.get_build_date().strftime("%Y%m%dT%H%M%SZ")
        self.host_arch = self.parsed_info.get('host-architecture', self.build_arch)
        self.env = self.parsed_info.get_environment()
        self.build_source = self.parsed_info.is_build_source()
        self.build_archall = self.parsed_info.is_build_arch_all()
        self.build_archany = self.parsed_info.is_build_arch_any()

        self.checksums = {}
        for alg in ('md5', 'sha1', 'sha256', 'sha512'):
            if self.parsed_info.get(f'checksums-{alg}', None):
                self.checksums[alg] = self.parsed_info[f'checksums-{alg}']

        self.logentry = self.parsed_info.get_changelog()
        if self.logentry:
            # Due to storing the binnmu changelog entry in deb822 buildinfo,
            # the first character is an unwanted newline
            self.logentry = str(self.logentry).lstrip('\n')
            # while the linebreak at the beginning is wrong, there are two
            # missing at the end
            self.logentry += '\n\n'

        self.build_depends = []
        self.required_timestamps = {}
        self.archive_name = None
        self.source_date = None
        self.suite_name = None
        self.component_name = None

    def get_debian_suite(self):
        """Returns the Debian suite suited for debootstraping the build
        environment as described by the .buildinfo file.
        (For *re*building we cannot base upon packages from sid as else
        we might be forced to downgrades which are not supported.)
        This is then used by rebuilders usage of debootstrap for
        rebuilding the underling packages.
        """
        debian_suite = 'sid'
        for pkg in self.parsed_info.relations['installed-build-depends']:
            if pkg[0]['name'] == "base-files":
                _, version = pkg[0]['version']
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
        self.build_path = self.build_path.replace('~', '-')
        return self.build_path

    def get_build_depends(self):
        # Storing self.build_depends is needed as we refresh information
        # from apt cache
        if not self.build_depends:
            installed = self.parsed_info.relations['installed-build-depends']
            for dep in installed:
                name = dep[0]['name']
                _, version = dep[0]['version']
                self.build_depends.append(Package(name, version))
        return self.build_depends


class Rebuilder:
    def __init__(self, buildinfo_file, snapshot_url, snapshot_mirror,
                 extra_repository_files=None, extra_repository_keys=None,
                 gpg_sign_keyid=None,
                 gpg_verify=False,
                 gpg_verify_key=None,
                 proxy=None,
                 use_metasnap=False):
        self.buildinfo = None
        self.snapshot_url = snapshot_url
        self.base_mirror = f"{snapshot_mirror}/archive"
        self.extra_repository_files = extra_repository_files
        self.extra_repository_keys = extra_repository_keys
        self.gpg_sign_keyid = gpg_sign_keyid
        self.proxy = proxy
        self.session = requests.Session()
        self.session.proxies = {
                "http:": self.proxy,
                "https": self.proxy
            }
        self.use_metasnap = use_metasnap
        self.tempaptdir = None
        self.tempaptcache = None
        self.required_timestamp_sources = {}
        self.tmpdir = os.environ.get('TMPDIR', '/tmp')
        self.buildinfo_file = None

        if buildinfo_file.startswith('http://') or \
                buildinfo_file.startswith('https://'):
            resp = self.get_response(buildinfo_file)
            if not resp.ok:
                raise RebuilderException("Cannot get buildinfo: {}")

            # We store remote buildinfo in a temporary file
            handle, self.buildinfo_file = tempfile.mkstemp(
                prefix="buildinfo-", dir=self.tmpdir)
            with open(handle, 'w') as fd:
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

        self.buildinfo = BuildInfo(self.buildinfo_file)

    def get_env(self):
        env = []
        for key, val in self.buildinfo.env.items():
            env.append(f"{key}=\"{val}\"")
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

    # TODO: refactor get_src_date and get_bin_date. Do a better distinction between "BuildInfo"
    #  and the source package which as to be defined.
    def get_src_date(self):
        if all([self.buildinfo.archive_name, self.buildinfo.source_date, self.buildinfo.suite_name, self.buildinfo.component_name]):
            return self.buildinfo.archive_name, self.buildinfo.source_date, self.buildinfo.suite_name, self.buildinfo.component_name
        srcpkgname = self.buildinfo.source
        srcpkgver = self.buildinfo.source_version
        json_url = f"{self.snapshot_url}/mr/package/{srcpkgname}/{srcpkgver}/srcfiles?fileinfo=1"
        logger.debug(f"Get source package info: {srcpkgname}={srcpkgver}")
        logger.debug(f"Source URL: {json_url}")
        resp = self.get_response(json_url)
        try:
            data = resp.json()
        except json.decoder.JSONDecodeError:
            raise RebuilderException(f"Cannot parse response for source: {self.buildinfo.source}")

        source_info = None
        for h in data.get('fileinfo', {}).values():
            # We pick the first dsc found.
            for f in h:
                if f['name'].endswith('.dsc'):
                    source_info = f
                    break
                if source_info:
                    break
        if not source_info:
            raise RebuilderException(f"No source info found for {srcpkgname}-{srcpkgver}")
        self.buildinfo.archive_name = source_info["archive_name"]
        self.buildinfo.source_date = source_info["timestamp_ranges"][0][0]
        self.buildinfo.suite_name = source_info["suite_name"]
        self.buildinfo.component_name = source_info["component_name"]
        return self.buildinfo.archive_name, self.buildinfo.source_date, self.buildinfo.suite_name, self.buildinfo.component_name

    def get_bin_date(self, package):
        pkgname = package.name
        pkgver = package.version
        pkgarch = package.architecture
        json_url = f"{self.snapshot_url}/mr/binary/{pkgname}/{pkgver}/binfiles?fileinfo=1"
        logger.debug(f"Get binary package info: {pkgname}={pkgver}")
        logger.debug(f"Binary URL: {json_url}")
        resp = self.get_response(json_url)
        try:
            data = resp.json()
        except json.decoder.JSONDecodeError:
            raise RebuilderException(f"Cannot parse response for package: {package.name}")

        pkghash = None
        if len(data.get('result', [])) == 1:
            pkghash = data['result'][0]['hash']
            package.architecture = data['result'][0]['architecture']
            if pkgarch and pkgarch != package.architecture:
                raise RebuilderException(f"Package {pkgname} was explicitly requested "
                                         f"{pkgarch} but only {package.architecture} was found")
            if not pkgarch and self.buildinfo.build_arch != package.architecture and \
                    "all" != package.architecture:
                raise RebuilderException(f"Package {pkgname} was implicitly requested "
                                         f"{self.buildinfo.build_arch} but only "
                                         f"{package.architecture} was found")
            pkgarch = package.architecture
        else:
            if not pkgarch:
                pkgarch = self.buildinfo.build_arch
            for result in data.get('result', []):
                if result['architecture'] == pkgarch:
                    pkghash = result['hash']
                    break
            if not pkghash:
                raise RebuilderException(f"Cannot find package in architecture {pkgarch}")
            package.architecture = pkgarch

        binary_info = [pkg for pkg in data['fileinfo'].get(pkghash, [])]
        if not binary_info:
            raise RebuilderException(f"No binary info found for {pkgname}:{pkgarch}-{pkgver}")
        package.hash = pkghash
        package.archive_name = binary_info[0]["archive_name"]
        package.timestamp = binary_info[0]["timestamp_ranges"][0][0]
        package.suite_name = binary_info[0]["suite_name"]
        package.component_name = binary_info[0]["component_name"]
        return package.archive_name, package.timestamp, package.suite_name, package.component_name

    def get_sources_list(self):
        """
            Returns a list of all inline Debian repositories for to the package
            to be rebuilt (not dependencies)
        """
        sources_list = []
        archive_name, source_date, dist, component = self.get_src_date()
        build_url = f"{self.base_mirror}/{archive_name}/{source_date}"

        # Add deb repository
        release_url = f"{build_url}/dists/{dist}/Release"
        resp = self.get_response(release_url)
        if not resp.ok:
            RebuilderException(f"Cannot fetch {dist} Release file: {release_url}")
        build_repo = f"deb {build_url}/ {dist} {component}"
        sources_list.append(build_repo)

        # Add deb-src repository
        source_release_url = f"{build_url}/dists/{dist}/main/source/Release"
        resp = self.get_response(source_release_url)
        if not resp.ok:
            RebuilderException(f"Cannot fetch {dist} Release file: {source_release_url}")
        source_repo = f"deb-src {build_url}/ {dist} main"
        sources_list.append(source_repo)

        if self.extra_repository_files:
            for repo_file in self.extra_repository_files:
                try:
                    with open(repo_file) as fd:
                        for line in fd:
                            if not line.startswith('#') and \
                                    not line.startswith('\n'):
                                sources_list.append(line.rstrip('\n'))
                except FileNotFoundError:
                    raise RebuilderException(f"Cannot find repository file: {repo_file}")

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
        files = {'buildinfo': open(self.buildinfo_file, 'rb')}
        try:
            resp = self.session.post("https://metasnap.debian.net/cgi-bin/api", files=files)
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

        # latest first
        content = reversed(resp.text.strip('\n').split('\n'))
        for line in content:
            arch, timestamp = line.split()
            if arch != self.buildinfo.build_arch:
                raise RebuilderException("Unable to handle multiple architectures")
            self.required_timestamp_sources.setdefault("debian+unstable+main", []).append(
                f"deb {self.base_mirror}/debian/{timestamp}/ unstable main")

            # We store timestamp value itself for the base mirror used for creating chroot
            self.buildinfo.required_timestamps.setdefault("debian+unstable+main", []).append(timestamp)

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
            required_timestamps.setdefault(location, {}).setdefault(timestamp, []).append(pkg)

            # We store timestamp value itself for the base mirror used for creating chroot
            self.buildinfo.required_timestamps.setdefault(location, []).append(timestamp)

        location_required_timestamps = {}
        for location, timestamps in required_timestamps.items():
            # sort by the number of packages found there, convert to list of tuples
            timestamps = sorted(timestamps.items(), key=lambda x: len(x[1]), reverse=True)
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
                archive, suite, component = location.split('+', 3)
                sources_list.setdefault(location, []).append(
                    (f"deb {self.base_mirror}/{archive}/{timestamp}/ {suite} {component}", pkgs)
                )
        return sources_list

    def find_build_dependencies(self):
        # Prepare APT cache for finding dependencies
        self.prepare_aptcache()

        notfound_packages = [pkg for pkg in self.buildinfo.get_build_depends()]
        temp_sources_list = self.tempaptdir + '/etc/apt/sources.list'
        with open(temp_sources_list, "a") as fd:
            for location, repositories in self.get_sources_list_from_timestamp().items():
                for timestamp_source, pkgs in repositories:
                    if not notfound_packages:
                        break
                    if not any(pkg.to_apt_install_format() in [p.to_apt_install_format() for p in notfound_packages]
                               for pkg in pkgs):
                        logger.info(f"Skipping snapshot: {timestamp_source}")
                        continue
                    logger.info(f"Remaining packages to be found: {len(notfound_packages)}")
                    self.required_timestamp_sources.setdefault(location, []).append(timestamp_source)
                    logger.debug(f"Timestamp source ({len(pkgs)} packages): {timestamp_source}")
                    fd.write(f"\n{timestamp_source}")
                    fd.flush()

                    # provides sources.list explicitly, otherwise `update()`
                    # doesn't reload it until the next `open()`
                    self.tempaptcache.update(sources_list=temp_sources_list)
                    self.tempaptcache.open()

                    for notfound_pkg in notfound_packages.copy():
                        pkg = self.tempaptcache.get(f"{notfound_pkg.name}:{notfound_pkg.architecture}")
                        if pkg is not None and pkg.versions.get(notfound_pkg.version) is not None:
                            notfound_packages.remove(notfound_pkg)

                    self.tempaptcache.close()

        if notfound_packages:
            for notfound_pkg in notfound_packages:
                logger.debug(f"{notfound_pkg.name}-{notfound_pkg.version}.{notfound_pkg.architecture}")
            raise RebuilderException("Cannot locate the following packages via "
                                     "snapshots or the current repo/mirror")

    def prepare_aptcache(self):
        self.tempaptdir = tempfile.mkdtemp(
            prefix="debrebuild-", dir=self.tmpdir)

        # Create apt.conf
        temp_apt_conf = f"{self.tempaptdir}/etc/apt/apt.conf"
        # Create sources.list
        temp_sources_list = f"{self.tempaptdir}/etc/apt/sources.list"

        apt_dirs = [
            '/etc/apt', '/etc/apt/trusted.gpg.d'
        ]
        for directory in apt_dirs:
            os.makedirs(f"{self.tempaptdir}/{directory}")

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
Binary::apt-get::Acquire::AllowInsecureRepositories "false";
""".format(build_arch=self.buildinfo.build_arch, tempdir=self.tempaptdir)
            if self.proxy:
                apt_conf += f'\nAcquire::http::proxy "{self.proxy}";\n'
            fd.write(apt_conf)

        with open(temp_sources_list, "w") as fd:
            fd.write("\n".join(self.get_sources_list()))

        keyrings = [
            "/usr/share/keyrings/debian-archive-keyring.gpg",
            "/usr/share/keyrings/debian-archive-removed-keys.gpg",
        ]
        if self.extra_repository_keys:
            keyrings += self.extra_repository_keys
        for keyring_src in keyrings:
            keyring_dst = f"{self.tempaptdir}/etc/apt/trusted.gpg.d/{os.path.basename(keyring_src)}"
            os.symlink(keyring_src, keyring_dst)

        # Init temporary APT cache
        try:
            logger.debug("Initialize APT cache")
            self.tempaptcache = apt.Cache(rootdir=self.tempaptdir, memonly=True)
            self.tempaptcache.close()
        except (PermissionError, apt_pkg.Error):
            raise RebuilderException("Failed to initialize APT cache")

    def get_apt_build_depends(self):
        apt_build_depends = []
        for pkg in self.buildinfo.get_build_depends():
            apt_build_depends.append(
                pkg.to_apt_install_format(self.buildinfo.build_arch))
        return apt_build_depends

    def get_chroot_basemirror(self):
        if self.buildinfo.required_timestamps.get(f"debian+{self.buildinfo.get_debian_suite()}+main", None):
            sorted_timestamp_sources = sorted(self.buildinfo.required_timestamps[f"debian+{self.buildinfo.get_debian_suite()}+main"], reverse=True)
            archive_name = "debian"
            suite_name = self.buildinfo.get_debian_suite()
            component_name = "main"
        elif self.buildinfo.required_timestamps.get("debian+unstable+main", None):
            sorted_timestamp_sources = sorted(self.buildinfo.required_timestamps["debian+unstable+main"], reverse=True)
            archive_name = "debian"
            suite_name = "unstable"
            component_name = "main"
        else:
            raise RebuilderException("Cannot determine base mirror to use")

        for timestamp in sorted_timestamp_sources:
            url = f"{self.base_mirror}/{archive_name}/{timestamp}"
            basemirror = f"deb {url} {suite_name} {component_name}"
            release_url = f"{url}/dists/{suite_name}/Release"
            resp = self.get_response(release_url)
            if resp.ok:
                return basemirror
        raise RebuilderException("Cannot determine base mirror to use")

    def has_build_essential_dependency(self):
        has_build_essential = False
        for pkg in self.buildinfo.get_build_depends():
            if pkg.name == "build-essential":
                has_build_essential = True
                break
        return has_build_essential

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

        # Prepare mmdebstrap command
        cmd = [
            'env', '-i',
            'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'TMPDIR={}'.format(self.tmpdir),
            'mmdebstrap',
            '--arch={}'.format(self.buildinfo.build_arch),
            '--include={}'.format(' '.join(self.get_apt_build_depends())),
            '--variant=apt',
            '--aptopt=Acquire::Check-Valid-Until "false"',
            '--aptopt=Acquire::http::Dl-Limit "1000";',
            '--aptopt=Acquire::https::Dl-Limit "1000";',
            '--aptopt=Acquire::Retries "5";',
            '--aptopt=APT::Get::allow-downgrades "true";',
        ]

        # Support for proxy
        if self.proxy:
            cmd += [
                '--aptopt=Acquire::http::proxy "{}";'.format(self.proxy)
            ]

        # Workaround for missing build-essential in buildinfo dependencies
        if not self.has_build_essential_dependency():
            cmd += [
                '--essential-hook=chroot "$1" sh -c "apt-get --yes install build-essential"'
            ]

        # Add dependencies for running build as builduser
        cmd += [
            '--essential-hook=chroot "$1" sh -c "apt-get --yes install fakeroot util-linux"'
        ]

        # Copy extra keys and repository files
        if self.extra_repository_keys:
            cmd += [
                '--essential-hook=copy-in {} /etc/apt/trusted.gpg.d/'.format(
                    join(self.extra_repository_keys))]

        if self.extra_repository_files:
            cmd += [
                '--essential-hook=chroot "$1" sh -c "apt-get --yes install apt-transport-https ca-certificates"'
            ]

        # Update APT cache with provided sources.list
        cmd += [
            '--essential-hook=chroot "$1" sh -c \"{}\"'.format(" && ".join(
                [
                    'rm /etc/apt/sources.list',
                    "echo '{}' >> /etc/apt/sources.list".format('\n'.join(self.get_sources_list() + self.get_sources_list_timestamps())),
                    'apt-get update'
                ]
            ))
        ]

        # Create builduser for running the build in mmdebstrap as builduser
        cmd += [
            '--customize-hook=chroot "$1" useradd --no-create-home -d /nonexistent -p "" builduser -s /bin/bash'
        ]

        # In case of binNMU build, we add the changelog entry from buildinfo
        binnmucmds = []
        if self.buildinfo.logentry:
            binnmucmds += [
                'cd {}'.format(quote(self.buildinfo.get_build_path())),
                "{{ printf '%s' {}; cat debian/changelog; }} > debian/changelog.debrebuild".format(quote(self.buildinfo.logentry)),
                "mv debian/changelog.debrebuild debian/changelog"
            ]

        # Prepare build directory and get package source
        cmd += [
            '--customize-hook=chroot "$1" env sh -c \"{}\"'.format(" && ".join(
                [
                    'apt-get source --only-source -d {}={}'.format(self.buildinfo.source, self.buildinfo.source_version),
                    'mkdir -p {}'.format(os.path.dirname(quote(self.buildinfo.get_build_path()))),
                    'dpkg-source --no-check -x /*.dsc {}'.format(quote(self.buildinfo.get_build_path())),
                ] + binnmucmds + [
                    'chown -R builduser:builduser {}'.format(os.path.dirname(quote(self.buildinfo.get_build_path()))),
                ]
            ))
        ]

        # Prepare build command
        cmd += [
            '--customize-hook=chroot "$1" runuser -u builduser -- env --chdir={} {}'.format(quote(self.buildinfo.get_build_path()), " && ".join(
                [
                    '{} dpkg-buildpackage -uc -a {} --build={}'.format(
                        ' '.join(self.get_env()), self.buildinfo.host_arch, build)
                ]
            ))
        ]

        cmd += [
            '--customize-hook=sync-out {} {}'.format(os.path.dirname(quote(self.buildinfo.get_build_path())), output),
            self.buildinfo.get_debian_suite(),
            '/dev/null',
            self.get_chroot_basemirror()
        ]

        logger.debug(' '.join(cmd))
        if subprocess.run(cmd).returncode != 0:
            raise RebuilderException("mmdebstrap failed")

    def verify_checksums(self, new_buildinfo):
        status = True
        for alg in self.buildinfo.checksums.keys():
            checksums = self.buildinfo.checksums[alg]
            new_checksums = new_buildinfo.checksums[alg]
            files = [f for f in checksums if not f['name'].endswith('.dsc')]
            new_files = [f for f in new_checksums if not f['name'].endswith('.dsc')]

            if len(files) != len(new_files):
                logger.debug(f"old buildinfo: {' '.join(files)}")
                logger.debug(f"new buildinfo: {' '.join(new_files)}")
                raise RebuilderException(
                    f"New buildinfo contains a different number of files in {alg} checksums.")

            for f in files:
                new_file = None
                for nf in new_files:
                    if nf['name'] == f['name']:
                        new_file = nf
                        break
                if not new_file:
                    raise RebuilderException(
                        f"Cannot find {f['name']} in new files")
                cur_status = True
                for prop in f.keys():
                    if prop not in new_file.keys():
                        raise RebuilderException(
                            f"'{prop}' is not used in both buildinfo files")
                    if prop == "size":
                        if f["size"] != new_file["size"]:
                            logger.error(f"Size differs for {f['name']}")
                            cur_status = False
                        continue
                    if f[prop] != new_file[prop]:
                        logger.error(f"Value of {prop} differs for {f['name']}")
                        cur_status = False
                if cur_status:
                    logger.info(f"{f['name']}: OK")
                else:
                    status = False

        if not status:
            msg = "Checksums: FAIL"
            logger.error(msg)
            raise RebuilderChecksumsError
        else:
            logger.info("Checksums: OK")

    def generate_intoto_metadata(self, output, new_buildinfo):
        new_files = [f['name'] for f in new_buildinfo.checksums["sha256"]
                     if not f['name'].endswith('.dsc')]
        cmd = [
            "in-toto-run", "--step-name=rebuild", "--no-command",
            "--products"
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
            raise RebuilderInTotoError("in-toto metadata generation failed")
        logger.info("in-toto metadata generation: OK")

    @staticmethod
    def get_host_architecture():
        try:
            builder_architecture = subprocess.check_output(
                ["dpkg", "--print-architecture"]).decode('utf8').rstrip('\n')
        except FileNotFoundError:
            raise RebuilderException("Cannot determinate builder host architecture")
        return builder_architecture

    def run(self, builder, output):
        # Predict new buildinfo name created by builder
        # Based on dpkg/scripts/dpkg-genbuildinfo.pl
        if self.buildinfo.architecture:
            build_arch = self.get_host_architecture()
        elif self.buildinfo.build_archall:
            build_arch = "all"
        elif self.buildinfo.build_source:
            build_arch = "source"
        else:
            raise RebuilderException("Nothing to build")
        new_buildinfo_file = f"{output}/{self.buildinfo.source}_{self.buildinfo.version}_{build_arch}.buildinfo"
        logger.debug(f"New buildinfo file: {new_buildinfo_file}")
        if os.path.exists(new_buildinfo_file):
            raise RebuilderException(
                "Refusing to overwrite existing buildinfo file")

        # Stage 1: Parse provided buildinfo file and setup the rebuilder
        try:
            if self.use_metasnap:
                logger.debug("Use metasnap for getting required timestamps")
                self.find_build_dependencies_from_metasnap()
            if not self.required_timestamp_sources:
                logger.debug("Use snapshot for getting required timestamps")
                self.find_build_dependencies()
        except (apt_pkg.Error, apt.cache.FetchFailedException,
                requests.exceptions.ConnectionError) as e:
            raise RebuilderException(f"Failed to fetch packages: {str(e)}")
        except KeyboardInterrupt:
            raise RebuilderException("Interruption")
        finally:
            if self.tempaptdir and self.tempaptdir.startswith(
                    os.path.join(self.tmpdir, 'debrebuild-')):
                if self.tempaptcache:
                    self.tempaptcache.close()
                shutil.rmtree(self.tempaptdir)
            if self.buildinfo_file.startswith(
                    os.path.join(self.tmpdir, 'buildinfo-')):
                os.remove(self.buildinfo_file)

        # Stage 2: Run the actual rebuild of provided buildinfo file
        if builder == "none":
            return
        if builder == "mmdebstrap":
            self.mmdebstrap(output)

        # Stage 3: Everything post-build actions with rebuild artifacts
        new_buildinfo = BuildInfo(realpath(new_buildinfo_file))
        self.generate_intoto_metadata(output, new_buildinfo)
        self.verify_checksums(new_buildinfo)


def get_args():
    parser = argparse.ArgumentParser(
        description='Given a buildinfo file from a Debian package, '
                    'generate instructions for attempting to reproduce '
                    'the binary packages built from the associated source '
                    'and build information.'
    )
    parser.add_argument(
        "buildinfo",
        help="Input buildinfo file. Local or remote file."
    )
    parser.add_argument(
        "--output",
        help="Directory for the build artifacts",
    )
    parser.add_argument(
        "--builder",
        help="Which building software should be used. (default: none)",
        default="none"
    )
    parser.add_argument(
        "--query-url",
        help="API url for querying package and binary information "
             "(default: http://snapshot.debian.org)",
        default="http://snapshot.debian.org"
    )
    parser.add_argument(
        "--snapshot-mirror",
        help="Snapshot mirror to use (default: http://snapshot.debian.org)",
        default="http://snapshot.debian.org"
    )
    parser.add_argument(
        "--use-metasnap",
        help="Use metasnap.debian.net. In contrast to snapshot.debian.org "
             "service, the metasnap.debian.net service will always return a "
             "minimal set of timestamps if the package versions were at some "
             "point part of Debian unstable main.",
        action="store_true"
    )
    parser.add_argument(
        "--extra-repository-file",
        help="Add repository file content to the list of apt sources during "
             "the package build.",
        action="append"
    )
    parser.add_argument(
        "--extra-repository-key",
        help="Add key file (.asc) to the list of trusted keys during "
             "the package build.",
        action="append"
    )
    parser.add_argument(
        "--gpg-sign-keyid",
        help="GPG keyid to use for signing in-toto metadata."
    )
    parser.add_argument(
        "--gpg-verify",
        help="Verify buildinfo GPG signature.",
        action="store_true"
    )
    parser.add_argument(
        "--gpg-verify-key",
        help="GPG key to use for buildinfo GPG check."
    )
    parser.add_argument(
        "--proxy",
        help="Proxy address to use."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display logger info messages."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Display logger debug messages."
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
        args.extra_repository_file = \
            [realpath(repo_file) for repo_file in args.extra_repository_file]

    if args.extra_repository_key:
        args.extra_repository_key = \
            [realpath(key_file) for key_file in args.extra_repository_key]

    if args.gpg_verify and not args.gpg_verify_key:
        logger.error(
            "Cannot verify buildinfo signature without GPG keyring provided")
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
            use_metasnap=args.use_metasnap
        )
        rebuilder.run(builder=args.builder, output=realpath(args.output))
    except RebuilderChecksumsError:
        return 2
    except RebuilderException as e:
        logger.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
