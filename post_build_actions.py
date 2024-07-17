import os
import json
import glob
import logging
import subprocess

from google.auth.transport import requests
from lib.downloads import download_with_retry
from initialize_and_find_dependencies import Rebuilder, RebuilderBuildInfo
import logging
import sys

logger = logging.getLogger("post_build_actions")
logger.setLevel(logging.DEBUG)  # Set logger level to DEBUG
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.DEBUG)  # Set handler level to DEBUG
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logger = logging.getLogger("execute_build")
logger.setLevel(logging.DEBUG)  # Set logger level to DEBUG

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

def verify_checksums(self, output, new_buildinfo):
    status = True
    summary = {}
    changed_packages = set()
    use_new_buildinfo = not is_source_available(self)

    logger.debug(f"Using new buildinfo: {use_new_buildinfo}")

    # Identify changed packages
    logger.debug("Identifying changed packages...")
    for pkg in self.buildinfo.build_depends + [self.buildinfo.source]:
        new_pkg = next((npkg for npkg in new_buildinfo.build_depends if npkg['name'] == pkg['name']), None)
        if new_pkg and new_pkg['version'] != pkg['version']:
            changed_packages.add(pkg['name'])
            logger.debug(f"Package version changed: {pkg['name']} from {pkg['version']} to {new_pkg['version']}")

    for alg in self.buildinfo.checksums.keys():
        checksums = self.buildinfo.checksums[alg]
        new_checksums = new_buildinfo.checksums.get(alg, {})
        files = [f for f in checksums if not f["name"].endswith(".dsc")]
        new_files = [f for f in new_checksums if not f["name"].endswith(".dsc")]

        summary.setdefault(alg, {})

        for f in files:
            new_file = next((nf for nf in new_files if nf["name"] == f["name"]), None)
            if not new_file:
                logger.error(f"{alg}: Cannot find equivalent for {f['name']} in new files")
                raise RebuilderException(f"{alg}: Cannot find equivalent for {f['name']} in new files")
            summary[alg].setdefault(new_file["name"], {})
            cur_status = True

            for prop in f:
                if prop not in new_file:
                    logger.error(f"{alg}: Property {prop} missing in new file for {f['name']}")
                    raise RebuilderException(f"{alg}: '{prop}' is not used in both buildinfo files")

                if prop != "name":
                    summary[alg][new_file["name"]][prop] = {"old": f[prop], "new": new_file[prop]}
                    if f[prop] != new_file[prop]:
                        logger.error(
                            f"{alg}: Value of '{prop}' differs for {f['name']} (old: {f[prop]}, new: {new_file[prop]})")
                        cur_status = False

            if cur_status:
                logger.info(f"{alg}: {new_file['name']}: OK")
            else:
                status = False

    if not status:
        logger.error("Checksum verification failed")
    else:
        logger.info("Checksum verification succeeded")

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

def download_from_snapshot(self, path, sha256):
    url = f"{self.snapshot_url}/mr/file/{sha256}/download"
    if not requests.head(url, timeout=10).ok:
        raise RebuilderException(f"Cannot find URL: {url}")
    return download_with_retry(url, path, sha256)

def generate_diffoscope(rebuilder, output, summary):
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
                download_from_snapshot(rebuilder, debian_file, files[f]["sha256"]["old"])
                run_diffoscope(output, debian_file, f)
            except Exception as e:
                logger.error(f"Cannot generate diffoscope for {f}: {str(e)}")
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

def post_build_actions(rebuilder, output):
    # Post-build actions
    logger.debug("Finding buildinfo files in output directory...")
    buildinfo_files = glob.glob(os.path.join(output, "*.buildinfo"))
    if not buildinfo_files:
        logger.error("No buildinfo file found in the output directory.")
        raise BuildInfoException("Cannot find any buildinfo file in the specified directory.")

    new_buildinfo_file = max(buildinfo_files, key=os.path.getmtime)
    logger.debug(f"Using buildinfo file: {new_buildinfo_file}")

    if is_source_available(rebuilder
                           ):
        new_buildinfo = RebuilderBuildInfo(new_buildinfo_file, False)
    else:
        new_buildinfo = RebuilderBuildInfo(new_buildinfo_file, True)

    status, summary = verify_checksums(rebuilder, output, new_buildinfo)
    with open(os.path.join(output, "summary.out"), "w") as fd:
        fd.write(json.dumps(summary))

    if not status:
        logger.error("Checksum verification failed.")
        generate_diffoscope(rebuilder, output, summary)
        raise RebuilderChecksumsError

    if rebuilder.gpg_sign_keyid:
        logger.debug("Generating in-toto metadata.")
        generate_intoto_metadata(rebuilder, output, new_buildinfo)

    logger.debug("Post-build actions completed successfully.")

def main():
    import sys

    if len(sys.argv) != 3:
        logger.debug("Usage: python post_build_actions.py <rebuilder_json_file> <output_directory>")
        sys.exit(1)

    rebuilder_json_file = sys.argv[1]
    artifacts_dir = sys.argv[1]

    # Load the Rebuilder instance from the JSON file
    with open(rebuilder_json_file, 'r') as f:
        rebuilder_data = json.load(f)

    rebuilder = Rebuilder.from_dict(rebuilder_data, rebuilder_json_file)
    rebuilder.buildinfo = RebuilderBuildInfo(rebuilder.buildinfo_file)

    # Call the post_build_actions function with the Rebuilder instance
    post_build_actions(rebuilder, artifacts_dir)

if __name__ == "__main__":
    main()
