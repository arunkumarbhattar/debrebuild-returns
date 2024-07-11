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
import subprocess
import sys
import tempfile
import glob
import debian.deb822
import debian.debian_support

# Configure logging
logger = logging.getLogger("debrebuild")
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

def get_source_name_from_buildinfo(buildinfo_file):
    with open(buildinfo_file) as fd:
        parsed_info = debian.deb822.BuildInfo(fd)
        source_name, _ = parsed_info.get_source()
    return source_name

def run(builder_args):
    logger.debug("Starting the run function")

    # Create a temporary JSON file to pass the builder_args dictionary
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode='w') as tf:
        json.dump(builder_args, tf)
        builder_args_json_file = tf.name

    # Run the subprocess with the JSON file as an argument
    try:
        subprocess.run(["python3", "initialize_and_find_dependencies.py", builder_args_json_file], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to initialize and find dependencies: {e}")
        raise RebuilderException("Failed to initialize and find dependencies")

    output_dir = builder_args["output_dir"]

    # Extract the source name from the buildinfo file
    source_name = get_source_name_from_buildinfo(builder_args["buildinfo_file"])
    checkpoint_dir = os.path.join("build_checkpoint", source_name)
    checkpoint_file = f"checkpoint_find_dep_{source_name}.json"
    checkpoint_json_path = os.path.join(checkpoint_dir, checkpoint_file)

    if not os.path.exists(checkpoint_json_path):
        logger.error(f"Checkpoint JSON file not found: {checkpoint_json_path}")
        raise RebuilderException("Checkpoint JSON file not found")

    # Run the subprocess with the checkpoint JSON file and output directory for execute_build
    try:
        subprocess.run(["python3", "execute_build.py", checkpoint_json_path, output_dir], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute build: {e}")
        raise RebuilderException("Failed to execute build")

    # Post-build actions
    logger.debug("Finding buildinfo files in output directory...")
    buildinfo_files = glob.glob(os.path.join(output_dir, "*.buildinfo"))
    if not buildinfo_files:
        logger.error("No buildinfo file found in the output directory.")
        raise BuildInfoException("Cannot find any buildinfo file in the specified directory.")

    new_buildinfo_file = max(buildinfo_files, key=os.path.getmtime)
    logger.debug(f"Using buildinfo file: {new_buildinfo_file}")

    # Post-build actions
    try:
        subprocess.run(["python3", "post_build_actions.py", checkpoint_json_path, output_dir], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to perform post-build actions: {e}")
        raise RebuilderException("Failed to perform post-build actions")

    logger.debug("Post-build actions completed successfully.")

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
        "--builder_json_file",
        help="builde process to resume from",
        default="",
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
            "output_dir": args.output
        }

        run(rebuilder_args)
    except RebuilderChecksumsError:
        return 2
    except RebuilderException as e:
        logger.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
