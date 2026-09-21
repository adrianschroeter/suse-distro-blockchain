#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""zypp repoverification plugin for the openSUSE distro attestation contract.

libzypp launches every executable in ``/usr/lib/zypp/plugins/repoverification``
during a repository metadata refresh, immediately after ``repodata/repomd.xml``
has been downloaded and before any GPG checks or solv conversion. A non-zero
exit status makes libzypp discard the repository, which blocks the metadata
update of that single repository.

The plugin is stateless and is invoked for *every* repository, therefore it is
opt-in by policy: only aliases with a ``[repo:<alias>]`` section in
``/etc/suse-distro-check.conf`` are enforced. Repositories without such a section
are handled according to the ``unmanaged`` policy (default: allowed).

See also ``suse_distro_blockchain.metadata`` for the shared check logic.
"""

import argparse
import os
import sys

try:
    from . import metadata
    from .metadata import OK, REJECT
except ImportError:  # pragma: nocover - direct execution as a plugin
    import metadata
    from metadata import OK, REJECT

try:
    from termcolor import colored
except ImportError:  # pragma: nocover - keep the plugin usable without colors
    def colored(text, *_args, **_kwargs):
        return text


def build_parser():
    parser = argparse.ArgumentParser(
        prog="suse-distro-check",
        description=(
            "zypp repoverification plugin: verify the raw repository metadata "
            "against the on-chain distro attestation contract."
        ),
    )
    parser.add_argument("--file", dest="file", help="path to the repository master index (repomd.xml)")
    parser.add_argument("--fsig", dest="fsig", help="path to the detached GPG signature")
    parser.add_argument("--fkey", dest="fkey", help="path to the GPG key")
    parser.add_argument("--ralias", dest="ralias", help="alias of the repository")
    parser.add_argument("--conf", default=None, help=f"config file (default: {metadata.DEFAULT_CONF})")
    parser.add_argument("--network", help="override the network section")
    parser.add_argument("--contract", help="override the contract address")
    parser.add_argument("--timeout", type=float, default=10.0, help="JSON-RPC timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="explain allowed repositories too")
    return parser


def emit(result, verbose=True):
    if not verbose and result.level == OK:
        return
    print(colored(f"[{metadata.TAG[result.level]}] {result.name}: {result.message}",
                  metadata.COLORS[result.level]))


def main(argv=None):
    args, unknown = build_parser().parse_known_args(argv)
    if unknown:
        print(f"suse-distro-check: ignoring unknown arguments: {' '.join(unknown)}", file=sys.stderr)
    alias = args.ralias or ""

    if not args.ralias and not args.file:
        print(
            "suse-distro-check: no repository context given (--ralias/--file); "
            "this plugin is normally invoked by libzypp during a refresh.",
            file=sys.stderr,
        )
        return 0

    conf_path = args.conf or metadata.default_conf_path()
    try:
        conf = metadata.load_conf(conf_path)
    except Exception as exc:  # never brick zypper over a broken config
        print(f"suse-distro-check: cannot read {conf_path}: {exc}", file=sys.stderr)
        conf = {}

    policy = metadata.resolve_policy(conf, alias)
    if args.network:
        policy.values["network"] = args.network

    for issue in policy.issues:
        print(colored(f"[warn] config: {issue}", "yellow"))

    if args.verbose:
        section = metadata.repo_section(alias)
        print(
            f"# conf={conf_path} alias={alias!r} managed={policy.managed} "
            f"section={section if policy.managed else '(none)'} "
            f"registered={policy.level('registered')} unmanaged={policy.level('unmanaged')}",
            file=sys.stderr,
        )

    if not policy.managed:
        result = metadata.unmanaged_result(policy)
        emit(result, verbose=args.verbose or result.level != OK)
        return 1 if result.level == REJECT else 0

    if not args.file or not os.path.exists(args.file):
        print(f"suse-distro-check: no repository master index for {alias!r}, skipping")
        return 0

    try:
        results = metadata.verify_repomd(
            args.file,
            policy,
            conf,
            fsig_path=args.fsig,
            timeout=args.timeout,
            contract_override=args.contract,
        )
    except Exception as exc:  # fail closed on the unexpected
        print(colored(f"[ERROR] internal: {exc}", "red"))
        return 1

    for result in results:
        emit(result, verbose=args.verbose or result.level != OK)

    return 1 if metadata.worst(results) == REJECT else 0


if __name__ == "__main__":
    sys.exit(main())
