#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""suse-distro-oci-check - verify an OCI container image against the contract.

The image reference is resolved to its manifest digest (via ``skopeo``), then
the digest is looked up on-chain exactly like repository metadata. Images are
matched to policy with ``[oci:<registry/repo>]`` sections in
``/etc/suse-distro-check.conf``; unmatched images follow the ``unmanaged``
policy (default: allowed).

A non-zero exit status means the image must not be used. On success the pinned
reference (``image@sha256:...``) can be printed with ``--print-ref``, which is
what the ``spodman`` front end uses to pull exactly the verified bytes.

See also ``suse_distro_blockchain.metadata`` for the shared check logic.
"""

import argparse
import sys

try:
    from . import metadata
    from .metadata import OK, REJECT
except ImportError:  # pragma: nocover - direct execution from a source checkout
    import metadata
    from metadata import OK, REJECT


# exit code used by the spodman front end to mean "scope has no policy, do nothing"
UNMANAGED = 3


def build_parser():
    parser = argparse.ArgumentParser(
        prog="suse-distro-oci-check",
        description="Verify an OCI container image against the on-chain distro attestation contract.",
    )
    parser.add_argument("image", help="image reference, e.g. registry.example/opensuse/leap:15.6")
    parser.add_argument("--conf", default=None, help=f"config file (default: {metadata.DEFAULT_CONF})")
    parser.add_argument("--network", help="override the network section")
    parser.add_argument("--contract", help="override the contract address")
    parser.add_argument("--timeout", type=float, default=10.0, help="JSON-RPC timeout in seconds")
    parser.add_argument("--print-ref", action="store_true",
                        help="print the verified image@sha256:<digest> reference on success")
    parser.add_argument("--managed-only", action="store_true",
                        help="exit with status 3 instead of reporting unmanaged scopes")
    parser.add_argument("-v", "--verbose", action="store_true", help="also show successful checks")
    return parser


def emit(result, verbose=True, stream=None):
    if not verbose and result.level == OK:
        return
    stream = stream or sys.stdout
    line = f"[{metadata.TAG[result.level]}] {result.name}: {result.message}"
    print(metadata.colorize(line, metadata.COLORS[result.level], stream), file=stream)


def main(argv=None):
    args = build_parser().parse_args(argv)

    conf_path = args.conf or metadata.default_conf_path()
    try:
        conf = metadata.load_conf(conf_path)
    except Exception as exc:  # never fail because of a broken config
        print(f"suse-distro-oci-check: cannot read {conf_path}: {exc}", file=sys.stderr)
        conf = {}

    scope = metadata.oci_scope(args.image)
    policy = metadata.resolve_oci_policy(conf, scope)
    if args.network:
        policy.values["network"] = args.network

    # With --print-ref only the pinned reference is written to stdout so that
    # callers (the spodman front end) can parse it; all diagnostics go to stderr.
    diag = sys.stderr if args.print_ref else sys.stdout

    for issue in policy.issues:
        print(metadata.colorize(f"[warn] config: {issue}", "yellow", sys.stderr),
              file=sys.stderr)

    if args.verbose:
        section = metadata.oci_section(scope)
        print(
            f"# conf={conf_path} scope={scope!r} managed={policy.managed} "
            f"section={section if policy.managed else '(none)'} "
            f"registered={policy.level('registered')} unmanaged={policy.level('unmanaged')}",
            file=sys.stderr,
        )

    if not policy.managed:
        if args.managed_only:
            return UNMANAGED
        result = metadata.unmanaged_result(policy)
        emit(result, verbose=args.verbose or result.level != OK, stream=diag)
        return 1 if result.level == REJECT else 0

    try:
        digest, results = metadata.verify_oci(
            args.image,
            policy,
            conf,
            timeout=args.timeout,
            contract_override=args.contract,
        )
    except Exception as exc:  # fail closed on the unexpected
        print(metadata.colorize(f"[ERROR] internal: {exc}", "red", diag), file=diag)
        return 1

    for result in results:
        emit(result, verbose=args.verbose or result.level != OK, stream=diag)

    if metadata.worst(results) == REJECT:
        return 1
    if args.print_ref and digest:
        print(f"{metadata.oci_scope(args.image)}@{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
