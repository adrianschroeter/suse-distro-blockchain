# SPDX-License-Identifier: GPL-3.0-or-later
"""``spodman`` - a verifying front end for podman.

Podman has no pull-time plugin hook (``containers-policy.json`` only supports
signature based requirements), so enforcement is provided by a small wrapper
installed in parallel to podman as ``spodman`` (users call ``spodman`` instead
of ``podman`` when they want the checks):

1. it locates the real podman binary (``PODMAN_REAL`` overrides the lookup),
2. for ``pull``/``run``/``create`` it resolves the image reference with
   ``suse-distro-oci-check`` and, if the scope is managed, rewrites the
   reference to ``image@sha256:<verified digest>`` before delegating,
3. a rejected image makes the shim exit non-zero without calling podman.

Unmanaged scopes (no ``[oci:<registry/repo>]`` section) are passed through
untouched so the shim stays a no-op on systems that did not opt in.

Set ``SUSE_DISTRO_OCI_CHECK_SKIP=1`` to bypass verification.
"""

import os
import re
import shutil
import subprocess
import sys

# exit code used by suse-distro-oci-check when the scope has no policy
UNMANAGED = 3

INTERCEPTED = ("pull", "run", "create")

# podman global options that take a separate value
_GLOBAL_VALUE_OPTS = {
    "--cgroup-manager", "--conmon", "--config", "--connection", "--events-backend",
    "--hooks-dir", "--identity", "--imagestore", "--log-level", "--namespace",
    "--network-config-dir", "--root", "--runroot", "--runtime", "--runtime-flag",
    "--ssh", "--storage-driver", "--storage-opt", "--tmpdir", "--url",
}
_GLOBAL_SHORT_VALUE_OPTS = {"-c"}

# subcommand options that take a separate value (subset covering common usage)
_SUB_VALUE_OPTS = {
    "--add-host", "--annotation", "--arch", "--attach", "--authfile", "--blkio-weight",
    "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile",
    "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime", "--cpu-shares",
    "--cpus", "--cpuset-cpus", "--cpuset-mems", "--device", "--dns", "--dns-option",
    "--dns-search", "--entrypoint", "--env", "--env-file", "--env-host", "--expose",
    "--gidmap", "--group-add", "--group-entry", "--health-cmd", "--health-interval",
    "--health-retries", "--health-start-period", "--health-timeout", "--hostname",
    "--hostuser", "--image-volume", "--init-path", "--ip", "--ipc", "--label",
    "--label-file", "--log-driver", "--log-opt", "--mac-address", "--memory",
    "--memory-swap", "--memory-swappiness", "--mount", "--name", "--network",
    "--network-alias", "--oom-score-adj", "--os", "--pid", "--pids-limit", "--platform",
    "--pod", "--publish", "--pull", "--restart", "--security-opt", "--shm-size",
    "--stop-signal", "--stop-timeout", "--subgidname", "--subuidname", "--sysctl",
    "--tmpfs", "--uidmap", "--ulimit", "--umask", "--user", "--userns", "--uts",
    "--volume", "--volume-driver", "--volumes-from", "--workdir",
}
_SUB_SHORT_VALUE_OPTS = {"-e", "-h", "-l", "-m", "-p", "-u", "-v", "-w"}

# transports that do not refer to a remote registry
_LOCAL_PREFIXES = (
    "dir:", "oci:", "oci-archive:", "docker-archive:", "docker-daemon:",
    "containers-storage:", "atomic:",
)
_IMAGE_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")


def find_real_podman(self_path=None):
    """Return the path of the real podman binary, skipping this shim."""
    override = os.environ.get("PODMAN_REAL")
    if override:
        return override
    self_path = self_path or os.environ.get("SUSE_DISTRO_SPODMAN_SELF")
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, "podman")
        if not os.path.exists(candidate):
            continue
        if self_path:
            try:
                if os.path.samefile(candidate, self_path):
                    continue
            except OSError:
                pass
        return candidate
    fallback = shutil.which("podman")
    if fallback and self_path:
        try:
            if os.path.samefile(fallback, self_path):
                return None
        except OSError:
            pass
    return fallback


def _is_local_reference(ref):
    if not ref:
        return True
    if ref.startswith(("/", ".", "~")):
        return True
    if ref.startswith(_LOCAL_PREFIXES):
        return True
    return bool(_IMAGE_ID_RE.match(ref))


def find_subcommand(argv):
    """Return ``(index, subcommand)`` in ``argv`` or ``(None, None)``."""
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            i += 1
            continue
        if token.startswith("--"):
            name = token.split("=", 1)[0]
            i += 1 if ("=" in token or name not in _GLOBAL_VALUE_OPTS) else 2
            continue
        if token.startswith("-") and token != "-":
            if len(token) == 2 and token in _GLOBAL_SHORT_VALUE_OPTS:
                i += 2
                continue
            i += 1
            continue
        return i, token
    return None, None


def _consume_value(token, value_opts, short_value_opts):
    """Return the number of extra tokens consumed by ``token`` as an option value."""
    if token.startswith("--"):
        if "=" in token or token.split("=", 1)[0] not in value_opts:
            return 0
        return 1
    if token.startswith("-") and token != "-":
        if len(token) == 2:
            return 1 if token in short_value_opts else 0
        # combined short options: a trailing value-taking option may carry its
        # value in the same token (-w/app) or as the next token (-w /app)
        if token[-1] in short_value_opts:
            return 1
        return 0
    return 0


def find_image_index(subcommand, args):
    """Return the index (into ``args``) of the image positional, or ``None``."""
    value_opts = _SUB_VALUE_OPTS
    short_value_opts = _SUB_SHORT_VALUE_OPTS
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            i += 1
            if i < len(args):
                return i
            return None
        if token.startswith("-") and token != "-":
            i += 1 + _consume_value(token, value_opts, short_value_opts)
            continue
        return i
    return None


def pull_policy(args):
    """Return the ``--pull`` policy value found in ``args`` (or ``None``)."""
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("--pull="):
            return token.split("=", 1)[1]
        if token == "--pull":
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                return args[i + 1]
            return "always"  # bare --pull is invalid; treat conservatively
        i += 1
    return None


def _verifier_command(ref):
    executable = shutil.which("suse-distro-oci-check")
    if executable:
        return [executable, "--managed-only", "--print-ref", ref]
    return [sys.executable, "-m", "suse_distro_blockchain.oci_check",
            "--managed-only", "--print-ref", ref]


def verify_reference(ref):
    """Return ``(exit_code, pinned_reference_or_None)`` for ``ref``."""
    proc = subprocess.run(_verifier_command(ref), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        if proc.stderr.strip():
            sys.stderr.write(proc.stderr)
        if proc.stdout.strip():
            sys.stderr.write(proc.stdout)
        return proc.returncode, None
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    return 0, (lines[-1].strip() if lines else None)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    real = find_real_podman()
    if not real:
        sys.stderr.write("spodman: cannot find the real podman binary "
                         "(set PODMAN_REAL)\n")
        return 127

    if os.environ.get("SUSE_DISTRO_OCI_CHECK_SKIP") == "1":
        os.execv(real, [real] + argv)

    index, subcommand = find_subcommand(argv)
    if subcommand not in INTERCEPTED:
        os.execv(real, [real] + argv)

    rest = argv[index + 1:]
    if pull_policy(rest) == "never":
        os.execv(real, [real] + argv)

    image_index = find_image_index(subcommand, rest)
    if image_index is None:
        os.execv(real, [real] + argv)

    ref = rest[image_index]
    if _is_local_reference(ref):
        os.execv(real, [real] + argv)

    try:
        code, pinned = verify_reference(ref)
    except FileNotFoundError as exc:
        sys.stderr.write(f"spodman: cannot run suse-distro-oci-check: {exc}\n")
        return 127

    if code == UNMANAGED:
        os.execv(real, [real] + argv)
    if code != 0 or not pinned:
        sys.stderr.write(f"spodman: image {ref!r} was rejected by "
                         "suse-distro-oci-check\n")
        return code or 1

    rest[image_index] = pinned
    new_argv = argv[:index + 1] + rest
    os.execv(real, [real] + new_argv)


if __name__ == "__main__":  # pragma: nocover
    sys.exit(main())
