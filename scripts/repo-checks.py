#!/usr/bin/env python3
"""Shared gate plumbing. Platform behaviour belongs in scripts/platform/."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def run(*args, **kwargs):
    print("+ " + " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), check=True, **kwargs)


def git_paths(*args):
    data = subprocess.check_output(["git", *args, "-z"])
    return [Path(os.fsdecode(p)) for p in data.split(b"\0") if p]


def files():
    return sorted({p for p in git_paths("ls-files", "--cached", "--others", "--exclude-standard") if p.is_file()})


def shell_files(paths):
    result = []
    for path in paths:
        first = path.read_bytes().split(b"\n", 1)[0]
        if path.suffix in {".sh", ".bash", ".bats", ".dash", ".ksh", ".zsh"} or re.match(rb"#!.*\b(?:ba|da|k|z)?sh\b", first):
            result.append(path)
    return result


def workflows(paths):
    return [p for p in paths if p.as_posix().startswith(".github/workflows/") and p.suffix in {".yml", ".yaml"}]


def lint(paths):
    actions = workflows(paths)
    if actions:
        run("actionlint", *actions)
        # Pedantic includes the SHA pinning audit. Offline keeps hooks deterministic.
        run("zizmor", "--offline", "--persona=pedantic", "--strict-collection", "--no-progress", *actions)
    scripts = shell_files(paths)
    if scripts:
        run("shellcheck", *scripts)
        run("shfmt", "-d", "-i", "4", *scripts)


def dependency_scan(paths):
    names = {"go.sum", "npm-shrinkwrap.json", "Pipfile.lock", "yarn.lock", "bun.lockb", "Package.resolved", "packages.lock.json"}
    locks = [p for p in paths if p.name != "mise.lock" and (
        p.name in names or p.name.endswith((".lock", ".lockb", ".lockfile", "-lock.json", "-lock.yaml", "-lock.yml"))
        or (p.name.startswith("requirements") and p.suffix == ".txt")
    )]
    if not locks:
        print("skipped: no dependency lockfiles present (Java runtime SBOM is in check:java:sbom)", flush=True)
        return
    args = ["osv-scanner", "scan", "source"]
    for path in locks:
        args.extend(["--lockfile", str(path)])
    run(*args)


def staged():
    run("gitleaks", "git", "--staged", "--redact", "--no-banner")
    run("git", "diff", "--cached", "--check")
    changed = git_paths("diff", "--cached", "--name-only", "--diff-filter=ACMR")
    with tempfile.TemporaryDirectory(prefix="ogiri-staged-") as directory:
        snapshot = Path(directory)
        run("git", "checkout-index", "--all", f"--prefix={snapshot}/")
        original = Path.cwd()
        os.chdir(snapshot)
        try:
            for path in changed:
                data = path.read_bytes()
                if b"\0" not in data and data and not data.endswith(b"\n"):
                    raise ValueError(f"formatter: {path}: missing final newline")
            lint(changed)
            java_files = [str(p) for p in changed if p.suffix == ".java" and p.as_posix().startswith(("ogiri/", "ogiri-spring-boot-starter/", "examples/spring-app/"))]
            if java_files:
                run("bash", original / "scripts/platform/java.sh", "staged", *java_files)
        finally:
            os.chdir(original)
    print("check:staged: PASS", flush=True)


def paths():
    base = os.environ.get("GATE_BASE_SHA", "")
    force = os.environ.get("GATE_FORCE_FULL", "false") == "true"
    if force or not base or set(base) == {"0"}:
        changed = None
    else:
        # A missing base is a gate failure, never an intentional path skip.
        changed = git_paths("diff", "--name-only", base, "HEAD")
    common = {"mise.toml", "lefthook.yml", ".gitignore"}
    shared = changed is None or any(p.as_posix() in common or p.as_posix().startswith((".github/", "contracts/", "examples/")) or (p.as_posix().startswith("scripts/") and not p.as_posix().startswith("scripts/platform/")) for p in changed)
    prefixes = {"java": ("ogiri/", "ogiri-spring-boot-starter/", "scripts/platform/java.sh"), "parity": ("contracts/conformance/", "ogiri/", "ogiri-spring-boot-starter/", "scripts/platform/")}
    results = {key: shared or any(p.as_posix().startswith(value) or (key in {"java", "parity"} and p.as_posix() == "pom.xml") for p in (changed or [])) for key, value in prefixes.items()}
    output = "".join(f"{key}={str(value).lower()}\n" for key, value in results.items())
    print(output, end="")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(output)


def result():
    needs = json.loads(os.environ["GATE_RESULTS"])
    assert needs["repo"]["result"] == "success", f"repo: {needs['repo']['result']}"
    selected = needs["repo"]["outputs"]
    for name in ("java", "parity"):
        expected = selected[name] == "true"
        status = needs[name]["result"]
        assert status == "success" or (not expected and status == "skipped"), f"{name}: {status} (selected={expected})"
    print("quality-gates: PASS (all selected jobs succeeded)")


def main():
    mode = sys.argv[1]
    if mode == "check":
        paths_to_check = files()
        lint(paths_to_check)
        run("gitleaks", "git", "--log-opts=HEAD", "--gitleaks-ignore-path=.github/.gitleaksignore", "--redact", "--no-banner")
        # History alone cannot see a newly edited/untracked secret.
        with tempfile.TemporaryDirectory(prefix="ogiri-secrets-") as directory:
            snapshot = Path(directory)
            for path in paths_to_check:
                target = snapshot / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
            run("gitleaks", "dir", "--redact", "--no-banner", snapshot)
        dependency_scan(paths_to_check)
        print("check:repo: PASS")
    elif mode == "staged":
        staged()
    elif mode == "fix":
        scripts = shell_files(files())
        if scripts:
            run("shfmt", "-w", "-i", "4", *scripts)
    elif mode == "paths":
        paths()
    elif mode == "result":
        result()
    else:
        raise ValueError(f"unknown repository task: {mode}")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError, AssertionError) as error:
        print(f"gate failed: {error}", file=sys.stderr)
        sys.exit(1)
