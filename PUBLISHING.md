# Publishing parrot-mcp

Everything you need to put this in front of other people, from an empty folder
to a stranger running it in one command.

Only the Python package gets published. The Docker target uses the official
`parrotsec/security` image, so there is no image of your own to build, tag or
push — users pull Parrot's.

| What | Where | Who needs it |
|---|---|---|
| The Python package | PyPI | Anyone using `pip install parrot-mcp` or `uvx parrot-mcp` |

`pip install .` from a clone works today, so nothing is blocked on PyPI.

Work top to bottom. Nothing here is destructive until Step 5.

---

## Before you start

You need:

- a GitHub account and the `gh` CLI or a browser
- a PyPI account (free) — https://pypi.org/account/register/
- a TestPyPI account (free, separate) — https://test.pypi.org/account/register/
- Docker running locally
- Python 3.10+ with `build` and `twine`

Check the tooling:

```bash
python -m pip install --upgrade build twine
python -m build --version
twine --version
git --version
docker --version
```

The name `parrot-mcp` was free on both PyPI and TestPyPI when this was written.
Confirm again in Step 4 — names do get taken.

---

## Step 1 — Make sure the code is clean

```bash
python -m pytest -q          # expect: 62 passed
python -m build              # expect: parrot_mcp-1.1.0.tar.gz and the wheel
twine check dist/*           # expect: PASSED for both files
```

If tests fail, stop. Do not publish a red build.

The version comes from `parrot_mcp/__init__.py`. It should read `1.1.0`, and
`CHANGELOG.md` should have a `## [1.1.0]` section. If you changed anything since
the last release, bump both before you go further:

- breaking change → `2.0.0`
- new tool or flag → `1.2.0`
- bug fix only → `1.1.1`

---

## Step 2 — Put it on GitHub

There is no git history yet, so create it.

```bash
git init -b main
git add -A
git commit -m "parrot-mcp 1.1.0"
```

Create an empty repo on GitHub named `parrot-mcp` (no README, no licence, no
gitignore — you already have those), then:

```bash
git remote add origin https://github.com/daoudiyounes/parrot-mcp.git
git push -u origin main
```

Now fix the placeholders. Search for `daoudiyounes` and replace it:

```bash
grep -rn "daoudiyounes" --include="*.md" --include="*.toml" .
```

- `pyproject.toml` — fill in the `[project.urls]` block:
  ```toml
  [project.urls]
  Repository = "https://github.com/daoudiyounes/parrot-mcp"
  Issues = "https://github.com/daoudiyounes/parrot-mcp/issues"
  ```
- `README.md` — the clone line.

Commit and push again.

---

## Step 3 — Let CI prove it works

`.github/workflows/ci.yml` runs on every push. It does three jobs:

1. `pytest` on Python 3.10, 3.11, 3.12 and 3.13.
2. `pip install .` on a clean machine, then `parrot-mcp --version`.
3. Builds the server image, starts it, and calls `/health`.

Open the Actions tab and wait for green. The image job catches packaging
mistakes before anyone installs the package.

---

## Step 4 — Dry run on TestPyPI

Never upload to PyPI first. TestPyPI is a separate server where mistakes are
free and permanent uploads to the real index are not.

Confirm the name is still free:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/simple/parrot-mcp/
# 404 = free, 200 = taken
```

Build clean and upload:

```bash
rm -rf dist/
python -m build
twine check dist/*
twine upload --repository testpypi dist/*
```

It asks for a username and password: username `__token__`, password is a
TestPyPI API token from https://test.pypi.org/manage/account/token/.

Install it in a throwaway environment to prove it works:

```bash
python -m venv /tmp/pmcp-test
/tmp/pmcp-test/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  parrot-mcp==1.1.0
/tmp/pmcp-test/bin/parrot-mcp --version
```

Expect `parrot-mcp 1.1.0`.

The `--extra-index-url` matters: TestPyPI does not carry the real dependencies
(`fastmcp`, `paramiko`), so pip has to fetch those from PyPI.

On Windows PowerShell the same commands work with
`.\.venv\Scripts\python.exe -m ...` and
`.\.venv-test\Scripts\parrot-mcp.exe --version`.

If this fails, fix it now. Re-uploading to TestPyPI with the same version is
allowed; re-uploading to PyPI is not.

---

## Step 5 — Publish to PyPI

Two ways to authenticate. Trusted Publishing is cleaner and needs no token in
your shell history.

### Option A — Trusted Publishing (recommended)

1. On PyPI: **Your account → Publishing → Add a new pending publisher**.
2. Fill in: project `parrot-mcp`, owner `daoudiyounes`, repository
   `parrot-mcp`, workflow `publish.yml`, environment `pypi`.
3. Add a workflow that builds and publishes. Create
   `.github/workflows/publish.yml`:

```yaml
name: publish

on:
  release:
    types: [published]

jobs:
  pypi:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install --upgrade build
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
```

4. Publish a GitHub Release (Step 7). The workflow uploads automatically.

### Option B — API token (manual)

Create a project-scoped token at https://pypi.org/manage/account/token/, then:

```bash
twine upload dist/*
# username: __token__
# password: pypi-AgEIcHlwaS5vcmc...
```

Verify as a stranger would:

```bash
python -m venv /tmp/pmcp-verify
/tmp/pmcp-verify/bin/pip install parrot-mcp
/tmp/pmcp-verify/bin/parrot-mcp --version

uvx parrot-mcp --version      # the one-liner most people will paste
```

`uvx` works as soon as the package is on PyPI. There is nothing else to set up.

---

## Step 6 — Nothing to publish for Docker

The docker target runs Parrot's own image, pulled on first use:

```bash
docker pull parrotsec/security:latest
```

There is no custom image to build or push. If a wrapped tool is missing from
the official image, install it once inside the persistent container:

```text
set_execution_target(target="docker", docker_container="parrot")
run_command(command="apt-get update && apt-get install -y hydra exploitdb")
```

That install survives between commands because the container is reused. List
what is present with `check_tools`. See the README section "Missing tools" for
the full install line.

The `Dockerfile` in the repo is only for running the *server itself* in a
container (HTTP mode). Publishing it is optional and not needed for users who
install the package.

---

## Step 7 — Tag and release

```bash
git tag v1.1.0
git push origin v1.1.0
```

GitHub → **Releases** → **Draft a new release** → tag `v1.1.0`. Title it
`1.1.0`. Paste the `[1.1.0]` section of `CHANGELOG.md` as the description.
If you used Trusted Publishing, publishing the release is what triggers the
PyPI upload — check the Actions run afterwards.

---

## Step 8 — Check the docs tell the truth

Every install command in the docs should be one you have run yourself in the
last day. Walk the README:

- [ ] `pip install parrot-mcp` works
- [ ] `uvx parrot-mcp --version` works
- [ ] `docker pull parrotsec/security:latest` works
- [ ] `claude mcp add parrot -- parrot-mcp --mode docker --container parrot` starts
- [ ] `check_tools` runs and lists what the official image has
- [ ] `nmap_scan` against a host you own returns a result
- [ ] `examples/*.json` point at a real binary path or command

Fix anything that does not. A broken install line is the most common way a
project like this dies, and it takes ten minutes to check.

---

## Step 9 — Tell people

Short and specific beats a wall of badges:

- the repo README is the landing page; keep the quick start at the top
- one sentence in the release notes saying what changed and what breaks

Do not claim more than the tool does. It has no scope enforcement, no TLS, no
long-lived sessions. Say so; the people who need it will still use it, and you
won't be surprised by a report later.

---

## Later releases

The short loop:

```bash
# make changes
python -m pytest -q
# edit CHANGELOG.md: add a new [x.y.z] section
# bump __version__ in parrot_mcp/__init__.py to the same number
git commit -am "release x.y.z"
git tag vx.y.z && git push origin vx.y.z
rm -rf dist/ && python -m build && twine check dist/*
twine upload dist/*
```

Then a GitHub Release from the tag.

**A version on PyPI can never be reused.** If you upload 1.1.0 with a bug, you
publish 1.1.1. You can delete a release (with `twine upload --skip-existing` or
the PyPI web UI) but the version number stays burned.

---

## If something goes wrong

**`File already exists` from twine.** That version is already on PyPI. Bump it.

**`HTTPError: 403` on upload.** Wrong token, or a token scoped to a different
project. Regenerate it for `parrot-mcp`.

**`check_tools` shows MISS on the published image.** The build failed to install
a package. Run `docker run --rm --entrypoint bash <image> -c 'apt-get update'`
and check the log line from the Dockerfile's install loop.

**`parrot-mcp` command not found after install.** The venv isn't active, or
`~/.local/bin` isn't on PATH. Use `python -m parrot_mcp.server --help` to
confirm the package installed.

**The name is taken.** Pick a new one in `pyproject.toml` and the README, then start again from Step 4.

---

## Checklist

```
[ ] 1. pytest green, build clean, twine check passes
[ ] 2. git init, push to GitHub, daoudiyounes replaced
[ ] 3. CI green, including the server image job
[ ] 4. TestPyPI upload, install from it, --version correct
[ ] 5. PyPI publish (Trusted Publishing or token), pip and uvx verified
[ ] 6. Official Parrot image pulls; missing tools installed once and persist
[ ] 7. Tag v1.1.0, GitHub Release with changelog text
[ ] 8. Every install line in the README actually run
[ ] 9. Announced, with honest limits stated
```

## How Docker works for users

The docker target pulls `parrotsec/security:latest` and creates one named
container on first use. It is reused, so anything you install stays:

```bash
parrot-mcp --mode docker --container parrot
```

```text
run_command(command="apt-get update && apt-get install -y hydra exploitdb")
```

Eleven of the 23 wrapped binaries ship in the official image. The other twelve
(amass, sublist3r, dnsrecon, dirsearch, sslyze, searchsploit, hydra, anonsurf,
macchanger, proxychains4, theHarvester, tor) return "not found" until installed.
The error message names the package, and `check_tools` shows the current state.
