# Development Notes and Guides

This file is intended to make it easier for new developers to get along with the code structure
and style of this project.

## Code Organisation

```text
py_simple_openid_connect/
├ src/simple_openid_connect/  (where all the main python code is located)
│  ├ data.py                  (message definitions for all OIDC interactions)
│  ├ client.py                (entry point for the high level client api)
│  ├ <others>                 (implementations for specific OIDC features)
│  ├ flows/                   (implementations of different authorization flows)
│  └ integrations/            (additional integrations into external software)
├ docs/                       (manually written documentation & sphinx config for auto-generated python docs)
└ tests/                      (test related code)
   ├ django_test_project/     (a simple django project using the django integration)
   ├ interactive_tests/       (tests which require user interaction to execute)
   └ <others>                 (pytest based test suit)
```

## How to set up a dev environment

### With nix

If you use nix, this project provides a `flake.nix` file that defines a development shell with all dependencies installed.
It can be entered by typing `nix develop`.
Additionally, a [nix-direnv](https://github.com/nix-community/nix-direnv) configuration file is also present which also sets up a python environment suitable for development.

### Manually

Ensure you have the following system dependencies installed:
- `python~=3.9`
- a python virtual environment manager. This document assumes [uv](https://github.com/astral-sh/uv).

Afterwards, follow the below commands to set up your development environment:

```shell
# create a virtual python environment
uv venv
# install this project + its dev dependencies into the virtual environment
uv pip install -e .[django,djangorestframework] -r requirements.dev.txt
# activate the venv python interpreter for use (use the correct activation script for your shell though)
source .venv/bin/activate
```

You should also enable [pre-commit](https://pre-commit.com/) hooks to check for linting and type errors before committing:

```shell
pre-commit install
```

## How to run the Tests

```shell
pytest
```

## How to build the Documentation

Assuming that the virtual environment is already activated, the following commands can be executed to build a local
version of the projects documentation.

```shell
cd docs
make html
```

Afterwards, the documentation is available as html files under `docs/_build/html`.
To view it, either open the files directly in your browser or use your favourite local http server to serve the content
(e.g. by running `python -m http.server -d docs/_build/html 8080`).

Sometimes, a clean build is required to update the documentation extracted from the source code.
This can be done by running `make clean`.

## How to release

In order to release a new version, the following steps are necessary.
Please keep in mind when picking a new version number that [Semantic Versioning](https://semver.org/) should be followed.

1. Bump version in [\_\_init\_\_.py](./src/simple_openid_connect/__init__.py).
2. Add entries regarding what changed to [CHANGELOG.md](./CHANGELOG.md).
3. Commit both changes using `git commit -m "bump version to vX.Y.Z"`
4. Tag the commit using `git tag -a -s vX.Y.Z`.

   The tag name should be the same as the version number and the tag notes should contain a copy of the changelog entry of the new version.
5. Publish to pypi using `flit publish`
