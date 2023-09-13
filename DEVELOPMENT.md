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

## How to set up the project

```shell
# create a virtual python environment
virtualenv venv
# activate it
source ./venv/bin/activate
# install this project into the venv + dev dependencies
pip install -e .[django,djangorestframework] -r requirements.dev.txt
```

## How to release

In order to release a new version, the following steps are necessary:

1. Bump version in [__init__.py](./src/simple_openid_connect/__init__.py) and commit the change
2. Tag the commit using `git tag -a -s v$version`
3. Publish to pypi using `flit publish`
