# Development notes

### How to release

In order to release a new version, the following steps are necessary:

1. Bump version in [__init__.py](./src/simple_openid_connect/__init__.py) and commit the change
2. Tag the commit using `git tag -a -s v$version`
3. Publish to pypi using `flit publish`
