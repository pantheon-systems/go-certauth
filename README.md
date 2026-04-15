# go-certauth

[![Go Report Card](https://goreportcard.com/badge/github.com/pantheon-systems/go-certauth)](https://goreportcard.com/report/github.com/pantheon-systems/go-certauth)
[![Unsupported](https://img.shields.io/badge/Pantheon-Unsupported-yellow?logo=pantheon&color=FFDC28)](https://pantheon.io/docs/oss-support-levels#unsupported)

*Be aware this is a PUBLIC project/repo; see [LICENSE.txt](/LICENSE.txt) for details.*

This package provides TLS certificate based authentication middleware. Our goal is
compatibility with `net/http`, `httprouter` and possibly other popular Go HTTP
routers.

## Usage

Examples of usage with various http router libs in the `./examples` directory.

## Creating a Release

Releases are automated via GitHub Actions and [GoReleaser](https://goreleaser.com/).

To create a new release:

```bash
git tag -s v0.1.0
git push origin v0.1.0
```

Pushing a [SemVer](https://semver.org/) tag triggers the release workflow, which runs tests and then creates a GitHub release with auto-generated changelog notes.

## Contributing

@TODO: a couple steps

## Acknowledgments

A big thanks to the https://github.com/unrolled/secure project whose approach to
writing middleware helped us figure out our approach to creating this project.

## TODO

- [x] add support for github.com/julienschmidt/httprouter
- [x] add examples for using with net/http and httprouter
- [ ] makefile with gvt for deps now that we're depending on httprouter
- [ ] add helper for compatibility with negroni (example: https://github.com/unrolled/secure/blob/v1/secure.go#L110-L111)
