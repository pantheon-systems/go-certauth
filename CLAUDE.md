# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-certauth is a TLS certificate-based authentication middleware library for Go. It enables mutual TLS (mTLS) authentication by validating client certificates and authorizing requests based on certificate OU (Organizational Unit) and CN (Common Name). It works with both `net/http` and `github.com/julienschmidt/httprouter`.

## Build and Test Commands

```bash
make all       # Run tests and build
make test      # Run tests (root package + pantheon subpackage)
make build     # Compile root package + pantheon subpackage
```

Run a single test:

```bash
go test github.com/pantheon-systems/go-certauth -run TestName
go test github.com/pantheon-systems/go-certauth/pantheon -run TestName
```

There is no linter configured beyond CodeQL security scanning in CI.

## Architecture

### Authorization Model

Checkers are organized in groups. Auth passes when **any** group passes; a group passes when **all** checkers in it pass:

```go
New(WithCheckers(A), WithCheckers(B, C))  // passes on: A || (B && C)
```

Authorization results are propagated via request context keys (`HasAuthorizedOU`, `HasAuthorizedCN`).

### Packages

- **`certauth`** (root) — Core middleware. `Auth` struct wraps authorization checkers and exposes `Handler()` (net/http) and `RouterHandler()` (httprouter) middleware wrappers. Uses functional options pattern (`New()` + `WithCheckers()`, `WithHeaders()`, `WithErrorHandler()`).
- **`certutils`** — TLS configuration helpers. Provides `NewTLSConfig()` with Mozilla-recommended cipher/protocol levels (`TLSConfigDefault`, `TLSConfigIntermediate`, `TLSConfigModern`) and `NewTLSServer()` for mTLS-ready HTTP servers. Has build-tag-based Go version compatibility (`certutils.go` vs `certutils_pre_go18.go`).
- **`pantheon`** — Pantheon-specific site authorization. `PantheonSiteAuthChecker` parses site UUID and environment from the certificate CN (format: `env.site-uuid.domain`) and validates against httprouter's `site` URI parameter.

### Key Interfaces

`AuthorizationChecker` (in `authorization.go`) is the extension point. Implement `CheckAuthorization(ou, cn)` and `CheckAuthorizationWithParams(ou, cn, params)` to add custom authorization logic.

### Legacy vs Current API

`NewAuth(Options{})` is deprecated. Use `New(...AuthOption)` with functional options.

## CI

- **GitHub Actions** — Runs `make test` and `make build` on push to `main` and all PRs.
- **GitHub Actions** — CodeQL security scanning on push to `main` and PRs.
- **GitHub Actions** — GoReleaser creates a GitHub release when a semver tag (`v*.*.*`) is pushed. The workflow runs tests before releasing.

## Releasing

Push a signed semver tag to trigger a release:

```bash
git tag -s v0.1.0
git push origin v0.1.0
```

GoReleaser skips binary builds (this is a library) and generates changelog notes automatically.
