# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-15

### Added

- Verify client SigV4 Authorization-header and presigned URL requests against
  the CDN hostname, then re-sign them for Backblaze B2.
- Support S3 REST `GET`, `HEAD`, `PUT`, `POST`, `DELETE`, and `OPTIONS`
  requests, including multipart REST operations.
- Add `ALLOW_UNSIGNED_READ`, disabled by default, for explicit anonymous
  `GET`/`HEAD` access.
- Add `SIGNATURE_MAX_SKEW_SECONDS` for Authorization-header clock skew.
- Add bilingual English and Simplified Chinese setup documentation and
  migration guidance.
- Add Worker-runtime Vitest coverage with independent AWS SDK and standard
  SigV4 fixtures.

### Changed

- Split the Worker into entrypoint, routing, and shared SigV4 modules.
- Stream request bodies directly to one upstream request and re-sign with the
  configured B2 credentials, timestamp, upstream host, checksum headers, and
  payload hash.
- Preserve the existing fixed-bucket, `$path`, `$host`, `ALLOWED_HEADERS`,
  `ALLOW_LIST_BUCKET`, and `RCLONE_DOWNLOAD` behavior.
- Preserve HEAD-to-GET compatibility, Range retries, manual redirects, and B2
  response headers.
- Remove the `aws4fetch` runtime dependency.
- Update CI to run tests, formatting checks, and a Wrangler dry run.

### Migration

- Deployments that depended on anonymous downloads must set
  `ALLOW_UNSIGNED_READ="true"`.
- Generate presigned URLs directly from the CDN URL. Do not sign a B2 URL and
  replace its hostname.
- HTML POST policy uploads, streaming chunk/trailer signatures, SigV4a, and
  session tokens are not supported in this release.

## [1.2.0] - 2024-10-09

### Added

- `RCLONE_DOWNLOAD` environment variable allows use with rclone's `--b2-download-url` option, stripping the `file\` prefix from the incoming path; fixes [#16](https://github.com/backblaze-b2-samples/cloudflare-b2/issues/16)

## [1.1.1] - 2024-10-08

### Added

- README now includes instruction to run `npm install`, fixing [#17](https://github.com/backblaze-b2-samples/cloudflare-b2/issues/17)

### Fixed

- Return correct response for ranged HEAD requests ([@jamesgreenley](https://github.com/jamesgreenley))

### Changed

- Bumped direct dependencies to current versions
- Bumped `path-to-regexp` version in response to dependabot alert

## [1.1.0] - 2024-07-20

### Fixed

- Send `HEAD` requests as `GET`s, fixing #18.

### Changed

- Update `aws4fetch` version to 1.0.19 and remove now-redundant region parsing code.
- Fix/suppress IntelliJ warnings.
- Make git ignore local worker files and directories.

## [1.0.0] - 2024-07-20

Declaring current version as 1.0.0.
