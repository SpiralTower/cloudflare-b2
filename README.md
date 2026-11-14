# Cloudflare Worker for Backblaze B2

English | [简体中文](README.zh-CN.md)

Use a [Cloudflare Worker](https://developers.cloudflare.com/workers/) as a
private [Backblaze B2](https://www.backblaze.com/b2/cloud-storage.html) S3
endpoint. Clients sign requests for the CDN hostname with a Backblaze
application key. The Worker verifies that signature, maps the request to the
B2 S3 hostname, signs it again with the same key, and forwards it to B2.

The Worker supports S3 REST requests for `GET`, `HEAD`, `PUT`, `POST`,
`DELETE`, and `OPTIONS`, including path-style, host-style, multipart REST,
and presigned URL requests. HTML POST policy form uploads, AWS streaming
chunk/trailer signing, SigV4a, and session tokens are not supported.

## Requirements

- Node.js 22 or newer
- A private B2 bucket and an application key that can access it
- A Cloudflare Custom Domain or Route that points your CDN hostname to the
  Worker

```sh
git clone git@github.com:backblaze-b2-samples/cloudflare-b2.git
cd cloudflare-b2
npm install
```

## Configuration

Configure `wrangler.toml` and store `B2_APPLICATION_KEY` as a Worker secret:

```toml
[vars]
B2_APPLICATION_KEY_ID = "<your b2 application key id>"
B2_ENDPOINT = "s3.us-west-001.backblazeb2.com"
BUCKET_NAME = "<bucket name, $path, or $host>"
ALLOW_LIST_BUCKET = "false"
ALLOW_UNSIGNED_READ = "false"
SIGNATURE_MAX_SKEW_SECONDS = "900"
RCLONE_DOWNLOAD = "false"
```

```sh
printf '%s' '<your b2 application key>' | npx wrangler secret put B2_APPLICATION_KEY
```

| Variable                     | Default         | Purpose                                                                                                                                                              |
| ---------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `B2_APPLICATION_KEY_ID`      | required        | B2 application key ID used to verify and re-sign requests.                                                                                                           |
| `B2_APPLICATION_KEY`         | required secret | B2 application key.                                                                                                                                                  |
| `B2_ENDPOINT`                | required        | Standard B2 S3 endpoint, such as `s3.us-west-001.backblazeb2.com`. The region is derived from it. Non-standard endpoints fail closed.                                |
| `BUCKET_NAME`                | required        | A fixed bucket name, `$path`, or `$host`.                                                                                                                            |
| `ALLOW_LIST_BUCKET`          | `false`         | Allows bucket listing (`GET` or `HEAD` at the bucket root) after authentication.                                                                                     |
| `ALLOW_UNSIGNED_READ`        | `false`         | Allows fully unsigned `GET` and `HEAD`, including `Range`. Anonymous writes are always denied.                                                                       |
| `SIGNATURE_MAX_SKEW_SECONDS` | `900`           | Allowed clock skew for Authorization-header signatures, from `0` to `86400`. Invalid values fall back to `900`. Presigned URLs use stricter issue and expiry checks. |
| `RCLONE_DOWNLOAD`            | `false`         | Strips the rclone `file/` prefix before forwarding, while verifying the signature against the original CDN URL.                                                      |
| `ALLOWED_HEADERS`            | unset           | If set, only the listed client headers are forwarded upstream. Header names are case-insensitive.                                                                    |

`ALLOW_LIST_BUCKET` and `ALLOW_UNSIGNED_READ` are independent. An unsigned
bucket listing still requires both `ALLOW_UNSIGNED_READ=true` and
`ALLOW_LIST_BUCKET=true`.

### Local development

Copy `.dev.vars.template` to `.dev.vars` and fill in the application key.
Wrangler uses `.dev.vars` for local secrets. Then run:

```sh
npx wrangler dev
```

### Bucket modes

- Fixed bucket: `BUCKET_NAME="my-bucket"` maps
  `https://cdn.example.com/path/to/object` to
  `https://my-bucket.s3.us-west-001.backblazeb2.com/path/to/object`.
- `$path`: `BUCKET_NAME="$path"` maps
  `https://cdn.example.com/my-bucket/path/to/object` to
  `https://s3.us-west-001.backblazeb2.com/my-bucket/path/to/object`.
- `$host`: `BUCKET_NAME="$host"` maps
  `https://my-bucket.cdn.example.com/path/to/object` to
  `https://my-bucket.s3.us-west-001.backblazeb2.com/path/to/object`.

The `$host` mode needs a Route or Custom Domain for each bucket hostname.
Wildcard routing alone is not sufficient.

## Client signing

Use the CDN hostname as the S3 endpoint. Sign the exact CDN URL, method,
query, and signed headers that you send to the Worker:

```sh
export AWS_ACCESS_KEY_ID='<your b2 application key id>'
export AWS_SECRET_ACCESS_KEY='<your b2 application key>'
export AWS_REGION='us-west-001'

aws s3 cp --endpoint-url https://cdn.example.com local.txt \
  s3://my-bucket/path/to/local.txt
```

The Worker checks the Authorization header against the CDN request, then
removes it and creates a new signature for the B2 hostname with a current
timestamp. `Authorization`-header requests must include
`x-amz-content-sha256` with either `UNSIGNED-PAYLOAD` or a 64-character
SHA-256 hex digest. B2 validates the body against that value.

Install the AWS CLI, SDK, or another S3 client with SigV4 support. The CDN
hostname is a custom endpoint, so use path-style requests unless your CDN
routing supports bucket subdomains. `$path` mode uses path-style routing.

### Presigned URLs

Presigned URLs must be generated directly against the CDN URL. Do not sign a
B2 URL and then replace its hostname with the CDN hostname: the host is part
of the signature and verification will fail.

```python
import boto3

client = boto3.client(
    "s3",
    endpoint_url="https://cdn.example.com",
    region_name="us-west-001",
    aws_access_key_id="<your b2 application key id>",
    aws_secret_access_key="<your b2 application key>",
    config=boto3.session.Config(s3={"addressing_style": "path"}),
)
url = client.generate_presigned_url(
    "get_object",
    Params={"Bucket": "my-bucket", "Key": "path/to/object"},
    ExpiresIn=3600,
)
```

Presigned URLs are accepted for `1` through `604800` seconds. Expired,
future-issued, over-seven-day, duplicate, and security-token URLs are
rejected. The Worker re-signs presigned requests with
`UNSIGNED-PAYLOAD` and an Authorization header before forwarding.

## Request behavior

- The exact CDN Host and URI are verified. Authentication query parameters
  are removed from the forwarded URL, while normal query parameters retain
  their original order and duplicates.
- `OPTIONS` bypasses authentication and is forwarded to B2 so the bucket's
  CORS policy controls the response.
- `multipart/form-data` POST policy uploads return `NotImplemented`. Other S3
  REST `POST` operations are forwarded after authentication.
- Request bodies are streamed from the client without buffering or tee-ing.
- `x-amz-checksum-*`, `content-md5`, and integrity headers that were signed by
  the client are retained and signed again for B2.
- `HEAD` is verified as `HEAD` on the CDN URL, re-signed as `GET` upstream,
  and returned without a body.
- A `Range` response missing `Content-Range` is retried up to three times.
  Redirects are not followed.
- B2 responses are returned unchanged; the Worker does not add cache headers.

## Allowed headers

By default, client headers are forwarded except authentication/framing
headers, hop-by-hop headers, Cloudflare-injected headers, the `cf-*` prefix,
`accept-encoding`, and conditional headers (`if-match`,
`if-modified-since`, `if-none-match`, `if-range`, `if-unmodified-since`).
The Worker also removes the client's old `Authorization`, `Host`, and
`x-amz-date` before signing the B2 request.

To restrict forwarding further, set a list:

```toml
ALLOWED_HEADERS = [
  "content-type",
  "range",
  "x-amz-checksum-sha256",
  "x-amz-server-side-encryption-customer-algorithm",
  "x-amz-server-side-encryption-customer-key",
  "x-amz-server-side-encryption-customer-key-md5",
]
```

Use the full list of headers that your clients sign and need upstream. A
missing header can change the behavior of S3 requests or break signature
verification. Header names are case-insensitive.

## Multipart uploads

S3 multipart REST operations, including `CreateMultipartUpload`,
`UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, and
`ListParts`, work through the normal signed request flow. HTML POST policy
uploads do not work.

## Rclone downloads

Rclone can use the Worker as a
[`--b2-download-url`](https://rclone.org/b2/#b2-download-url):

```toml
RCLONE_DOWNLOAD = "true"
```

Rclone requests friendly URLs such as
`https://cdn.example.com/file/my-bucket/path/to/file.txt`. The Worker
removes the `file/<bucket>/` prefix for the upstream path but verifies the
signature against the exact CDN URL that Rclone sent.

## Bucket caching

The Worker signs every B2 request. Configure a cache-control directive in B2
Bucket Info so Cloudflare can cache objects according to your policy:

```json
{ "Cache-Control": "public, max-age=86400" }
```

The Worker does not modify B2 response headers or cache rules. Cloudflare
may also cache private responses only when your cache rules allow them; do
not configure a shared cache for responses that must remain private.

## Migration from 1.2

Version 1.3 verifies client signatures instead of only signing upstream
requests. Deployments that relied on anonymous reads must explicitly set
`ALLOW_UNSIGNED_READ="true"`. All other deployments should sign requests
against the CDN hostname and may need to allow the headers their client
uses.

The Worker's default `fetch(request, env, ctx)` export is unchanged.

## Development and tests

```sh
npm test
npx prettier --check '**/*.{js,css,json,md}'
npx wrangler deploy --dry-run
```

No real B2 bucket is needed for the test suite. The tests run in the Worker
runtime with fixed AWS SDK and standard SigV4 fixtures.

## Deployment

```sh
npx wrangler deploy
```

The GitHub workflow runs tests, formatting checks, and a Wrangler dry run on
pushes to `main`.

## Acknowledgements

Adapted from
[worker-signed-s3-template](https://github.com/obezuk/worker-signed-s3-template).
