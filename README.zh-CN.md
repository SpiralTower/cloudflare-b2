# Cloudflare Worker for Backblaze B2

[English](README.md) | 简体中文

使用 [Cloudflare Worker](https://developers.cloudflare.com/workers/) 作为私有
[Backblaze B2](https://www.backblaze.com/b2/cloud-storage.html) S3 端点。客户端
使用 B2 application key 对 CDN 域名上的请求签名；Worker 验证客户端签名，将请求
映射到 B2 S3 域名，再用同一组凭据重签并转发给 B2。

支持 S3 REST `GET`、`HEAD`、`PUT`、`POST`、`DELETE` 和 `OPTIONS`，包括 DNS
风格、路径风格、固定长度上传、multipart REST 和预签名 URL。不支持 HTML POST
policy 上传、AWS streaming chunk/trailer 签名、SigV4a 和 session token。

## 要求

- Node.js 22 或更高版本
- 私有 B2 桶及可访问该桶的 application key
- 指向 Worker 的 Cloudflare Custom Domain 或 Route

```sh
git clone git@github.com:backblaze-b2-samples/cloudflare-b2.git
cd cloudflare-b2
npm install
```

## 配置

在 `wrangler.toml` 中设置 `B2_APPLICATION_KEY_ID`、`B2_ENDPOINT`、
`BUCKET_NAME` 等变量，并将 `B2_APPLICATION_KEY` 保存为 Worker secret：

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

| 变量                         | 默认值      | 说明                                                                                                             |
| ---------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------- |
| `B2_APPLICATION_KEY_ID`      | 必填        | 用于验签和重签的 B2 application key ID。                                                                         |
| `B2_APPLICATION_KEY`         | 必填 secret | B2 application key。                                                                                             |
| `B2_ENDPOINT`                | 必填        | 标准 B2 S3 endpoint，例如 `s3.us-west-001.backblazeb2.com`。Worker 从中推导 region，非标准 endpoint 将失败关闭。 |
| `BUCKET_NAME`                | 必填        | 固定桶名、`$path` 或 `$host`。                                                                                   |
| `ALLOW_LIST_BUCKET`          | `false`     | 允许认证后的桶根目录列表请求。                                                                                   |
| `ALLOW_UNSIGNED_READ`        | `false`     | 允许完全未签名的 `GET`/`HEAD`（包括 Range）；匿名写始终拒绝。                                                    |
| `SIGNATURE_MAX_SKEW_SECONDS` | `900`       | Authorization 头签名可接受的时钟偏差，范围 `0..86400`。无效值回退到 `900`。预签名 URL 使用严格签发及过期检查。   |
| `RCLONE_DOWNLOAD`            | `false`     | 转发前移除 rclone 的 `file/` 前缀，但仍按客户端实际 CDN URL 验签。                                               |
| `ALLOWED_HEADERS`            | 未设置      | 设置后仅转发列出的客户端请求头。`Content-Length` 单独处理以保留固定长度上传，名称不区分大小写。                  |

`ALLOW_LIST_BUCKET` 和 `ALLOW_UNSIGNED_READ` 相互独立。匿名列出桶必须同时设置
`ALLOW_UNSIGNED_READ="true"` 和 `ALLOW_LIST_BUCKET="true"`。

### 本地开发

复制 `.dev.vars.template` 为 `.dev.vars` 并填写 application key，然后运行：

```sh
npx wrangler dev
```

### 桶路由模式

- 固定桶：`BUCKET_NAME="my-bucket"`，将
  `https://cdn.example.com/path/to/object` 映射为
  `https://my-bucket.s3.us-west-001.backblazeb2.com/path/to/object`。
- `$path`：`BUCKET_NAME="$path"`，将
  `https://cdn.example.com/my-bucket/path/to/object` 映射为
  `https://s3.us-west-001.backblazeb2.com/my-bucket/path/to/object`。
- `$host`：`BUCKET_NAME="$host"`，将
  `https://my-bucket.cdn.example.com/path/to/object` 映射为
  `https://my-bucket.s3.us-west-001.backblazeb2.com/path/to/object`。

`$host` 模式需要为每个桶域名配置 Route 或 Custom Domain，不能只依赖通配路由。

## 客户端签名

客户端必须把 CDN 域名作为 S3 endpoint，并直接对发送给 Worker 的 CDN URL、
method、query 和 SignedHeaders 签名：

```sh
export AWS_ACCESS_KEY_ID='<your b2 application key id>'
export AWS_SECRET_ACCESS_KEY='<your b2 application key>'
export AWS_REGION='us-west-001'

aws s3 cp --endpoint-url https://cdn.example.com local.txt \
  s3://my-bucket/path/to/local.txt
```

Worker 验证 CDN Host 上的 Authorization 头，然后移除旧签名，使用当前时间和 B2
Host 重新签名。Authorization 头请求必须提供 `x-amz-content-sha256`，值为
`UNSIGNED-PAYLOAD` 或 64 位 SHA-256 十六进制摘要，B2 会用该值校验实际 body。

### 预签名 URL

预签名 URL 必须直接针对 CDN URL 生成，不能先生成 B2 URL 再替换域名。Host 是
签名的一部分，替换域名会导致验签失败。

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

预签名有效期必须为 `1..604800` 秒。已过期、未来签发、超过 7 天、参数重复或使用
security token 的 URL 会被拒绝。Worker 会移除认证 query，并使用
`UNSIGNED-PAYLOAD` 和 Authorization 头重签。

## 请求行为

- 验签严格使用客户端 CDN Host 和 URI。转发前移除认证 query，普通 query 的
  顺序和重复值保持不变。
- `OPTIONS` 绕过验签并转发给 B2，由桶的 CORS 配置决定响应。
- `multipart/form-data` POST policy 返回 `NotImplemented`；其他 S3 REST POST
  在验签后转发。
- 带 `Content-Length` 的请求会先完整读取并校验，再以相同长度转发到上游。body
  短于或长于声明长度时返回 `IncompleteBody`；格式非法时返回 `InvalidRequest`。
- 不带 `Content-Length` 的请求 body 仍直接从客户端流式转发，不读取、不缓存、不
  tee。AWS streaming SigV4 请求仍不支持。
- 客户端签名过的 `x-amz-checksum-*`、`content-md5` 和完整性相关请求头会透传
  并由 Worker 重签。
- `HEAD` 按客户端 `HEAD` 验签，以 `GET` 重签上游，响应不返回 body。
- Range 响应缺少 `Content-Range` 时最多重试 3 次；3xx 响应不跟随。
- B2 响应原样返回，Worker 不添加缓存头。

## 请求头白名单

默认会转发客户端请求头，但始终过滤认证/分帧头、逐跳头、Cloudflare 注入头及
`cf-*` 前缀、`accept-encoding` 和条件请求头（`if-match`、
`if-modified-since`、`if-none-match`、`if-range`、`if-unmodified-since`）。
Worker 还会在重签前移除旧 `Authorization`、`Host` 和 `x-amz-date`。

`Content-Length` 会根据已验证的请求 body 长度恢复，并在不纳入上游签名的情况下
转发；无需加入 `ALLOWED_HEADERS`。

如需进一步限制转发头，可设置：

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

白名单需要包含客户端签名且上游所需的全部请求头，否则可能改变 S3 请求行为或导致
验签失败。请求头名称不区分大小写。

## Multipart 上传

S3 multipart REST（CreateMultipartUpload、UploadPart、
CompleteMultipartUpload、AbortMultipartUpload、ListParts 等）通过普通签名
流程支持。HTML POST policy 上传不支持。

Forgejo 的 MinIO storage 等客户端应使用固定长度上传。Forgejo 必须使用 HTTPS
S3 endpoint（`MINIO_USE_SSL=true`）；其 HTTP endpoint 模式会使用 AWS streaming
SigV4，本 Worker 会明确拒绝。

## Rclone 下载

可将 Worker 用作 rclone 的 `--b2-download-url`：

```toml
RCLONE_DOWNLOAD = "true"
```

Rclone 会请求类似
`https://cdn.example.com/file/my-bucket/path/to/file.txt` 的友好 URL。
Worker 转发时移除 `file/<bucket>/` 前缀，但验签仍使用 Rclone 实际发送的 CDN URL。

## 桶缓存

Worker 会为每个 B2 请求签名。可在 B2 Bucket Info 中配置缓存策略，例如：

```json
{ "Cache-Control": "public, max-age=86400" }
```

Worker 不修改 B2 响应头或缓存规则。若对象需要保持私有，请勿为共享缓存配置可缓存
该响应的规则。

## 从 1.2 升级

1.3 版本改为验证客户端签名。此前依赖匿名读取的部署必须显式设置
`ALLOW_UNSIGNED_READ="true"`。其他部署应改为直接对 CDN 域名签名，并确保
`ALLOWED_HEADERS` 包含客户端所需请求头。

Worker 默认导出仍为 `fetch(request, env, ctx)`。

## 开发与测试

```sh
npm test
npx prettier --check '**/*.{js,css,json,md}'
npx wrangler deploy --dry-run
```

测试不需要真实 B2 桶，使用固定 AWS SDK 和标准 SigV4 fixture 在 Worker 运行时执行。

## 部署

```sh
npx wrangler deploy
```

GitHub workflow 会在推送到 `main` 时运行测试、格式检查和 Wrangler dry-run。

## 致谢

基于 [worker-signed-s3-template](https://github.com/obezuk/worker-signed-s3-template)
改编。
