import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { network } from './network.js'
import worker from '../index.js'
import { signRequest } from '../src/sigv4.js'

const credentials = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
}

const baseEnv = {
  BUCKET_NAME: 'my-bucket',
  B2_ENDPOINT: 's3.us-west-001.backblazeb2.com',
  B2_APPLICATION_KEY_ID: credentials.accessKeyId,
  B2_APPLICATION_KEY: credentials.secretAccessKey,
}

async function signedRequest(url, options = {}) {
  const body = options.body
  const headers = new Headers(options.headers)
  if (body !== undefined) headers.set('content-type', 'text/plain')
  const signed = await signRequest({
    method: options.method || 'GET',
    url: options.signUrl || url,
    headers,
    payloadHash: 'UNSIGNED-PAYLOAD',
    credentials,
    region: 'us-west-001',
    now: new Date(),
  })
  for (const name of signed.signedHeaders) {
    if (name === 'host') continue
    const value = signed.headers.get(name)
    if (value !== null) headers.set(name, value)
  }
  headers.set('authorization', signed.authorization)
  return new Request(url, {
    method: options.method || 'GET',
    headers,
    body,
  })
}

async function presignedRequest(url, method = 'GET') {
  const { S3Client, GetObjectCommand } = await import('@aws-sdk/client-s3')
  const { getSignedUrl } = await import('@aws-sdk/s3-request-presigner')
  const client = new S3Client({
    region: 'us-west-001',
    endpoint: 'https://cdn.example.com',
    forcePathStyle: false,
    credentials,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
  })
  const command = new GetObjectCommand({
    Bucket: 'my-bucket',
    Key: url.pathname.slice(1),
    VersionId: url.searchParams.get('versionId') || undefined,
  })
  const signedUrl = await getSignedUrl(client, command, {
    signingDate: new Date(),
    expiresIn: 3600,
  })
  return new Request(signedUrl, { method })
}

describe('Worker proxy', () => {
  it('rejects unsupported CONNECT and TRACE methods', async () => {
    const response = await worker.fetch(
      new Request('https://cdn.example.com/test.txt', { method: 'TRACE' }),
      baseEnv,
    )
    expect(response.status).toBe(405)
    expect(await response.text()).toContain('<Code>MethodNotAllowed</Code>')
  })

  it('denies unsigned reads by default without contacting upstream', async () => {
    network.use(
      http.get(
        '*',
        () => {
          throw new Error('upstream should not be called')
        },
        { once: true },
      ),
    )

    const response = await worker.fetch(
      new Request('https://cdn.example.com/test.txt'),
      baseEnv,
    )

    expect(response.status).toBe(403)
    expect(await response.text()).toContain('<Code>AccessDenied</Code>')
  })

  it('allows unsigned GET and HEAD only when explicitly enabled', async () => {
    const env = { ...baseEnv, ALLOW_UNSIGNED_READ: 'true' }
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/test.txt',
        ({ request }) =>
          HttpResponse.text(request.method === 'HEAD' ? '' : 'object'),
      ),
    )

    const getResponse = await worker.fetch(
      new Request('https://cdn.example.com/test.txt'),
      env,
    )
    expect(await getResponse.text()).toBe('object')

    const headResponse = await worker.fetch(
      new Request('https://cdn.example.com/test.txt', { method: 'HEAD' }),
      env,
    )
    expect(headResponse.status).toBe(200)
    expect(await headResponse.text()).toBe('')
  })

  it('treats a malformed signature as an authentication failure', async () => {
    const env = { ...baseEnv, ALLOW_UNSIGNED_READ: 'true' }
    network.use(
      http.get(
        '*',
        () => {
          throw new Error('upstream should not be called')
        },
        { once: true },
      ),
    )
    const response = await worker.fetch(
      new Request(
        'https://cdn.example.com/test.txt?X-Amz-Signature=not-a-signature',
      ),
      env,
    )

    expect(response.status).toBe(400)
    expect(await response.text()).toContain(
      '<Code>AuthorizationHeaderMalformed</Code>',
    )
  })

  it('handles OPTIONS without authentication and preserves CORS headers', async () => {
    network.use(
      http.options(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/test.txt',
        async ({ request }) => {
          expect(request.headers.get('origin')).toBe('https://app.example.com')
          expect(request.headers.get('access-control-request-method')).toBe(
            'PUT',
          )
          return new HttpResponse(null, {
            status: 204,
            headers: {
              'access-control-allow-origin': 'https://app.example.com',
              'access-control-allow-methods': 'PUT',
            },
          })
        },
        { once: true },
      ),
    )

    const response = await worker.fetch(
      new Request('https://cdn.example.com/test.txt', {
        method: 'OPTIONS',
        headers: {
          origin: 'https://app.example.com',
          'access-control-request-method': 'PUT',
        },
      }),
      baseEnv,
    )

    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe(
      'https://app.example.com',
    )
  })

  it('denies bucket listing by default', async () => {
    const request = await signedRequest('https://cdn.example.com/')
    const response = await worker.fetch(request, baseEnv)

    expect(response.status).toBe(403)
    expect(await response.text()).toContain('<Code>AccessDenied</Code>')
  })

  it('allows bucket listing when configured', async () => {
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/',
        () => HttpResponse.xml('<ListBucketResult/>'),
        { once: true },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/')
    const response = await worker.fetch(request, {
      ...baseEnv,
      ALLOW_LIST_BUCKET: 'true',
    })

    expect(response.status).toBe(200)
    expect(await response.text()).toBe('<ListBucketResult/>')
  })

  it('streams PUT bodies through one upstream fetch', async () => {
    let upstreamCalls = 0
    let receivedBody
    network.use(
      http.put(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        async ({ request }) => {
          upstreamCalls += 1
          receivedBody = await request.text()
          expect(request.headers.has('authorization')).toBe(true)
          return new HttpResponse(null, { status: 200 })
        },
        { once: true },
      ),
    )

    const request = await signedRequest('https://cdn.example.com/object.bin', {
      method: 'PUT',
      body: 'request body',
    })
    const response = await worker.fetch(request, baseEnv)

    expect(response.status).toBe(200)
    expect(upstreamCalls).toBe(1)
    expect(receivedBody).toBe('request body')
  }, 10000)

  it('rejects HTML POST policy uploads without authentication', async () => {
    const response = await worker.fetch(
      new Request('https://cdn.example.com/', {
        method: 'POST',
        headers: { 'content-type': 'multipart/form-data; boundary=x' },
        body: '--x--',
      }),
      baseEnv,
    )

    expect(response.status).toBe(501)
    expect(await response.text()).toContain('<Code>NotImplemented</Code>')
  })

  it('forwards checksums and integrity headers to the upstream signature', async () => {
    let checksum
    let contentMd5
    network.use(
      http.put(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        ({ request }) => {
          checksum = request.headers.get('x-amz-checksum-sha256')
          contentMd5 = request.headers.get('content-md5')
          const authorization = request.headers.get('authorization')
          expect(authorization).toContain('x-amz-checksum-sha256')
          expect(authorization).toContain('content-md5')
          return new HttpResponse(null, { status: 200 })
        },
        { once: true },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin', {
      method: 'PUT',
      body: 'body',
      headers: {
        'x-amz-checksum-sha256': 'checksum',
        'content-md5': 'md5',
      },
    })

    expect((await worker.fetch(request, baseEnv)).status).toBe(200)
    expect(checksum).toBe('checksum')
    expect(contentMd5).toBe('md5')
  })

  it('signs a HEAD client request and uses GET upstream', async () => {
    let upstreamMethod
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        ({ request }) => {
          upstreamMethod = request.method
          return HttpResponse.text('body should be dropped', {
            headers: { 'content-length': '21', 'x-upstream': 'kept' },
          })
        },
        { once: true },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin', {
      method: 'HEAD',
    })
    const response = await worker.fetch(request, baseEnv)

    expect(upstreamMethod).toBe('GET')
    expect(response.status).toBe(200)
    expect(await response.text()).toBe('')
    expect(response.headers.get('x-upstream')).toBe('kept')
  })

  it('retries a range response without Content-Range', async () => {
    let calls = 0
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        () => {
          calls += 1
          return calls < 2
            ? HttpResponse.text('full object')
            : HttpResponse.text('partial', {
                headers: { 'content-range': 'bytes 0-6/20' },
              })
        },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin', {
      headers: { range: 'bytes=0-6' },
    })
    const response = await worker.fetch(request, baseEnv)

    expect(calls).toBe(2)
    expect(await response.text()).toBe('partial')
    expect(response.headers.get('content-range')).toBe('bytes 0-6/20')
  })

  it('stops range retries after three attempts and returns the final response', async () => {
    let calls = 0
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        () => {
          calls += 1
          return HttpResponse.text(`full ${calls}`)
        },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin', {
      headers: { range: 'bytes=0-6' },
    })
    const response = await worker.fetch(request, baseEnv)

    expect(calls).toBe(3)
    expect(await response.text()).toBe('full 3')
  })

  it('does not retry a non-successful range response', async () => {
    let calls = 0
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        () => {
          calls += 1
          return new HttpResponse(null, { status: 416 })
        },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin', {
      headers: { range: 'bytes=100-200' },
    })
    const response = await worker.fetch(request, baseEnv)

    expect(response.status).toBe(416)
    expect(calls).toBe(1)
  })

  it('returns redirects without following them', async () => {
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        () =>
          new HttpResponse(null, {
            status: 302,
            headers: { location: 'https://example.com/elsewhere' },
          }),
        { once: true },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin')
    const response = await worker.fetch(request, baseEnv)

    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toBe(
      'https://example.com/elsewhere',
    )
  })

  it('forwards normal query parameters in their original order', async () => {
    let receivedUrl
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        ({ request }) => {
          receivedUrl = request.url
          return new HttpResponse(null, { status: 200 })
        },
        { once: true },
      ),
    )
    const request = await signedRequest(
      'https://cdn.example.com/object.bin?b=2&a=1&a=0',
    )
    const response = await worker.fetch(request, baseEnv)

    expect(response.status).toBe(200)
    expect(receivedUrl).toContain('?b=2&a=1&a=0')
  })

  it('handles POST and DELETE S3 REST requests', async () => {
    for (const method of ['POST', 'DELETE']) {
      network.use(
        http[method.toLowerCase()](
          'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
          () => new HttpResponse(null, { status: 204 }),
          { once: true },
        ),
      )
      const request = await signedRequest(
        'https://cdn.example.com/object.bin',
        { method, body: method === 'POST' ? 'job' : undefined },
      )
      const response = await worker.fetch(request, baseEnv)
      expect(response.status).toBe(204)
    }
  })

  it('does not modify successful response or cache headers', async () => {
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        () =>
          HttpResponse.text('value', {
            headers: {
              'cache-control': 'public, max-age=60',
              etag: '"etag"',
              'content-type': 'text/custom',
            },
          }),
        { once: true },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin')
    const response = await worker.fetch(request, baseEnv)

    expect(response.headers.get('cache-control')).toBe('public, max-age=60')
    expect(response.headers.get('etag')).toBe('"etag"')
    expect(response.headers.get('content-type')).toBe('text/custom')
  })

  it('returns upstream errors unchanged', async () => {
    const errorXml =
      '<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>upstream</Message></Error>'
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/missing.txt',
        () =>
          new HttpResponse(errorXml, {
            status: 404,
            statusText: 'Object Missing',
            headers: {
              'content-type': 'application/xml',
              'x-b2-error': 'untouched',
            },
          }),
        { once: true },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/missing.txt')
    const response = await worker.fetch(request, baseEnv)

    expect(response.status).toBe(404)
    expect(response.statusText).toBe('Object Missing')
    expect(await response.text()).toBe(errorXml)
    expect(response.headers.get('x-b2-error')).toBe('untouched')
  })

  it('accepts a client presigned URL and removes its auth query', async () => {
    let receivedUrl
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/object.bin',
        ({ request }) => {
          receivedUrl = request.url
          expect(request.headers.has('authorization')).toBe(true)
          return HttpResponse.text('presigned object')
        },
        { once: true },
      ),
    )
    const request = await presignedRequest(
      new URL('https://cdn.example.com/object.bin?versionId=2'),
    )
    const response = await worker.fetch(request, baseEnv)

    expect(response.status).toBe(200)
    expect(await response.text()).toBe('presigned object')
    expect(receivedUrl).not.toContain('X-Amz-Signature')
    expect(receivedUrl).toContain('versionId=2')
  })

  it('fails closed for a non-standard B2 endpoint', async () => {
    network.use(
      http.get(
        '*',
        () => {
          throw new Error('upstream should not be called')
        },
        { once: true },
      ),
    )
    const request = await signedRequest('https://cdn.example.com/object.bin')
    const response = await worker.fetch(request, {
      ...baseEnv,
      B2_ENDPOINT: 'example.com',
    })

    expect(response.status).toBe(400)
    expect(await response.text()).toContain('<Code>InvalidRequest</Code>')
  })

  it('allows a rclone request and verifies the original CDN URL', async () => {
    const key = `rclone-${crypto.randomUUID()}.bin`
    network.use(
      http.get(
        'https://my-bucket.s3.us-west-001.backblazeb2.com/rclone-*',
        async ({ request }) => {
          expect(request.headers.has('range')).toBe(true)
          return HttpResponse.text('rclo', {
            status: 206,
            headers: { 'content-range': 'bytes 0-3/13' },
          })
        },
        { once: true },
      ),
    )
    const headers = new Headers({ range: 'bytes=0-3' })
    const signed = await signRequest({
      method: 'GET',
      url: `https://cdn.example.com/file/my-bucket/${key}`,
      headers,
      credentials,
      region: 'us-west-001',
      now: new Date(),
    })
    headers.set('x-amz-date', signed.amzDate)
    headers.set(
      'x-amz-content-sha256',
      signed.headers.get('x-amz-content-sha256'),
    )
    headers.set('authorization', signed.authorization)
    const rcloneRequest = new Request(
      `https://cdn.example.com/file/my-bucket/${key}`,
      { headers },
    )
    const response = await worker.fetch(rcloneRequest, {
      ...baseEnv,
      RCLONE_DOWNLOAD: 'true',
    })
    expect(response.status).toBe(206)
    expect(await response.text()).toBe('rclo')
  })
})
