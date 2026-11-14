import { describe, expect, it } from 'vitest'
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3'
import { SignatureV4 } from '@smithy/signature-v4'
import { HttpRequest } from '@smithy/protocol-http'
import { Sha256 } from '@aws-crypto/sha256-js'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import {
  canonicalizeQuery,
  parseRawQuery,
  verifyRequest,
} from '../src/sigv4.js'

const credentials = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
}

async function presignGet(path, extra = {}) {
  const client = new S3Client({
    region: 'us-east-1',
    endpoint: 'https://cdn.example.com',
    forcePathStyle: true,
    credentials,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
  })
  return getSignedUrl(
    client,
    new GetObjectCommand({
      Bucket: 'bucket',
      Key: path,
      ...extra,
    }),
    {
      signingDate: new Date('2026-11-15T02:00:00Z'),
      expiresIn: 3600,
    },
  )
}

async function signAuthorization({
  method = 'GET',
  path = '/bucket/test.txt',
  host = 'cdn.example.com',
  headers = {},
  query = {},
  payload = 'UNSIGNED-PAYLOAD',
  signingDate = new Date('2026-11-15T02:00:00Z'),
} = {}) {
  const signer = new SignatureV4({
    credentials,
    region: 'us-east-1',
    service: 's3',
    sha256: Sha256,
    uriEscapePath: false,
  })
  const signed = await signer.sign(
    new HttpRequest({
      protocol: 'https:',
      hostname: host,
      method,
      path,
      query,
      headers: {
        host,
        'x-amz-content-sha256': payload,
        ...headers,
      },
    }),
    {
      signingDate,
      unsignableHeaders: new Set([
        'authorization',
        'x-amz-date',
        'x-amz-content-sha256',
      ]),
      signableHeaders: new Set(Object.keys(headers)),
    },
  )
  return new Request(`https://${host}${path}`, {
    method,
    headers: signed.headers,
  })
}

function signedDateRequest() {
  return new Request('https://cdn.example.com/bucket/test.txt', {
    headers: {
      authorization:
        'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261115/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256, Signature=057e6379a2ac75fcb40205ce0d024ea7aada717b6e0d9f1f319d88aa7d396c4e',
      date: 'Sat, 15 Nov 2026 02:00:00 GMT',
      'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
    },
  })
}

function encodeQueryComponent(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  )
}

describe('SigV4 verification', () => {
  it('canonicalizes repeated keys and empty query values', () => {
    expect(canonicalizeQuery(parseRawQuery('b=2&a=1&a=0&empty=&bare'))).toBe(
      'a=0&a=1&b=2&bare=&empty=',
    )
  })

  it('verifies the AWS S3 documented SigV4 presigned GET vector', async () => {
    const request = new Request(
      'https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404',
    )

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2013-05-24T00:00:00Z'),
      }),
    ).resolves.toMatchObject({ kind: 'presigned' })
  })

  it('verifies an AWS SDK presigned request against the CDN URL', async () => {
    const request = new Request(await presignGet('folder/test.txt'))

    const result = await verifyRequest(request, credentials, {
      now: new Date('2026-11-15T02:00:00Z'),
    })

    expect(result.kind).toBe('presigned')
  })

  it.each([
    ['repeated and empty values', { a: ['1', '0'], empty: '', bare: '' }],
    [
      'encoded spaces and plus signs',
      { space: ['a b', 'a+b'], plus: ['+', '%2B'] },
    ],
  ])('verifies an AWS SDK presigned request with %s', async (_label, query) => {
    const signer = new SignatureV4({
      credentials,
      region: 'us-east-1',
      service: 's3',
      sha256: Sha256,
      uriEscapePath: false,
    })
    const signed = await signer.presign(
      new HttpRequest({
        protocol: 'https:',
        hostname: 'cdn.example.com',
        method: 'GET',
        path: '/bucket/test.txt',
        query,
        headers: {
          host: 'cdn.example.com',
          'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
        },
      }),
      {
        signingDate: new Date('2026-11-15T02:00:00Z'),
        expiresIn: 3600,
      },
    )
    const search = Object.entries(signed.query)
      .flatMap(([name, value]) =>
        (Array.isArray(value) ? value : [value]).map(
          (item) =>
            `${encodeQueryComponent(name)}=${encodeQueryComponent(item)}`,
        ),
      )
      .join('&')
    const url = `https://cdn.example.com/bucket/test.txt?${search}`

    await expect(
      verifyRequest(new Request(url), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).resolves.toMatchObject({ kind: 'presigned' })
  })

  it.each([
    {
      query: { a: ['1', '0'], empty: '', bare: '' },
      search: '?a=1&a=0&empty=&bare=',
    },
    {
      query: { space: ['a b', 'a+b'], plus: ['+', '%2B'] },
      search: '?space=a%20b&space=a%2Bb&plus=%2B&plus=%252B',
    },
  ])(
    'verifies an AWS SDK Authorization request with $search',
    async ({ query, search }) => {
      const signer = new SignatureV4({
        credentials,
        region: 'us-east-1',
        service: 's3',
        sha256: Sha256,
        uriEscapePath: false,
      })
      const signed = await signer.sign(
        new HttpRequest({
          protocol: 'https:',
          hostname: 'cdn.example.com',
          method: 'GET',
          path: '/bucket/test.txt',
          query,
          headers: {
            host: 'cdn.example.com',
            'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
          },
        }),
        {
          signingDate: new Date('2026-11-15T02:00:00Z'),
          unsignableHeaders: new Set([
            'authorization',
            'x-amz-date',
            'x-amz-content-sha256',
          ]),
          signableHeaders: new Set(),
        },
      )
      const request = new Request(
        `https://cdn.example.com/bucket/test.txt${search}`,
        { headers: signed.headers },
      )

      await expect(
        verifyRequest(request, credentials, {
          now: new Date('2026-11-15T02:00:00Z'),
        }),
      ).resolves.toMatchObject({ kind: 'authorization' })
    },
  )

  it.each([
    ['space', 'folder/a b.txt'],
    ['unicode', 'folder/文件.txt'],
    ['plus', 'folder/a+b.txt'],
    ['encoded slash', 'folder/a%2Fb.txt'],
    ['repeated slash', 'folder//test.txt'],
  ])('verifies an AWS SDK path containing %s', async (_label, path) => {
    const request = new Request(await presignGet(path))

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).resolves.toMatchObject({ kind: 'presigned' })
  })

  it('rejects a modified presigned query', async () => {
    const url = new URL(await presignGet('test.txt'))
    url.searchParams.set('versionId', 'tampered')

    await expect(
      verifyRequest(new Request(url.href), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'SignatureDoesNotMatch' })
  })

  it('rejects a modified signed header', async () => {
    const client = new S3Client({
      region: 'us-east-1',
      endpoint: 'https://cdn.example.com',
      forcePathStyle: true,
      credentials,
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
    })
    const command = new GetObjectCommand({
      Bucket: 'bucket',
      Key: 'test.txt',
      IfMatch: '"original"',
    })
    const url = new URL(
      await getSignedUrl(client, command, {
        signingDate: new Date('2026-11-15T02:00:00Z'),
        signableHeaders: new Set(['host', 'if-match']),
      }),
    )
    const request = new Request(url, {
      headers: { 'if-match': '"modified"' },
    })

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'SignatureDoesNotMatch' })
  })

  it.each([['x-amz-content-sha256', '0'.repeat(64)]])(
    'rejects a modified %s header',
    async (name) => {
      const request = await signAuthorization()
      const headers = new Headers(request.headers)
      headers.set(name, name === 'host' ? 'wrong.example.com' : '0'.repeat(64))

      await expect(
        verifyRequest(new Request(request.url, { headers }), credentials, {
          now: new Date('2026-11-15T02:00:00Z'),
        }),
      ).rejects.toMatchObject({
        code: 'SignatureDoesNotMatch',
      })
    },
  )

  it('rejects a request moved to a different Host', async () => {
    const request = await signAuthorization()

    await expect(
      verifyRequest(
        new Request('https://evil.example.com/bucket/test.txt', {
          headers: request.headers,
        }),
        credentials,
        { now: new Date('2026-11-15T02:00:00Z') },
      ),
    ).rejects.toMatchObject({ code: 'SignatureDoesNotMatch' })
  })

  it('verifies an Authorization header signature', async () => {
    const request = await signAuthorization()

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).resolves.toMatchObject({ kind: 'authorization' })
  })

  it('rejects a modified Authorization payload hash', async () => {
    const request = await signAuthorization()
    const headers = new Headers(request.headers)
    headers.set('x-amz-content-sha256', '0'.repeat(64))

    await expect(
      verifyRequest(new Request(request, { headers }), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'SignatureDoesNotMatch' })
  })

  it('rejects an incorrect secret', async () => {
    const request = await signAuthorization()

    await expect(
      verifyRequest(
        request,
        { ...credentials, secretAccessKey: `${credentials.secretAccessKey}x` },
        { now: new Date('2026-11-15T02:00:00Z') },
      ),
    ).rejects.toMatchObject({ code: 'SignatureDoesNotMatch' })
  })

  it('rejects an incorrect access key', async () => {
    const request = await signAuthorization()

    await expect(
      verifyRequest(
        request,
        { ...credentials, accessKeyId: 'WRONGACCESSKEY' },
        { now: new Date('2026-11-15T02:00:00Z') },
      ),
    ).rejects.toMatchObject({ code: 'AuthorizationHeaderMalformed' })
  })

  it('enforces the configurable Authorization clock skew', async () => {
    const request = await signAuthorization()

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:15:01Z'),
        maxSkewSeconds: '900',
      }),
    ).rejects.toMatchObject({ code: 'RequestTimeTooSkewed' })

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:15:01Z'),
        maxSkewSeconds: '901',
      }),
    ).resolves.toMatchObject({ kind: 'authorization' })
  })

  it('falls back to 900 seconds for an invalid skew', async () => {
    const request = await signAuthorization()

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:15:01Z'),
        maxSkewSeconds: 'invalid',
      }),
    ).rejects.toMatchObject({ code: 'RequestTimeTooSkewed' })
  })

  it('treats an empty skew setting as invalid', async () => {
    const request = await signAuthorization()

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:15:01Z'),
        maxSkewSeconds: '',
      }),
    ).rejects.toMatchObject({ code: 'RequestTimeTooSkewed' })
  })

  it.each([
    ['expired', '2026-11-15T03:00:01Z', 'RequestExpired'],
    ['future-dated', '2026-11-14T23:59:59Z', 'RequestTimeTooSkewed'],
    ['too long', '2026-11-15T02:00:00Z', 'InvalidRequest', 604801],
    ['zero', '2026-11-15T02:00:00Z', 'InvalidRequest', 0],
  ])(
    'rejects a %s presigned URL',
    async (_label, now, code, expires = 3600) => {
      const url = new URL(await presignGet('test.txt'))
      url.searchParams.set('X-Amz-Expires', String(expires))
      const client = new S3Client({
        region: 'us-east-1',
        endpoint: 'https://cdn.example.com',
        forcePathStyle: true,
        credentials,
        requestChecksumCalculation: 'WHEN_REQUIRED',
        responseChecksumValidation: 'WHEN_REQUIRED',
      })
      const command = new GetObjectCommand({
        Bucket: 'bucket',
        Key: 'test.txt',
      })
      const signedUrl = new URL(
        await getSignedUrl(client, command, {
          signingDate: new Date('2026-11-15T02:00:00Z'),
          expiresIn: expires === 604801 || expires === 0 ? undefined : expires,
          signableHeaders: new Set(['host']),
        }),
      )
      signedUrl.searchParams.set('X-Amz-Expires', String(expires))

      await expect(
        verifyRequest(new Request(signedUrl), credentials, {
          now: new Date(now),
        }),
      ).rejects.toMatchObject({ code })
    },
  )

  it('accepts a signed Date header when x-amz-date is absent', async () => {
    const request = signedDateRequest()

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).resolves.toMatchObject({ kind: 'authorization' })
  })

  it('rejects an impossible presigned date', async () => {
    const url = new URL(await presignGet('test.txt'))
    const credential = url.searchParams.get('X-Amz-Credential')
    url.searchParams.set('X-Amz-Date', '20260230T020000Z')
    url.searchParams.set(
      'X-Amz-Credential',
      credential.replace('20261115', '20260230'),
    )

    await expect(
      verifyRequest(new Request(url), credentials, {
        now: new Date('2026-03-01T00:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'AuthorizationHeaderMalformed' })
  })

  it.each([
    ['duplicate signature', 'X-Amz-Signature'],
    ['missing signature', 'X-Amz-Signature'],
    ['duplicate credential', 'X-Amz-Credential'],
  ])('rejects a %s presigned parameter', async (label, parameter) => {
    const url = new URL(await presignGet('test.txt'))
    if (label.startsWith('missing')) {
      url.searchParams.delete(parameter)
    } else {
      url.searchParams.append(parameter, url.searchParams.get(parameter))
    }

    await expect(
      verifyRequest(new Request(url), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({
      code: 'AuthorizationHeaderMalformed',
    })
  })

  it.each([
    'X-Amz-Algorithm',
    'X-Amz-Credential',
    'X-Amz-Date',
    'X-Amz-Expires',
    'X-Amz-SignedHeaders',
    'X-Amz-Signature',
  ])('rejects a mixed-case duplicate %s parameter', async (parameter) => {
    const url = new URL(await presignGet('test.txt'))
    url.searchParams.append(
      parameter.toLowerCase(),
      url.searchParams.get(parameter),
    )

    await expect(
      verifyRequest(new Request(url), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'AuthorizationHeaderMalformed' })
  })

  it('rejects simultaneous header and presigned authentication', async () => {
    const request = await signAuthorization()
    const url = new URL(request.url)
    url.searchParams.set('X-Amz-Signature', '0'.repeat(64))

    await expect(
      verifyRequest(new Request(url, request), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'InvalidRequest' })
  })

  it('rejects security tokens in presigned URLs', async () => {
    const url = new URL(await presignGet('test.txt'))
    url.searchParams.set('X-Amz-Security-Token', 'token')

    await expect(
      verifyRequest(new Request(url), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'InvalidRequest' })
  })

  it('rejects security token headers', async () => {
    const request = await signAuthorization({
      headers: { 'x-amz-security-token': 'token' },
    })

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'InvalidRequest' })
  })

  it.each([
    ['SigV4a', 'AWS4-ECDSA-P256-SHA256'],
    ['unsupported algorithm', 'AWS4-HMAC-SHA1'],
  ])('rejects %s Authorization headers', async (_label, algorithm) => {
    const request = await signAuthorization()
    const headers = new Headers(request.headers)
    headers.set(
      'authorization',
      headers.get('authorization').replace('AWS4-HMAC-SHA256', algorithm),
    )

    await expect(
      verifyRequest(new Request(request, { headers }), credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'AuthorizationHeaderMalformed' })
  })

  it.each([
    ['STREAMING-AWS4-HMAC-SHA256-PAYLOAD', {}],
    ['64'.repeat(32), { 'content-encoding': 'aws-chunked' }],
    ['UNSIGNED-PAYLOAD', { 'x-amz-decoded-content-length': '10' }],
    ['UNSIGNED-PAYLOAD', { 'x-amz-trailer': 'x-amz-checksum-crc32' }],
  ])('rejects streaming payload %s', async (payload, extraHeaders) => {
    const request = await signAuthorization({
      payload,
      headers: extraHeaders,
    })

    await expect(
      verifyRequest(request, credentials, {
        now: new Date('2026-11-15T02:00:00Z'),
      }),
    ).rejects.toMatchObject({ code: 'NotImplemented' })
  })
})
