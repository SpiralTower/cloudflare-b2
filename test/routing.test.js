import { describe, expect, it } from 'vitest'
import {
  parseB2Endpoint,
  removeQueryParameters,
  routeRequest,
} from '../src/routing.js'

const baseEnv = {
  B2_ENDPOINT: 's3.us-west-001.backblazeb2.com',
}

describe('routing', () => {
  it('extracts the region from a standard B2 endpoint', () => {
    expect(parseB2Endpoint('s3.us-west-004.backblazeb2.com')).toEqual({
      endpoint: 's3.us-west-004.backblazeb2.com',
      region: 'us-west-004',
    })
  })

  it('rejects a non-standard endpoint', () => {
    expect(() => parseB2Endpoint('example.com')).toThrow(
      'standard Backblaze B2 S3 endpoint',
    )
  })

  it('routes a fixed bucket and preserves the query order', () => {
    const result = routeRequest(
      new Request(
        'https://cdn.example.com/a%20b.txt?versionId=2&partNumber=1&X-Amz-Signature=abc',
      ),
      { ...baseEnv, BUCKET_NAME: 'my-bucket' },
    )

    expect(result.upstream.href).toBe(
      'https://my-bucket.s3.us-west-001.backblazeb2.com/a%20b.txt?versionId=2&partNumber=1',
    )
    expect(result.bucket).toBe('my-bucket')
    expect(result.region).toBe('us-west-001')
  })

  it('marks bucket list requests and respects ALLOW_LIST_BUCKET', () => {
    const fixed = routeRequest(new Request('https://cdn.example.com/'), {
      ...baseEnv,
      BUCKET_NAME: 'my-bucket',
    })
    expect(fixed.isListBucket).toBe(true)

    const path = routeRequest(
      new Request('https://cdn.example.com/my-bucket/'),
      { ...baseEnv, BUCKET_NAME: '$path' },
    )
    expect(path.isListBucket).toBe(true)

    const object = routeRequest(
      new Request('https://cdn.example.com/object.txt'),
      { ...baseEnv, BUCKET_NAME: 'my-bucket' },
    )
    expect(object.isListBucket).toBe(false)
  })

  it('routes $path buckets', () => {
    const result = routeRequest(
      new Request('https://cdn.example.com/bucket/folder/test.txt'),
      { ...baseEnv, BUCKET_NAME: '$path' },
    )

    expect(result.upstream.pathname).toBe('/bucket/folder/test.txt')
    expect(result.upstream.hostname).toBe(
      'bucket.s3.us-west-001.backblazeb2.com',
    )
  })

  it('routes $host buckets', () => {
    const result = routeRequest(
      new Request('https://photos.cdn.example.com/folder/test.txt'),
      { ...baseEnv, BUCKET_NAME: '$host' },
    )

    expect(result.upstream.pathname).toBe('/folder/test.txt')
    expect(result.upstream.hostname).toBe(
      'photos.s3.us-west-001.backblazeb2.com',
    )
  })

  it('strips the rclone file prefix for fixed buckets', () => {
    const result = routeRequest(
      new Request('https://cdn.example.com/file/my-bucket/folder/test.txt'),
      {
        ...baseEnv,
        BUCKET_NAME: 'my-bucket',
        RCLONE_DOWNLOAD: 'true',
      },
    )

    expect(result.upstream.pathname).toBe('/folder/test.txt')
  })

  it('strips the rclone file and bucket prefixes for $path', () => {
    const result = routeRequest(
      new Request('https://cdn.example.com/file/my-bucket/folder/test.txt'),
      {
        ...baseEnv,
        BUCKET_NAME: '$path',
        RCLONE_DOWNLOAD: 'true',
      },
    )

    expect(result.upstream.pathname).toBe('/my-bucket/folder/test.txt')
  })

  it('removes authentication query parameters case-insensitively', () => {
    expect(
      removeQueryParameters(
        '?x-amz-signature=1&versionId=2&X-Amz-Credential=3&x=4',
        new Set(['x-amz-signature', 'x-amz-credential']),
      ),
    ).toBe('?versionId=2&x=4')
  })
})
