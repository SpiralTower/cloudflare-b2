import { describe, expect, it } from 'vitest'
import { signRequest, verifyRequest } from '../src/sigv4.js'

const credentials = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
}

describe('SigV4 signing', () => {
  it('produces a signature accepted by the verifier', async () => {
    const headers = new Headers({
      'content-type': 'text/plain',
      'x-amz-checksum-sha256': 'checksum',
    })
    const result = await signRequest({
      method: 'PUT',
      url: 'https://bucket.s3.us-west-001.backblazeb2.com/folder/a%20b.txt?partNumber=2',
      headers,
      payloadHash: 'UNSIGNED-PAYLOAD',
      credentials,
      region: 'us-west-001',
      now: new Date('2026-11-15T02:00:00Z'),
    })
    headers.set('authorization', result.headers.get('authorization'))
    headers.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD')
    headers.set('x-amz-date', '20261115T020000Z')

    await expect(
      verifyRequest(
        new Request(
          'https://bucket.s3.us-west-001.backblazeb2.com/folder/a%20b.txt?partNumber=2',
          { method: 'PUT', headers },
        ),
        credentials,
        { now: new Date('2026-11-15T02:00:00Z') },
      ),
    ).resolves.toMatchObject({ kind: 'authorization' })
    expect(result.signedHeaders).toContain('content-type')
    expect(result.signedHeaders).toContain('x-amz-checksum-sha256')
  })

  it('omits presigned authentication query parameters', () => {
    return signRequest({
      method: 'GET',
      url: 'https://bucket.s3.us-west-001.backblazeb2.com/key?versionId=1&X-Amz-Signature=old&X-Amz-Date=old',
      credentials,
      region: 'us-west-001',
      now: new Date('2026-11-15T02:00:00Z'),
    }).then((result) => {
      expect(result.signedHeaders).not.toContain('x-amz-security-token')
      expect(result.amzDate).toBe('20261115T020000Z')
    })
  })
})
