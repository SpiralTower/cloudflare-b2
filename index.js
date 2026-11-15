import {
  SigV4Error,
  hasSigV4Information,
  signRequest,
  verifyRequest,
} from './src/sigv4.js'
import { RoutingError, routeRequest } from './src/routing.js'

const XML_HEADERS = {
  'content-type': 'application/xml; charset=utf-8',
}
const SUPPORTED_METHODS = new Set([
  'GET',
  'HEAD',
  'PUT',
  'POST',
  'DELETE',
  'OPTIONS',
])
const RANGE_RETRY_ATTEMPTS = 3
const UNSIGNED_FORWARD_HEADERS = new Set(['content-length'])
const CORS_REQUEST_HEADERS = new Set([
  'origin',
  'access-control-request-method',
  'access-control-request-headers',
  'access-control-request-private-network',
])
const CONTENT_LENGTH_PATTERN = /^\d+$/
const UNSIGNABLE_HEADERS = new Set([
  'accept-encoding',
  'authorization',
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'connection',
  'host',
  'if-match',
  'if-modified-since',
  'if-none-match',
  'if-range',
  'if-unmodified-since',
  'keep-alive',
  'proxy-connection',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-real-ip',
  'x-amz-date',
  'x-amz-security-token',
])

class RequestBodyError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'RequestBodyError'
    this.code = code
  }
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function xmlError(code, message, status = 403) {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${escapeXml(code)}</Code><Message>${escapeXml(message)}</Message></Error>`,
    {
      status,
      headers: XML_HEADERS,
    },
  )
}

function errorResponse(error) {
  if (error instanceof SigV4Error) {
    return xmlError(error.code, error.message, error.status)
  }
  if (error instanceof RoutingError) {
    return xmlError(
      error.code,
      error.message,
      ['InvalidRequest', 'AuthorizationHeaderMalformed'].includes(error.code)
        ? 400
        : 500,
    )
  }
  if (error instanceof RequestBodyError) {
    return xmlError(error.code, error.message, 400)
  }
  console.error(error)
  return xmlError('InternalError', 'Internal server error', 500)
}

function filterHeaders(headers, env, preserveCors = false) {
  const allowed =
    env.ALLOWED_HEADERS === undefined
      ? null
      : new Set(
          Array.from(env.ALLOWED_HEADERS, (name) =>
            String(name).trim().toLowerCase(),
          ),
        )
  return new Headers(
    Array.from(headers.entries()).filter(([name]) => {
      const lowerName = name.toLowerCase()
      if (UNSIGNABLE_HEADERS.has(lowerName) || lowerName.startsWith('cf-')) {
        return false
      }
      return (
        UNSIGNED_FORWARD_HEADERS.has(lowerName) ||
        allowed === null ||
        allowed.has(lowerName) ||
        (preserveCors && CORS_REQUEST_HEADERS.has(lowerName))
      )
    }),
  )
}

function parseContentLength(request) {
  const value = request.headers.get('content-length')
  if (value === null) return null
  if (!CONTENT_LENGTH_PATTERN.test(value)) {
    throw new RequestBodyError(
      'InvalidRequest',
      'The Content-Length header must be a non-negative integer.',
    )
  }
  const length = Number(value)
  if (!Number.isSafeInteger(length)) {
    throw new RequestBodyError(
      'InvalidRequest',
      'The Content-Length header is too large.',
    )
  }
  return length
}

async function bufferRequestBody(request, expectedLength) {
  const chunks = []
  let receivedLength = 0
  const reader = request.body.getReader()
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      receivedLength += value.byteLength
      if (receivedLength > expectedLength) {
        throw new RequestBodyError(
          'IncompleteBody',
          'The request body is larger than the Content-Length header.',
        )
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  if (receivedLength !== expectedLength) {
    throw new RequestBodyError(
      'IncompleteBody',
      'The request body length does not match the Content-Length header.',
    )
  }
  const body = new Uint8Array(receivedLength)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return body
}

async function prepareUpstreamBody(request, upstreamMethod, signedHeaders) {
  if (upstreamMethod === 'GET' || upstreamMethod === 'HEAD') {
    return { body: undefined, headers: signedHeaders }
  }

  const contentLength = parseContentLength(request)
  const decodedContentLength = request.headers.get(
    'x-amz-decoded-content-length',
  )

  if (contentLength !== null && decodedContentLength !== null) {
    throw new RequestBodyError(
      'InvalidRequest',
      'Content-Length and x-amz-decoded-content-length cannot be used together.',
    )
  }

  if (contentLength === null) {
    if (request.body === null) {
      return { body: undefined, headers: signedHeaders }
    }
    return { body: request.body, headers: signedHeaders }
  }

  const headers = new Headers(signedHeaders)
  if (contentLength === 0 && request.body === null) {
    return { body: undefined, headers }
  }
  if (request.body === null) {
    throw new RequestBodyError(
      'IncompleteBody',
      'The request body length does not match the Content-Length header.',
    )
  }

  const body = await bufferRequestBody(request, contentLength)
  headers.set('content-length', String(contentLength))
  return { body, headers }
}

function headResponse(response) {
  return new Response(null, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  })
}

function isAnonymousReadAllowed(request, env) {
  return (
    String(env.ALLOW_UNSIGNED_READ) === 'true' &&
    ['GET', 'HEAD'].includes(request.method)
  )
}

function isHtmlPostPolicy(request) {
  return (
    request.method === 'POST' &&
    String(request.headers.get('content-type') || '')
      .toLowerCase()
      .startsWith('multipart/form-data')
  )
}

async function fetchWithRangeRetry(upstreamRequest) {
  if (!upstreamRequest.headers.has('range')) {
    return fetch(upstreamRequest)
  }

  let attempts = RANGE_RETRY_ATTEMPTS
  let response
  do {
    const controller = new AbortController()
    response = await fetch(upstreamRequest, { signal: controller.signal })
    if (response.headers.has('content-range')) break
    if (!response.ok) break
    attempts -= 1
    if (attempts > 0) controller.abort()
  } while (attempts > 0)
  return response
}

export default {
  async fetch(request, env) {
    try {
      if (!SUPPORTED_METHODS.has(request.method)) {
        return xmlError(
          'MethodNotAllowed',
          'The requested method is not supported.',
          405,
        )
      }
      if (!['http:', 'https:'].includes(new URL(request.url).protocol)) {
        return xmlError(
          'InvalidRequest',
          'Only HTTP and HTTPS requests are supported.',
          400,
        )
      }
      if (isHtmlPostPolicy(request)) {
        return xmlError(
          'NotImplemented',
          'HTML POST policy uploads are not supported.',
          501,
        )
      }

      const credentials = {
        accessKeyId: env.B2_APPLICATION_KEY_ID,
        secretAccessKey: env.B2_APPLICATION_KEY,
      }
      const verificationOptions = {
        maxSkewSeconds: env.SIGNATURE_MAX_SKEW_SECONDS,
        requireAuthentication: true,
      }
      const anonymousRead = isAnonymousReadAllowed(request, env)
      let verification = null

      if (request.method !== 'OPTIONS') {
        if (anonymousRead) {
          if (hasSigV4Information(request)) {
            verification = await verifyRequest(
              request,
              credentials,
              verificationOptions,
            )
          }
        } else {
          verification = await verifyRequest(
            request,
            credentials,
            verificationOptions,
          )
        }
      }

      const route = routeRequest(request, env)
      if (
        route.isListBucket &&
        ['GET', 'HEAD'].includes(request.method) &&
        String(env.ALLOW_LIST_BUCKET) !== 'true'
      ) {
        return xmlError(
          'AccessDenied',
          'Bucket listing is disabled for this deployment.',
        )
      }
      const upstreamMethod = request.method === 'HEAD' ? 'GET' : request.method
      const payloadHash =
        request.method === 'HEAD' || request.method === 'OPTIONS'
          ? 'UNSIGNED-PAYLOAD'
          : verification?.payloadHash || 'UNSIGNED-PAYLOAD'
      const filteredHeaders = filterHeaders(
        request.headers,
        env,
        request.method === 'OPTIONS',
      )
      const signed = await signRequest({
        method: upstreamMethod,
        url: route.upstream,
        headers: filteredHeaders,
        payloadHash,
        credentials,
        region: route.region,
      })
      const upstreamBody = await prepareUpstreamBody(
        request,
        upstreamMethod,
        signed.headers,
      )
      const upstreamRequest = new Request(route.upstream, {
        method: upstreamMethod,
        headers: upstreamBody.headers,
        body: upstreamBody.body,
        redirect: 'manual',
      })
      const response = await fetchWithRangeRetry(upstreamRequest)
      return request.method === 'HEAD' ? headResponse(response) : response
    } catch (error) {
      return errorResponse(error)
    }
  },
}
