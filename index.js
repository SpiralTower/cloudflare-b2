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
const UNSIGNABLE_HEADERS = new Set([
  'accept-encoding',
  'authorization',
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'connection',
  'content-length',
  'host',
  'if-match',
  'if-modified-since',
  'if-none-match',
  'if-range',
  'if-unmodified-since',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-real-ip',
  'x-amz-date',
])

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
      error.code === 'InvalidRequest' ? 400 : 500,
    )
  }
  console.error(error)
  return xmlError('InternalError', 'Internal server error', 500)
}

function filterHeaders(headers, env) {
  const allowed = env.ALLOWED_HEADERS
  return new Headers(
    Array.from(headers.entries()).filter(([name]) => {
      const lowerName = name.toLowerCase()
      if (UNSIGNABLE_HEADERS.has(lowerName) || lowerName.startsWith('cf-')) {
        return false
      }
      if (allowed === undefined) return true
      return allowed.includes(lowerName)
    }),
  )
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

      if (request.method !== 'OPTIONS') {
        if (anonymousRead) {
          if (hasSigV4Information(request)) {
            await verifyRequest(request, credentials, verificationOptions)
          }
        } else {
          await verifyRequest(request, credentials, verificationOptions)
        }
      }

      const route = routeRequest(request, env)
      if (route.isListBucket && String(env.ALLOW_LIST_BUCKET) !== 'true') {
        return xmlError(
          'AccessDenied',
          'Bucket listing is disabled for this deployment.',
        )
      }
      const upstreamMethod = request.method === 'HEAD' ? 'GET' : request.method
      const payloadHash =
        request.method === 'HEAD' || request.method === 'OPTIONS'
          ? 'UNSIGNED-PAYLOAD'
          : request.headers.get('x-amz-content-sha256') || 'UNSIGNED-PAYLOAD'
      const signed = await signRequest({
        method: upstreamMethod,
        url: route.upstream,
        headers: filterHeaders(request.headers, env),
        payloadHash,
        credentials,
        region: route.region,
      })
      const upstreamRequest = new Request(route.upstream, {
        method: upstreamMethod,
        headers: signed.headers,
        body:
          upstreamMethod === 'GET' || upstreamMethod === 'HEAD'
            ? undefined
            : request.body,
        redirect: 'manual',
      })
      const response = await fetchWithRangeRetry(upstreamRequest)
      return request.method === 'HEAD' ? headResponse(response) : response
    } catch (error) {
      return errorResponse(error)
    }
  },
}
