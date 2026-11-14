const ALGORITHM = 'AWS4-HMAC-SHA256'
const AMZ_DATE_PATTERN = /^\d{8}T\d{6}Z$/
const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/i
const MAX_PRESIGNED_TTL = 604800
const DEFAULT_MAX_SKEW_SECONDS = 900
const SIGNATURE_QUERY_PARAM = new Set(['x-amz-signature'])
const AUTHENTICATION_QUERY_PARAMETERS = [
  'X-Amz-Algorithm',
  'X-Amz-Credential',
  'X-Amz-Date',
  'X-Amz-Expires',
  'X-Amz-SignedHeaders',
  'X-Amz-Signature',
  'X-Amz-Content-Sha256',
  'X-Amz-Security-Token',
]
const REQUIRED_PRESIGNED_QUERY_PARAMETERS =
  AUTHENTICATION_QUERY_PARAMETERS.slice(0, 6)

export class SigV4Error extends Error {
  constructor(code, message, status = 403) {
    super(message)
    this.name = 'SigV4Error'
    this.code = code
    this.status = status
  }
}

export function timingSafeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false

  const length = Math.max(left.length, right.length)
  let difference = left.length ^ right.length
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0)
  }
  return difference === 0
}

export function rfc3986Encode(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  )
}

export function canonicalizePath(pathname) {
  const path = pathname.startsWith('/') ? pathname : `/${pathname}`
  let decoded
  try {
    decoded = decodeURIComponent(path)
  } catch {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The request path contains invalid percent-encoding.',
      400,
    )
  }

  return decoded
    .split('/')
    .map((segment) => rfc3986Encode(segment))
    .join('/')
}

export function parseRawQuery(query) {
  if (query === '') return []
  return query.split('&').map((part) => {
    const separator = part.indexOf('=')
    return separator === -1
      ? { key: part, value: '', hasValue: false }
      : {
          key: part.slice(0, separator),
          value: part.slice(separator + 1),
          hasValue: true,
        }
  })
}

function decodeQueryPart(value, name) {
  try {
    return decodeURIComponent(value)
  } catch {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      `The ${name} query parameter has invalid percent-encoding.`,
      400,
    )
  }
}

function decodeQueryForSignature(value) {
  try {
    return decodeURIComponent(value)
  } catch {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The query string has invalid percent-encoding.',
      400,
    )
  }
}

export function canonicalizeQuery(parts, excluded = new Set()) {
  return parts
    .filter(
      ({ key }) =>
        !excluded.has(decodeQueryPart(key, 'query key').toLowerCase()),
    )
    .map(({ key, value }) => ({
      key: rfc3986Encode(decodeQueryForSignature(key)),
      value: rfc3986Encode(decodeQueryForSignature(value)),
    }))
    .sort((left, right) => {
      if (left.key !== right.key) return left.key < right.key ? -1 : 1
      if (left.value === right.value) return 0
      return left.value < right.value ? -1 : 1
    })
    .map(({ key, value }) => `${key}=${value}`)
    .join('&')
}

export function canonicalizeHeaders(headers, signedHeaderNames, host = null) {
  return signedHeaderNames
    .map((name) => {
      const values = name === 'host' && host !== null ? host : headers.get(name)
      if (values === null) {
        throw new SigV4Error(
          'AuthorizationHeaderMalformed',
          `Signed header "${name}" is missing.`,
          400,
        )
      }
      return `${name}:${values.trim().replace(/\s+/g, ' ')}`
    })
    .join('\n')
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value)
  return toHex(await crypto.subtle.digest('SHA-256', bytes))
}

async function hmac(key, value) {
  let cryptoKey
  try {
    cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
  } catch {
    cryptoKey = await crypto.subtle.importKey(
      'raw',
      key.buffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
  }
  return new Uint8Array(
    await crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      new TextEncoder().encode(value),
    ),
  )
}

async function deriveSigningKey(secret, shortDate, region) {
  const dateKey = await hmac(
    new TextEncoder().encode(`AWS4${secret}`),
    shortDate,
  )
  const regionKey = await hmac(dateKey, region)
  const serviceKey = await hmac(regionKey, 's3')
  return hmac(serviceKey, 'aws4_request')
}

function sqlTimestampToLongDate(timestamp) {
  return timestamp.replace(/[-:]/g, '').replace('.000Z', 'Z')
}

function parseRequestTime(request, signedHeaderNames) {
  const amzDate = request.headers.get('x-amz-date')
  if (amzDate !== null) {
    if (!AMZ_DATE_PATTERN.test(amzDate)) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'x-amz-date must use the YYYYMMDDTHHMMSSZ format.',
        400,
      )
    }
    return amzDate
  }

  if (!signedHeaderNames.includes('date')) {
    throw new SigV4Error(
      'AccessDenied',
      'AWS authentication requires a valid x-amz-date or signed Date header.',
    )
  }

  const dateHeader = request.headers.get('date')
  const date = dateHeader === null ? new Date(NaN) : new Date(dateHeader)
  if (Number.isNaN(date.getTime())) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The signed Date header is invalid.',
      400,
    )
  }
  return sqlTimestampToLongDate(date.toISOString())
}

function parseMaxSkew(value) {
  const text = String(value).trim()
  if (!/^\d+$/.test(text)) return DEFAULT_MAX_SKEW_SECONDS
  const parsed = Number(text)
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 86400
    ? parsed
    : DEFAULT_MAX_SKEW_SECONDS
}

function getCaseInsensitiveParameterValues(params, name) {
  return findCaseInsensitiveParamNames(params, [name]).flatMap((paramName) =>
    params.getAll(paramName),
  )
}

function requireSingleParameter(params, name) {
  const values = getCaseInsensitiveParameterValues(params, name)
  if (values.length !== 1) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      `The ${name} query parameter must appear exactly once.`,
      400,
    )
  }
  return values[0]
}

function parseScope(credential, accessKeyId) {
  const credentialParts = credential.split('/').flatMap((part) => {
    return part.split(/%2F/i).flatMap((nestedPart) => {
      try {
        return decodeURIComponent(nestedPart).split('/')
      } catch {
        return [nestedPart]
      }
    })
  })
  const parts =
    credentialParts.length === 1 && credential.includes('%2F')
      ? credential.split('%2F')
      : credentialParts
  if (
    parts.length !== 5 ||
    parts[0] !== accessKeyId ||
    parts[1] === '' ||
    parts[3] !== 's3' ||
    parts[4] !== 'aws4_request'
  ) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The credential scope must be <access-key>/<date>/<region>/s3/aws4_request.',
      400,
    )
  }
  return {
    shortDate: parts[1],
    region: parts[2],
  }
}

export function parseAuthorization(request) {
  const authorization = request.headers.get('authorization')
  if (authorization === null) return null
  if (!authorization.startsWith(`${ALGORITHM} `)) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The Authorization header uses an unsupported signing algorithm.',
      400,
    )
  }

  const fields = {}
  for (const item of authorization.slice(ALGORITHM.length + 1).split(',')) {
    const separator = item.indexOf('=')
    if (separator === -1) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'The Authorization header is malformed.',
        400,
      )
    }
    const name = item.slice(0, separator).trim()
    const value = item.slice(separator + 1).trim()
    if (
      !['Credential', 'SignedHeaders', 'Signature'].includes(name) ||
      name in fields ||
      value === ''
    ) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'The Authorization header is malformed.',
        400,
      )
    }
    fields[name] = value
  }
  if (
    Object.keys(fields).length !== 3 ||
    !SIGNATURE_PATTERN.test(fields.Signature)
  ) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The Authorization header is malformed.',
      400,
    )
  }

  const signedHeaderNames = fields.SignedHeaders.toLowerCase().split(';')
  if (
    signedHeaderNames.some(
      (name) => !/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name),
    ) ||
    new Set(signedHeaderNames).size !== signedHeaderNames.length ||
    [...signedHeaderNames].sort().join(';') !== signedHeaderNames.join(';')
  ) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'SignedHeaders must be a sorted, unique, semicolon-separated list.',
      400,
    )
  }

  return {
    kind: 'authorization',
    credential: fields.Credential,
    signedHeaders: fields.SignedHeaders,
    signedHeaderNames,
    signature: fields.Signature,
  }
}

function findCaseInsensitiveParamNames(params, names) {
  const expected = new Set(names.map((name) => name.toLowerCase()))
  return Array.from(params.keys()).filter((name) =>
    expected.has(name.toLowerCase()),
  )
}

async function calculateSignature({
  method,
  pathname,
  query,
  signedHeaderNames,
  signedHeaders,
  payloadHash,
  longDate,
  scope,
  secretAccessKey,
}) {
  const canonicalRequest = [
    method,
    canonicalizePath(pathname),
    query,
    signedHeaders,
    '',
    signedHeaderNames.join(';'),
    payloadHash,
  ].join('\n')
  const scopeString = `${scope.shortDate}/${scope.region}/s3/aws4_request`
  const stringToSign = [
    ALGORITHM,
    longDate,
    scopeString,
    await sha256(canonicalRequest),
  ].join('\n')
  const signingKey = await deriveSigningKey(
    secretAccessKey,
    scope.shortDate,
    scope.region,
  )
  return toHex(await hmac(signingKey, stringToSign))
}

function formatAmzDate(value) {
  return new Date(value).toISOString().replace(/[-:]|\.\d{3}/g, '')
}

export async function signRequest({
  method,
  url,
  headers: inputHeaders = new Headers(),
  payloadHash = 'UNSIGNED-PAYLOAD',
  credentials,
  region,
  now = new Date(),
}) {
  if (
    typeof credentials?.accessKeyId !== 'string' ||
    typeof credentials?.secretAccessKey !== 'string'
  ) {
    throw new SigV4Error(
      'AccessDenied',
      'Worker signing credentials are not configured.',
      500,
    )
  }
  if (typeof region !== 'string' || region === '') {
    throw new SigV4Error(
      'InvalidRequest',
      'The upstream region could not be determined.',
      500,
    )
  }

  const requestUrl = new URL(url)
  const longDate = formatAmzDate(now)
  const shortDate = longDate.slice(0, 8)
  const headers = new Headers(inputHeaders)
  headers.delete('authorization')
  headers.delete('host')
  headers.set('x-amz-content-sha256', payloadHash)
  headers.set('x-amz-date', longDate)

  const signedHeaderNames = new Set([
    'host',
    'x-amz-content-sha256',
    'x-amz-date',
  ])
  for (const name of headers.keys()) {
    const lowerName = name.toLowerCase()
    if (
      lowerName.startsWith('x-amz-') ||
      lowerName === 'content-md5' ||
      lowerName === 'content-type'
    ) {
      signedHeaderNames.add(lowerName)
    }
  }
  const sortedSignedHeaders = Array.from(signedHeaderNames).sort()
  const signedHeaders = canonicalizeHeaders(
    headers,
    sortedSignedHeaders,
    requestUrl.host,
  )
  const scope = { shortDate, region }
  const query = canonicalizeQuery(
    parseRawQuery(requestUrl.search.replace(/^\?/, '')),
  )
  const signature = await calculateSignature({
    method,
    pathname: requestUrl.pathname,
    query,
    signedHeaderNames: sortedSignedHeaders,
    signedHeaders,
    payloadHash,
    longDate,
    scope,
    secretAccessKey: credentials.secretAccessKey,
  })
  const authorization = `${ALGORITHM} Credential=${credentials.accessKeyId}/${shortDate}/${region}/s3/aws4_request, SignedHeaders=${sortedSignedHeaders.join(';')}, Signature=${signature}`
  headers.set('authorization', authorization)

  return {
    headers,
    authorization,
    amzDate: longDate,
    signedHeaders: sortedSignedHeaders,
    payloadHash,
  }
}

function validatePayloadHash(value) {
  if (value === null) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'x-amz-content-sha256 is required for Authorization header requests.',
      400,
    )
  }
  if (value !== 'UNSIGNED-PAYLOAD' && !SIGNATURE_PATTERN.test(value)) {
    throw new SigV4Error(
      'NotImplemented',
      `Payload hash "${value}" is not supported.`,
      501,
    )
  }
  return value
}

function rejectStreaming(request, payloadHash, signedHeaderNames) {
  if (
    /^STREAMING-/i.test(payloadHash) ||
    /(?:^|,)aws-chunked(?:=|,|$)/i.test(
      request.headers.get('content-encoding') || '',
    ) ||
    request.headers.has('x-amz-decoded-content-length') ||
    request.headers.has('x-amz-trailer') ||
    signedHeaderNames.some((name) => name.startsWith('x-amz-trailer'))
  ) {
    throw new SigV4Error(
      'NotImplemented',
      'Streaming SigV4 payloads and trailers are not supported.',
      501,
    )
  }
}

export async function verifyRequest(request, credentials, options = {}) {
  const url = new URL(request.url)
  const hasAuthorizationHeader = request.headers.has('authorization')
  const hasSecurityTokenHeader = request.headers.has('x-amz-security-token')
  const hasPresignInformation =
    findCaseInsensitiveParamNames(
      url.searchParams,
      AUTHENTICATION_QUERY_PARAMETERS,
    ).length > 0
  if (
    !hasAuthorizationHeader &&
    !hasPresignInformation &&
    !hasSecurityTokenHeader
  ) {
    if (options.requireAuthentication) {
      throw new SigV4Error(
        'AccessDenied',
        'A valid SigV4 signature is required.',
      )
    }
    return null
  }

  if (
    typeof credentials?.accessKeyId !== 'string' ||
    typeof credentials?.secretAccessKey !== 'string'
  ) {
    throw new SigV4Error(
      'AccessDenied',
      'Worker signing credentials are not configured.',
      500,
    )
  }

  const hasAuthorization = request.headers.has('authorization')
  const authParamNames = findCaseInsensitiveParamNames(
    url.searchParams,
    AUTHENTICATION_QUERY_PARAMETERS,
  )
  const hasAnyPresignParameter = authParamNames.length > 0

  if (hasAuthorization && hasAnyPresignParameter) {
    throw new SigV4Error(
      'InvalidRequest',
      'Use either Authorization header signing or presigned URL signing.',
      400,
    )
  }
  if (
    !hasAuthorization &&
    hasAnyPresignParameter &&
    !authParamNames.some((name) => name.toLowerCase() === 'x-amz-signature')
  ) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The presigned URL is missing required authentication parameters.',
      400,
    )
  }
  if (
    hasSecurityTokenHeader ||
    authParamNames.some((name) => name.toLowerCase() === 'x-amz-security-token')
  ) {
    throw new SigV4Error(
      'InvalidRequest',
      'Security token authentication is not supported.',
      400,
    )
  }
  if (!hasAuthorization && !hasAnyPresignParameter) return null

  const requestTime = options.now ? new Date(options.now) : new Date()
  let longDate
  let signedHeaderNames
  let signature
  let scope
  let payloadHash
  let query

  if (hasAuthorization) {
    const parsed = parseAuthorization(request)
    signedHeaderNames = parsed.signedHeaderNames
    signature = parsed.signature
    scope = parseScope(parsed.credential, credentials.accessKeyId)
    longDate = parseRequestTime(request, signedHeaderNames)
    payloadHash = validatePayloadHash(
      request.headers.get('x-amz-content-sha256'),
    )
    rejectStreaming(request, payloadHash, signedHeaderNames)
    query = canonicalizeQuery(parseRawQuery(url.search.slice(1)))
  } else {
    const params = url.searchParams
    for (const name of REQUIRED_PRESIGNED_QUERY_PARAMETERS) {
      requireSingleParameter(params, name)
    }
    if (
      getCaseInsensitiveParameterValues(params, 'X-Amz-Content-Sha256').length >
      1
    ) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'The X-Amz-Content-Sha256 query parameter must appear at most once.',
        400,
      )
    }
    if (requireSingleParameter(params, 'X-Amz-Algorithm') !== ALGORITHM) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'The presigned URL uses an unsupported signing algorithm.',
        400,
      )
    }
    scope = parseScope(
      requireSingleParameter(params, 'X-Amz-Credential'),
      credentials.accessKeyId,
    )
    longDate = requireSingleParameter(params, 'X-Amz-Date')
    if (!AMZ_DATE_PATTERN.test(longDate)) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'X-Amz-Date must use the YYYYMMDDTHHMMSSZ format.',
        400,
      )
    }
    if (longDate.slice(0, 8) !== scope.shortDate) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'The credential date does not match X-Amz-Date.',
        400,
      )
    }
    const expiresText = requireSingleParameter(params, 'X-Amz-Expires')
    if (!/^\d+$/.test(expiresText)) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'X-Amz-Expires must be an integer.',
        400,
      )
    }
    const expires = Number(expiresText)
    const issuedAt = parseLongDate(longDate)
    if (issuedAt > requestTime.getTime()) {
      throw new SigV4Error(
        'RequestTimeTooSkewed',
        'The presigned URL is not valid yet.',
      )
    }
    if (expires < 1 || expires > MAX_PRESIGNED_TTL) {
      throw new SigV4Error(
        'InvalidRequest',
        'X-Amz-Expires must be between 1 and 604800 seconds.',
        400,
      )
    }
    if (requestTime.getTime() > issuedAt + expires * 1000) {
      throw new SigV4Error('RequestExpired', 'The presigned URL has expired.')
    }

    signedHeaderNames = requireSingleParameter(params, 'X-Amz-SignedHeaders')
      .toLowerCase()
      .split(';')
    if (
      signedHeaderNames.some(
        (name) => !/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name),
      ) ||
      new Set(signedHeaderNames).size !== signedHeaderNames.length ||
      [...signedHeaderNames].sort().join(';') !== signedHeaderNames.join(';')
    ) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'X-Amz-SignedHeaders must be a sorted, unique, semicolon-separated list.',
        400,
      )
    }
    if (!signedHeaderNames.includes('host')) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'The host header must be signed.',
        400,
      )
    }
    signature = requireSingleParameter(params, 'X-Amz-Signature')
    if (!SIGNATURE_PATTERN.test(signature)) {
      throw new SigV4Error(
        'AuthorizationHeaderMalformed',
        'X-Amz-Signature must be a SHA-256 hex digest.',
        400,
      )
    }
    payloadHash = 'UNSIGNED-PAYLOAD'
    rejectStreaming(
      request,
      request.headers.get('x-amz-content-sha256') || payloadHash,
      signedHeaderNames,
    )
    query = canonicalizeQuery(
      parseRawQuery(url.search.slice(1)),
      SIGNATURE_QUERY_PARAM,
    )
  }

  if (!signedHeaderNames.includes('host')) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The host header must be signed.',
      400,
    )
  }
  if (longDate.slice(0, 8) !== scope.shortDate) {
    throw new SigV4Error(
      'AuthorizationHeaderMalformed',
      'The credential date does not match the request time.',
      400,
    )
  }
  if (hasAuthorization) {
    const time = parseLongDate(longDate)
    const maxSkew = parseMaxSkew(options.maxSkewSeconds)
    if (
      Number.isNaN(time) ||
      Math.abs(requestTime.getTime() - time) > maxSkew * 1000
    ) {
      throw new SigV4Error(
        'RequestTimeTooSkewed',
        'The difference between the request time and the server time is too large.',
      )
    }
  }

  const signedHeaders = canonicalizeHeaders(
    request.headers,
    signedHeaderNames,
    url.host,
  )
  const expected = await calculateSignature({
    method: request.method,
    pathname: url.pathname,
    query,
    signedHeaderNames,
    signedHeaders,
    payloadHash,
    longDate,
    scope,
    secretAccessKey: credentials.secretAccessKey,
  })
  if (!timingSafeEqual(signature.toLowerCase(), expected)) {
    throw new SigV4Error(
      'SignatureDoesNotMatch',
      'The request signature we calculated does not match the signature you provided.',
    )
  }

  return {
    kind: hasAuthorization ? 'authorization' : 'presigned',
    signedHeaders: signedHeaderNames,
    payloadHash,
    scope,
  }
}

export function hasSigV4Information(request) {
  if (
    request.headers.has('authorization') ||
    request.headers.has('x-amz-security-token')
  ) {
    return true
  }
  const url = new URL(request.url)
  return (
    findCaseInsensitiveParamNames(
      url.searchParams,
      AUTHENTICATION_QUERY_PARAMETERS,
    ).length > 0
  )
}

function parseLongDate(value) {
  if (!AMZ_DATE_PATTERN.test(value)) return NaN
  const time = new Date(
    `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(9, 11)}:${value.slice(11, 13)}:${value.slice(13, 15)}Z`,
  ).getTime()
  return Number.isNaN(time) || formatAmzDate(time) !== value ? NaN : time
}
