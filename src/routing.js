const B2_ENDPOINT_PATTERN = /^s3\.([a-z]{2}-[a-z]+-\d{3})\.backblazeb2\.com$/i

export class RoutingError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'RoutingError'
    this.code = code
  }
}

export function parseB2Endpoint(endpoint) {
  const value = String(endpoint || '')
    .trim()
    .toLowerCase()
  const match = B2_ENDPOINT_PATTERN.exec(value)
  if (!match) {
    throw new RoutingError(
      'InvalidRequest',
      'B2_ENDPOINT must be a standard Backblaze B2 S3 endpoint.',
    )
  }
  return {
    endpoint: value,
    region: match[1],
  }
}

function pathSegments(pathname) {
  return pathname
    .replace(/^\/+/, '')
    .split('/')
    .filter((segment, index, segments) => {
      return !(segment === '' && index === segments.length - 1)
    })
}

export function routeRequest(request, env) {
  const incoming = new URL(request.url)
  const bucketSetting = String(env.BUCKET_NAME || '')
  if (bucketSetting === '') {
    throw new RoutingError('InvalidRequest', 'BUCKET_NAME is not configured.')
  }

  const { endpoint, region } = parseB2Endpoint(env.B2_ENDPOINT)
  const segments = pathSegments(incoming.pathname)
  const rcloneDownload = String(env.RCLONE_DOWNLOAD) === 'true'
  const rcloneSegments = incoming.pathname.replace(/^\/+/, '').split('/')
  const isRcloneRequest = rcloneDownload && rcloneSegments[0] === 'file'
  let bucket
  let keySegments

  if (bucketSetting === '$path') {
    const routeSegments = isRcloneRequest ? rcloneSegments : segments
    const bucketSegment =
      bucketSetting === '$path' && isRcloneRequest
        ? routeSegments[1]
        : routeSegments[0]
    if (!bucketSegment) {
      throw new RoutingError('InvalidRequest', 'The bucket name is missing.')
    }
    bucket = bucketSegment
    keySegments = isRcloneRequest
      ? routeSegments.slice(2)
      : routeSegments.slice(1)
  } else if (bucketSetting === '$host') {
    bucket = incoming.hostname.split('.')[0]
    if (!bucket || bucket === incoming.hostname) {
      throw new RoutingError(
        'InvalidRequest',
        'The bucket subdomain is missing.',
      )
    }
    keySegments = isRcloneRequest ? rcloneSegments.slice(2) : segments
  } else {
    bucket = bucketSetting
    keySegments = isRcloneRequest ? rcloneSegments.slice(2) : segments
  }

  let upstreamPathname = incoming.pathname
  if (isRcloneRequest) {
    const prefixLength = bucketSetting === '$path' ? 1 : 2
    const remainingSegments = rcloneSegments.slice(prefixLength)
    upstreamPathname =
      remainingSegments.length > 0 ? `/${remainingSegments.join('/')}` : '/'
  }

  const upstream = new URL(incoming.toString())
  upstream.protocol = 'https:'
  upstream.port = ''
  upstream.hostname =
    bucketSetting === '$path' ? endpoint : `${bucket}.${endpoint}`
  upstream.pathname = upstreamPathname
  upstream.search = removeQueryParameters(
    incoming.search,
    new Set([
      'x-amz-algorithm',
      'x-amz-credential',
      'x-amz-date',
      'x-amz-expires',
      'x-amz-signedheaders',
      'x-amz-signature',
      'x-amz-content-sha256',
      'x-amz-security-token',
    ]),
  )

  return {
    incoming,
    upstream,
    bucket,
    region,
    isListBucket: keySegments.length === 0,
  }
}

export function removeQueryParameters(search, excluded) {
  if (search === '' || search === '?') return ''
  const values = []
  for (const part of search.slice(1).split('&')) {
    const separator = part.indexOf('=')
    const rawKey = separator === -1 ? part : part.slice(0, separator)
    let decodedKey
    try {
      decodedKey = decodeURIComponent(rawKey)
    } catch {
      throw new RoutingError(
        'AuthorizationHeaderMalformed',
        'The query string has invalid percent-encoding.',
      )
    }
    if (!excluded.has(decodedKey.toLowerCase())) values.push(part)
  }
  return values.length > 0 ? `?${values.join('&')}` : ''
}
