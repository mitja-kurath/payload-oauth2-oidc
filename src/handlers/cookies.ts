type SameSite = 'Lax' | 'Strict' | 'None'

export interface CookieOptions {
  path?: string
  httpOnly?: boolean
  sameSite?: SameSite
  maxAge?: number
  secure?: boolean
}

export const parseCookies = (cookieHeader: string): Record<string, string> => {
  const out: Record<string, string> = {}
  if (!cookieHeader) return out

  for (const part of cookieHeader.split(';')) {
    const [rawKey, ...rawVal] = part.split('=')
    const key = rawKey?.trim()
    if (!key) continue
    const value = rawVal.join('=').trim()
    if (!value) continue
    out[key] = decodeURIComponent(value)
  }

  return out
}

export const serializeCookie = (
  name: string,
  value: string,
  options: CookieOptions,
): string => {
  const parts: string[] = [`${name}=${encodeURIComponent(value)}`]

  if (options.path) parts.push(`Path=${options.path}`)
  if (typeof options.maxAge === 'number') parts.push(`Max-Age=${options.maxAge}`)
  if (options.httpOnly) parts.push('HttpOnly')
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`)
  if (options.secure) parts.push('Secure')

  return parts.join('; ')
}

export const deleteCookie = (name: string, options: CookieOptions): string =>
  serializeCookie(name, '', { ...options, maxAge: 0 })

export const isSecureServerUrl = (serverURL: string): boolean => {
  try {
    return new URL(serverURL).protocol === 'https:'
  } catch {
    return false
  }
}
