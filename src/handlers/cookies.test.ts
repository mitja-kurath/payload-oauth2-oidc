import { describe, expect, it } from 'vitest'
import { deleteCookie, isSecureServerUrl, parseCookies, serializeCookie } from './cookies.js'

describe('cookies', () => {
  it('parses cookies into a map', () => {
    const parsed = parseCookies('a=1; b=two; c=three%20four')
    expect(parsed).toEqual({ a: '1', b: 'two', c: 'three four' })
  })

  it('serializes cookie options', () => {
    const cookie = serializeCookie('token', 'abc', {
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
      maxAge: 10,
      secure: true,
    })

    expect(cookie).toContain('token=abc')
    expect(cookie).toContain('Path=/')
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Lax')
    expect(cookie).toContain('Max-Age=10')
    expect(cookie).toContain('Secure')
  })

  it('creates a deletion cookie', () => {
    const cookie = deleteCookie('token', { path: '/', httpOnly: true, sameSite: 'Lax', secure: true })
    expect(cookie).toContain('token=')
    expect(cookie).toContain('Max-Age=0')
    expect(cookie).toContain('Path=/')
  })

  it('detects secure server URLs', () => {
    expect(isSecureServerUrl('https://example.com')).toBe(true)
    expect(isSecureServerUrl('http://localhost:3000')).toBe(false)
    expect(isSecureServerUrl('not-a-url')).toBe(false)
  })
})
