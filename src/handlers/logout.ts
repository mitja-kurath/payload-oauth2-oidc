import { OAuth2PluginOptions } from '../types.js'
import { deleteCookie, isSecureServerUrl } from './cookies.js'

export const handleLogout = (options: OAuth2PluginOptions): Response => {
  const response = new Response(null, {
    status: 302,
    headers: { Location: options.logoutRedirect || '/' },
  })

  const secure = options.cookieSecure ?? isSecureServerUrl(options.serverURL)
  const sameSite = options.cookieSameSite ?? 'Lax'
  response.headers.append('Set-Cookie', deleteCookie('oauth-token', {
    path: '/',
    httpOnly: true,
    sameSite,
    secure,
  }))
  
  return response
}
