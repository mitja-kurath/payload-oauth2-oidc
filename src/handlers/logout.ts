import { OAuth2PluginOptions } from '../types.js'

export const handleLogout = (options: OAuth2PluginOptions): Response => {
  const response = new Response(null, {
    status: 302,
    headers: { Location: options.logoutRedirect || '/' },
  })

  response.headers.append('Set-Cookie', 'oauth-token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
  
  return response
}