import { 
  discovery, 
  buildAuthorizationUrl, 
  randomPKCECodeVerifier, 
  calculatePKCECodeChallenge, 
  randomState,
  type DiscoveryConfig
} from 'openid-client'
import type { OAuth2PluginOptions, OAuthStrategy } from '../types.js'
import { isSecureServerUrl, serializeCookie } from './cookies.js'

const discoveryCache = new Map<string, { config: DiscoveryConfig; expires: number }>()

export const handleLogin = async (
  strategy: OAuthStrategy,
  options: OAuth2PluginOptions,
): Promise<Response> => {
  const cacheKey = strategy.issuerUrl
  let cached = discoveryCache.get(cacheKey)
  
  if (!cached || cached.expires < Date.now()) {
    const discovered = await discovery(
      new URL(strategy.issuerUrl),
      strategy.clientId,
      strategy.clientSecret
    )
    cached = { config: discovered, expires: Date.now() + 1000 * 60 * 60 } // 1 hour
    discoveryCache.set(cacheKey, cached)
  }

  const config = cached.config
  
  const verifier = randomPKCECodeVerifier()
  const challenge = await calculatePKCECodeChallenge(verifier)
  const state = randomState()
  
  const authUrl = buildAuthorizationUrl(config, {
    code_challenge: challenge,
    code_challenge_method: 'S256',
    redirect_uri: `${options.serverURL}/api/oauth/${strategy.name}/callback`,
    scope: strategy.scopes.join(' '),
    state,
    ...strategy.authorizationParameters,
  })

  const response = new Response(null, { status: 302, headers: { Location: authUrl.href } })
  const secure = options.cookieSecure ?? isSecureServerUrl(options.serverURL)
  const sameSite = options.cookieSameSite ?? 'Lax'
  const cookieOptions = { path: '/', httpOnly: true, maxAge: 600, sameSite, secure }
  
  response.headers.append('Set-Cookie', serializeCookie('oauth_verifier', verifier, cookieOptions))
  response.headers.append('Set-Cookie', serializeCookie('oauth_state', state, cookieOptions))
  
  return response
}
