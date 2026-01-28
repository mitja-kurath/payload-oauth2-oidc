import { discovery, buildAuthorizationUrl, randomPKCECodeVerifier, calculatePKCECodeChallenge, randomState } from 'openid-client'
import type { OAuth2PluginOptions, OAuthStrategy } from '../types.js'
import { isSecureServerUrl, serializeCookie } from './cookies.js'

export const handleLogin = async (
  strategy: OAuthStrategy,
  options: OAuth2PluginOptions,
): Promise<Response> => {
  const config = await discovery(new URL(strategy.issuerUrl), strategy.clientId, strategy.clientSecret)
  
  const verifier = randomPKCECodeVerifier()
  const challenge = await calculatePKCECodeChallenge(verifier)
  const state = randomState()
  
  const authUrl = buildAuthorizationUrl(config, {
    code_challenge: challenge,
    code_challenge_method: 'S256',
    redirect_uri: `${options.serverURL}/api/oauth/${strategy.name}/callback`,
    scope: strategy.scopes.join(' '),
    state,
  })

  const response = new Response(null, { status: 302, headers: { Location: authUrl.href } })
  const secure = isSecureServerUrl(options.serverURL)
  const cookieOptions = { path: '/', httpOnly: true, maxAge: 600, sameSite: 'Lax' as const, secure }
  
  response.headers.append('Set-Cookie', serializeCookie('oauth_verifier', verifier, cookieOptions))
  response.headers.append('Set-Cookie', serializeCookie('oauth_state', state, cookieOptions))
  
  return response
}
