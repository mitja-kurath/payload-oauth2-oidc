import { PayloadRequest } from 'payload'
import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  discovery,
  fetchProtectedResource,
  randomPKCECodeVerifier,
  randomState,
} from 'openid-client'
import jwt from 'jsonwebtoken'
import type { OAuth2PluginOptions, OAuthStrategy } from './types.js'

export const handleLogin = async (
  strategy: OAuthStrategy,
  options: OAuth2PluginOptions,
): Promise<Response> => {
  const config = await discovery(
    new URL(strategy.issuerUrl),
    strategy.clientId,
    strategy.clientSecret,
  )
  const code_verifier = randomPKCECodeVerifier()
  const code_challenge = await calculatePKCECodeChallenge(code_verifier)
  const state = randomState()
  const redirect_uri = `${options.serverURL}/api/oauth/${strategy.name}/callback`

  const authUrl = buildAuthorizationUrl(config, {
    code_challenge,
    code_challenge_method: 'S256',
    redirect_uri,
    scope: strategy.scopes.join(' '),
    state,
  })

  const response = new Response(null, { status: 302, headers: { Location: authUrl.href } })
  const cookieOptions = 'Path=/; HttpOnly; Max-Age=600; SameSite=Lax'
  response.headers.append('Set-Cookie', `oauth_verifier=${code_verifier}; ${cookieOptions}`)
  response.headers.append('Set-Cookie', `oauth_state=${state}; ${cookieOptions}`)
  return response
}

export const handleCallback = async (
  req: PayloadRequest,
  strategy: OAuthStrategy,
  options: OAuth2PluginOptions,
): Promise<Response> => {
  try {
    const config = await discovery(
      new URL(strategy.issuerUrl),
      strategy.clientId,
      strategy.clientSecret,
    )
    const cookies = req.headers.get('cookie') || ''
    const code_verifier = cookies.match(/oauth_verifier=([^;]+)/)?.[1]
    const expected_state = cookies.match(/oauth_state=([^;]+)/)?.[1]

    const tokens = await authorizationCodeGrant(config, new URL(req.url!), {
      expectedState: expected_state,
      pkceCodeVerifier: code_verifier,
    })

    const userInfoUrl = config.serverMetadata().userinfo_endpoint
    if (!userInfoUrl) throw new Error('No userinfo endpoint')

    const uiRes = await fetchProtectedResource(
      config,
      tokens.access_token,
      new URL(userInfoUrl),
      'GET',
    )
    const userinfo = (await uiRes.json()) as Record<string, unknown>
    const mappedData = await strategy.userMapper(userinfo)
    const collectionSlug = options.userCollectionSlug || 'users'

    const sub = String(userinfo.sub)
    let email =
      typeof userinfo.email === 'string'
        ? userinfo.email.toLowerCase().trim()
        : `${sub}@oauth.local`

    // Suche nach SUB ODER Email
    const { docs } = await req.payload.find({
      collection: collectionSlug,
      where: { or: [{ 'oauthLinks.sub': { equals: sub } }, { email: { equals: email } }] },
    })

    let user = docs[0]
    if (!user) {
      user = await req.payload.create({
        collection: collectionSlug,
        data: {
          ...mappedData,
          email,
          oauthLinks: [{ strategy: strategy.name, sub }],
          password: randomState(),
        },
      })
    } else {
      user = await req.payload.update({
        collection: collectionSlug,
        id: user.id,
        data: { ...mappedData, oauthLinks: [{ strategy: strategy.name, sub }] },
      })
    }

    // UNSER EIGENES TOKEN SIGNIEREN (HS256 Standard)
    const oauthToken = jwt.sign({ id: String(user.id) }, req.payload.secret, { expiresIn: '7d' })

    const response = new Response(null, {
      status: 302,
      headers: { Location: options.successRedirect },
    })
    const isLocal = options.serverURL.includes('localhost')
    const cookieVal = `oauth-token=${oauthToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${isLocal ? '' : '; Secure'}`

    response.headers.append('Set-Cookie', cookieVal)
    response.headers.append('Set-Cookie', 'oauth_verifier=; Path=/; Max-Age=0')
    response.headers.append('Set-Cookie', 'oauth_state=; Path=/; Max-Age=0')
    return response
  } catch (err) {
    req.payload.logger.error(`[OAuth2 Plugin] ${err}`)
    return new Response(null, { status: 302, headers: { Location: options.failureRedirect } })
  }
}
