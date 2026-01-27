import { PayloadRequest } from 'payload'
import { discovery, authorizationCodeGrant, fetchProtectedResource, randomState } from 'openid-client'
import jwt from 'jsonwebtoken'
import type { OAuth2PluginOptions, OAuthStrategy } from '../types.js'

export const handleCallback = async (
  req: PayloadRequest,
  strategy: OAuthStrategy,
  options: OAuth2PluginOptions,
): Promise<Response> => {
  try {
    const config = await discovery(new URL(strategy.issuerUrl), strategy.clientId, strategy.clientSecret)
    const cookies = req.headers.get('cookie') || ''
    const verifier = cookies.match(/oauth_verifier=([^;]+)/)?.[1]
    const state = cookies.match(/oauth_state=([^;]+)/)?.[1]

    const tokens = await authorizationCodeGrant(config, new URL(req.url!), {
      expectedState: state,
      pkceCodeVerifier: verifier,
    })

    const userInfoUrl = config.serverMetadata().userinfo_endpoint
    if (!userInfoUrl) throw new Error('No userinfo endpoint found')

    const uiRes = await fetchProtectedResource(config, tokens.access_token, new URL(userInfoUrl), 'GET')
    const userinfo = (await uiRes.json()) as Record<string, unknown>
    
    const mappedData = await strategy.userMapper(userinfo)
    const collectionSlug = options.userCollectionSlug || 'users'
    const sub = String(userinfo.sub)
    let email = typeof userinfo.email === 'string' ? userinfo.email.toLowerCase().trim() : `${sub}@oauth.local`

    // Suche oder erstelle User
    const { docs } = await req.payload.find({
      collection: collectionSlug,
      where: { or: [{ 'oauthLinks.sub': { equals: sub } }, { email: { equals: email } }] },
    })

    let user = docs[0]
    if (!user) {
      user = await req.payload.create({
        collection: collectionSlug,
        data: { ...mappedData, email, oauthLinks: [{ strategy: strategy.name, sub }], password: randomState() },
      })
    } else {
      user = await req.payload.update({
        collection: collectionSlug,
        id: user.id,
        data: { ...mappedData, oauthLinks: [{ strategy: strategy.name, sub }] },
      })
    }

    // Signiere Session-Token
    const sessionToken = jwt.sign({ id: String(user.id) }, req.payload.secret, { expiresIn: '7d' })
    const isLocal = options.serverURL.includes('localhost')

    const response = new Response(null, { status: 302, headers: { Location: options.successRedirect } })
    response.headers.append('Set-Cookie', `oauth-token=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${isLocal ? '' : '; Secure'}`)
    
    // Aufräumen
    response.headers.append('Set-Cookie', 'oauth_verifier=; Path=/; Max-Age=0')
    response.headers.append('Set-Cookie', 'oauth_state=; Path=/; Max-Age=0')

    return response
  } catch (err) {
    req.payload.logger.error(`[OAuth2 Plugin] Callback Error: ${err}`)
    return new Response(null, { status: 302, headers: { Location: options.failureRedirect } })
  }
}