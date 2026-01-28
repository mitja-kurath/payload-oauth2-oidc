import { PayloadRequest } from 'payload'
import { 
  discovery, 
  authorizationCodeGrant, 
  fetchProtectedResource, 
  randomState 
} from 'openid-client'
import jwt from 'jsonwebtoken'
import type { OAuth2PluginOptions, OAuthStrategy } from '../types.js'
import { deleteCookie, isSecureServerUrl, parseCookies, serializeCookie } from './cookies.js'

export const handleCallback = async (
  req: PayloadRequest,
  strategy: OAuthStrategy,
  options: OAuth2PluginOptions,
): Promise<Response> => {
  try {
    const config = await discovery(
      new URL(strategy.issuerUrl),
      strategy.clientId,
      strategy.clientSecret
    )

    const cookies = parseCookies(req.headers.get('cookie') || '')
    const verifier = cookies.oauth_verifier
    const state = cookies.oauth_state

    if (!verifier || !state) {
      req.payload.logger.warn('[OAuth2] Missing PKCE verifier or state cookie')
      return new Response(null, {
        status: 302,
        headers: { Location: `${options.failureRedirect}?error=missing_state` },
      })
    }

    const tokens = await authorizationCodeGrant(config, new URL(req.url!), {
      expectedState: state,
      pkceCodeVerifier: verifier,
    })

    const userInfoUrl = config.serverMetadata().userinfo_endpoint
    if (!userInfoUrl) throw new Error('No userinfo endpoint found on provider')

    const uiRes = await fetchProtectedResource(
      config, 
      tokens.access_token, 
      new URL(userInfoUrl), 
      'GET'
    )
    const userinfo = (await uiRes.json()) as Record<string, unknown>

    const mappedData = await strategy.userMapper(userinfo)
    const collectionSlug = options.userCollectionSlug || 'users'
    const sub = String(userinfo.sub)
    const emailRaw = typeof userinfo.email === 'string'
      ? userinfo.email.toLowerCase().trim()
      : undefined
    const emailVerifiedFlag = userinfo.email_verified
    const emailVerified = emailVerifiedFlag === true || emailVerifiedFlag === 'true'
    const canLinkByEmail = options.linkByEmail !== false
      && !!emailRaw
      && (options.requireEmailVerified ? emailVerified : emailVerifiedFlag !== false && emailVerifiedFlag !== 'false')
    const email = emailRaw || `${sub}@oauth.local`

    if (emailRaw && options.requireEmailVerified && !emailVerified) {
      req.payload.logger.warn(`[OAuth2] Email not verified for: ${emailRaw}`)
    }

    const { docs } = await req.payload.find({
      collection: collectionSlug,
      where: {
        or: [
          { 'oauthLinks.sub': { equals: sub } },
          ...(canLinkByEmail ? [{ email: { equals: email } }] : []),
        ]
      },
    })

    let user = docs[0]

    if (!user) {
      if (options.allowRegistration === false) {
        req.payload.logger.warn(`[OAuth2] Registration denied for: ${email}`)
        return new Response(null, {
          status: 302,
          headers: { Location: `${options.failureRedirect}?error=registration_disabled` },
        })
      }

      user = await req.payload.create({
        collection: collectionSlug,
        data: {
          ...mappedData,
          email,
          oauthLinks: [{ strategy: strategy.name, sub }],
          password: randomState(),
        },
      })
      req.payload.logger.info(`[OAuth2] New User Created: ${email}`)
    } else {
      user = await req.payload.update({
        collection: collectionSlug,
        id: user.id,
        data: {
          ...mappedData,
          oauthLinks: [
            ...(user.oauthLinks?.filter((l: any) => l.strategy !== strategy.name) || []),
            { strategy: strategy.name, sub }
          ],
        },
      })
      req.payload.logger.info(`[OAuth2] Profile synced: ${user.email}`)
    }

    const sessionToken = jwt.sign(
      { id: String(user.id) }, 
      req.payload.secret, 
      { expiresIn: '7d' }
    )

    const response = new Response(null, {
      status: 302,
      headers: { Location: options.successRedirect },
    })

    const secure = options.cookieSecure ?? isSecureServerUrl(options.serverURL)
    const sameSite = options.cookieSameSite ?? 'Lax'
    const tokenCookie = serializeCookie('oauth-token', sessionToken, {
      path: '/',
      httpOnly: true,
      sameSite,
      maxAge: 604800,
      secure,
    })

    response.headers.append('Set-Cookie', tokenCookie)

    const shortLivedCookieOptions = { path: '/', httpOnly: true, sameSite, secure }
    response.headers.append('Set-Cookie', deleteCookie('oauth_verifier', shortLivedCookieOptions))
    response.headers.append('Set-Cookie', deleteCookie('oauth_state', shortLivedCookieOptions))

    return response

  } catch (err) {
    req.payload.logger.error(`[OAuth2 Plugin] Callback Error: ${err}`)
    return new Response(null, {
      status: 302,
      headers: { Location: `${options.failureRedirect}?error=callback_failed` },
    })
  }
}
