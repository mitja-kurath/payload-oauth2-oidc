import type { PayloadRequest } from 'payload'

export interface OAuthStrategy {
  name: string
  issuerUrl: string
  clientId: string
  clientSecret: string
  scopes: string[]
  userMapper?: (
    userinfo: Record<string, unknown>,
    context: { req: PayloadRequest },
  ) => Promise<Record<string, unknown>> | Record<string, unknown>
  /**
   * Additional parameters to send to the authorization endpoint
   */
  authorizationParameters?: Record<string, string>
}

export interface OAuth2PluginOptions {
  strategies: OAuthStrategy[]
  serverURL: string
  successRedirect: string
  failureRedirect: string
  logoutRedirect?: string
  userCollectionSlug?: string
  enabled?: boolean
  allowRegistration?: boolean
  cookieSecure?: boolean
  cookieSameSite?: 'Lax' | 'Strict' | 'None'
  /**
   * Custom name for the session cookie.
   * @default 'payload-oauth-token'
   */
  cookieName?: string
  linkByEmail?: boolean
  requireEmailVerified?: boolean
  /**
   * Token expiration in seconds.
   * @default 604800 (7 days)
   */
  tokenExpiration?: number
  /**
   * Callback called after successful login but before redirecting.
   */
  afterLogin?: (user: any, context: { req: PayloadRequest; tokens: any }) => Promise<void> | void
}
