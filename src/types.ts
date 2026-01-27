export interface OAuthStrategy {
  name: string
  issuerUrl: string
  clientId: string
  clientSecret: string
  scopes: string[]
  userMapper: (
    userinfo: Record<string, unknown>,
  ) => Promise<Record<string, unknown>> | Record<string, unknown>
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
}