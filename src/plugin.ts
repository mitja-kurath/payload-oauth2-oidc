import { type CollectionConfig, type Config, type Field, type PayloadRequest, type Plugin } from 'payload'
import type { OAuth2PluginOptions } from './types.js'
import { handleLogin } from './handlers/login.js'
import { handleCallback } from './handlers/callback.js'
import { handleLogout } from './handlers/logout.js'
import { customOAuthStrategy } from './strategy.js'

export const oAuth2 = (pluginOptions: OAuth2PluginOptions): Plugin => 
  (incomingConfig: Config): Config => {
    if (pluginOptions.enabled === false) return incomingConfig
    
    const config = { ...incomingConfig }
    const collectionSlug = pluginOptions.userCollectionSlug || 'users'

    config.collections = (config.collections || []).map((col): CollectionConfig => {
      if (col.slug === collectionSlug) {
        return {
          ...col,
          auth: {
            ...(typeof col.auth === 'object' ? col.auth : {}),
            strategies: [
              ...(typeof col.auth === 'object' && col.auth.strategies ? col.auth.strategies : []),
              customOAuthStrategy(collectionSlug),
            ],
          },
          fields: [
            ...col.fields,
            {
              name: 'oauthLinks',
              type: 'array',
              admin: { hidden: true },
              fields: [
                { name: 'strategy', type: 'text' },
                { name: 'sub', type: 'text' },
              ],
            },
          ],
        }
      }
      return col
    })

    const strategyEndpoints = pluginOptions.strategies.flatMap((s) => [
      { path: `/oauth/${s.name}/login`, method: 'get' as const, handler: () => handleLogin(s, pluginOptions) },
      { path: `/oauth/${s.name}/callback`, method: 'get' as const, handler: (req: PayloadRequest) => handleCallback(req, s, pluginOptions) },
    ])

    const globalEndpoints = [
      { path: '/oauth/logout', method: 'get' as const, handler: () => handleLogout(pluginOptions) }
    ]

    config.endpoints = [...(config.endpoints || []), ...strategyEndpoints, ...globalEndpoints]

    return config
  }