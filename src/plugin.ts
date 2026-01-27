import {
  type CollectionConfig,
  type Config,
  type Field,
  type PayloadRequest,
  type Plugin,
} from 'payload'
import type { OAuth2PluginOptions } from './types.js'
import { handleCallback, handleLogin } from './handler.js'
import { customOAuthStrategy } from './strategy.js'

export const oAuth2 =
  (pluginOptions: OAuth2PluginOptions): Plugin =>
  (incomingConfig: Config): Config => {
    if (pluginOptions.enabled === false) return incomingConfig
    const config = { ...incomingConfig }
    const { strategies, userCollectionSlug = 'users' } = pluginOptions

    config.collections = (config.collections || []).map((col): CollectionConfig => {
      if (col.slug === userCollectionSlug) {
        return {
          ...col,
          auth: {
            ...(typeof col.auth === 'object' ? col.auth : {}),
            strategies: [
              ...(typeof col.auth === 'object' && col.auth.strategies ? col.auth.strategies : []),
              customOAuthStrategy(userCollectionSlug),
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

    const endpoints = strategies.flatMap((strategy) => [
      {
        path: `/oauth/${strategy.name}/login`,
        method: 'get' as const,
        handler: () => handleLogin(strategy, pluginOptions),
      },
      {
        path: `/oauth/${strategy.name}/callback`,
        method: 'get' as const,
        handler: (req: PayloadRequest) => handleCallback(req, strategy, pluginOptions),
      },
    ])

    config.endpoints = [...(config.endpoints || []), ...endpoints]
    return config
  }
