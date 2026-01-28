import { describe, expect, it } from 'vitest'
import type { Config } from 'payload'
import { oAuth2 } from './plugin.js'

const baseOptions = {
  enabled: true,
  strategies: [],
  serverURL: 'https://example.com',
  successRedirect: 'https://example.com/success',
  failureRedirect: 'https://example.com/failure',
}

describe('oAuth2 plugin', () => {
  it('adds oauthLinks when missing', () => {
    const plugin = oAuth2(baseOptions)
    const config = plugin({
      collections: [
        {
          slug: 'users',
          auth: true,
          fields: [{ name: 'email', type: 'text' }],
        },
      ],
    } as Config)

    const fields = config.collections?.[0]?.fields || []
    const matches = fields.filter((field: any) => field?.name === 'oauthLinks')
    expect(matches).toHaveLength(1)
  })

  it('does not duplicate oauthLinks if already present', () => {
    const plugin = oAuth2(baseOptions)
    const config = plugin({
      collections: [
        {
          slug: 'users',
          auth: true,
          fields: [
            { name: 'email', type: 'text' },
            { name: 'oauthLinks', type: 'array', fields: [] },
          ],
        },
      ],
    } as Config)

    const fields = config.collections?.[0]?.fields || []
    const matches = fields.filter((field: any) => field?.name === 'oauthLinks')
    expect(matches).toHaveLength(1)
  })
})
