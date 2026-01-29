import { AuthStrategy } from 'payload'
import jwt from 'jsonwebtoken'

export const customOAuthStrategy = (collectionSlug: string, cookieName: string): AuthStrategy => ({
  name: 'custom-oauth-strategy',
  authenticate: async ({ payload, headers }) => {
    const cookies = headers.get('cookie') || ''
    const token = cookies.split('; ').find(row => row.startsWith(`${cookieName}=`))?.split('=')[1]

    if (!token) return { user: null }

    try {
      const decoded = jwt.verify(token, payload.secret) as { id: string }
      const user = await payload.findByID({ collection: collectionSlug, id: decoded.id, depth: 0 })

      if (user) return { user: { ...user, collection: collectionSlug } }
    } catch (err) {
      payload.logger.error(`[OAuth Strategy] Invalid Session: ${err instanceof Error ? err.message : 'JWT Error'}`)
    }
    return { user: null }
  },
})