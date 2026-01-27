import { AuthStrategy } from 'payload'
import jwt from 'jsonwebtoken'

export const customOAuthStrategy = (collectionSlug: string): AuthStrategy => ({
  name: 'custom-oauth-strategy',
  authenticate: async ({ payload, headers }) => {
    const cookieHeader = headers.get('cookie') || ''

    // Sichereres Cookie-Parsing
    const token = cookieHeader
      .split('; ')
      .find((row) => row.startsWith('oauth-token='))
      ?.split('=')[1]

    if (!token) {
      return { user: null }
    }

    try {
      // Wir nutzen das Secret direkt vom Payload-Objekt, das garantiert Übereinstimmung
      const decoded = jwt.verify(token, payload.secret) as { id: string }

      // Den User in der Datenbank suchen
      const user = await payload.findByID({
        collection: collectionSlug,
        id: decoded.id,
        depth: 0,
      })

      if (user) {
        // Erfolg! Wir geben den User an Payload zurück
        return {
          user: {
            ...user,
            collection: collectionSlug,
            _strategy: 'custom-oauth-strategy',
          },
        }
      }

      payload.logger.warn(`[OAuth Strategy] User ID ${decoded.id} nicht in DB gefunden.`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      payload.logger.error(`[OAuth Strategy] JWT Fehler: ${msg}`)
    }

    return { user: null }
  },
})
