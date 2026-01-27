# Payload OAuth2 Plugin (OIDC)

A professional, lightweight, and highly flexible OpenID Connect (OIDC) and OAuth2 integration for **Payload CMS v3**. 

Unlike other plugins that try to "hack" Payload's internal authentication, this plugin implements a **Native Custom Auth Strategy**. It allows you to identify users via secure, signed cookies while working perfectly with Payload's existing access control and `req.user` systems.

## Key Features

- **Payload v3 Native:** Specifically architected for the Next.js / React Server Components environment of Payload 3.x.
- **Generic OIDC Support:** Works with any OIDC-compliant provider (Google, GitHub, Keycloak, Auth0, and **Hitobito/MiData**).
- **Multi-Strategy:** Configure multiple identity providers (e.g., "Login with Google" AND "Login with MiData") simultaneously.
- **User Provisioning & Sync:** 
  - **Auto-Registration:** Creates new users on their first login.
  - **Registration Control:** Toggle `allowRegistration` to restrict access to pre-existing users only.
  - **Automatic Profile Sync:** Updates user data (roles, names, etc.) in your database on every login.
- **Smart Account Linking:** Automatically matches OAuth identities to existing Payload accounts via email or Provider ID (`sub`).
- **Modern Security:** Built-in PKCE (Proof Key for Code Exchange) support and secure, `HttpOnly` cookie session management.
- **Built-in Logout:** A global logout endpoint that clears session cookies across the application.

## Installation

```bash
pnpm add payload-oauth2 openid-client jsonwebtoken
# or
npm install payload-oauth2 openid-client jsonwebtoken
```

## Quick Start

Register the plugin in your `payload.config.ts`:

```typescript
import { oAuth2 } from 'payload-oauth2'
import { buildConfig } from 'payload'

export default buildConfig({
  // ... collections, etc.
  plugins: [
    oAuth2({
      enabled: true,
      serverURL: process.env.NEXT_PUBLIC_SERVER_URL!, // e.g., http://localhost:3000
      successRedirect: `${process.env.FRONTEND_URL}/dashboard`,
      failureRedirect: `${process.env.FRONTEND_URL}/login?error=failed`,
      logoutRedirect: `${process.env.FRONTEND_URL}/`,
      allowRegistration: true, // Set to false for "Invite-only" systems
      strategies: [
        {
          name: 'midata',
          issuerUrl: 'https://db.scout.ch',
          clientId: process.env.MIDATA_CLIENT_ID!,
          clientSecret: process.env.MIDATA_CLIENT_SECRET!,
          scopes: ['openid', 'email', 'profile', 'with_roles'],
          // Transform OIDC claims to Payload user fields
          userMapper: async (userinfo) => {
            const roles = (userinfo['roles'] as any[]) || []
            return {
              role: roles.some(r => r.name.includes('Leiter')) ? 'leader' : 'member',
              firstName: userinfo.given_name,
              lastName: userinfo.family_name,
            }
          },
        },
      ],
    }),
  ],
})
```

## Plugin Options

| Option | Type | Description |
| :--- | :--- | :--- |
| `strategies` | `OAuthStrategy[]` | Array of OIDC provider configurations. |
| `serverURL` | `string` | The base URL of your Payload backend. |
| `successRedirect` | `string` | URL to redirect users to after a successful login. |
| `failureRedirect` | `string` | URL to redirect users to if an error occurs. |
| `logoutRedirect` | `string` | URL to redirect users to after logging out. |
| `allowRegistration` | `boolean` | If `false`, only users already in the DB can log in. Default: `true`. |
| `userCollectionSlug`| `string` | The slug of your auth collection. Default: `'users'`. |

## REST API Endpoints

The plugin automatically exposes the following endpoints:

- `GET /api/oauth/:strategy/login` - Redirects the user to the OIDC provider.
- `GET /api/oauth/:strategy/callback` - Internal handler for the OAuth handshake.
- `GET /api/oauth/logout` - Clears the session and redirects to `logoutRedirect`.

## Frontend Integration

When calling Payload APIs from your frontend, you must include credentials to send the `oauth-token` cookie.

### Fetch Example
```javascript
const response = await fetch('http://localhost:3000/api/users/me', {
  method: 'GET',
  credentials: 'include', // CRITICAL: This sends the session cookie
});
const data = await response.json();
console.log('User session:', data.user);
```

### Angular (HttpClient) Example
```typescript
this.http.get('/api/users/me', { withCredentials: true }).subscribe(...)
```

## Account Linking Architecture

When a user logs in, the plugin follows this logic:
1. Searches for a user with the same `oauthLinks.sub` (Provider ID).
2. If not found, searches for a user with the same verified `email`.
3. If found, it **links** the OAuth identity to that account and updates the profile.
4. If not found and `allowRegistration` is `true`, it creates a new user document.

## Technical Details

- **Session Management:** Uses JWTs signed with your `PAYLOAD_SECRET` stored in an `HttpOnly`, `SameSite=Lax` cookie named `oauth-token`.
- **Custom Strategy:** Registers an authentication strategy that Payload calls on every request to populate `req.user`.

## License

MIT - Developed by **Mitja Kurath**. Use freely in your projects!
