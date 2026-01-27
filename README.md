# Payload OAuth2 Plugin

A lightweight, flexible OpenID Connect (OIDC) and OAuth2 integration for Payload CMS. 

> **Disclaimer:** This plugin supports OAuth2 on a payload backend. This implementation is rushed and unpolished, but may be improved later on. Use it at your own risk in production environments.

## Overview

This plugin allows you to integrate any OIDC-compliant identity provider (Google, GitHub, Keycloak, Auth0, Okta, etc.) into your Payload CMS application. It handles the full authentication flow, including PKCE for enhanced security, and automatically manages user creation and account linking.

## Features

- **Generic OIDC Support:** Works with any provider that supports discovery endpoints.
- **PKCE Enabled:** Modern security standards using Proof Key for Code Exchange.
- **Automatic User Provisioning:** Automatically creates users in your Payload `users` collection upon successful login.
- **Account Linking:** Smartly links OAuth identities to existing accounts via email or unique provider IDs (`sub`).
- **Custom User Mapping:** A flexible `userMapper` function lets you decide how claims from your provider (like `picture` or `username`) are saved to Payload fields.
- **Payload Native:** Implemented as a custom Auth Strategy, meaning it integrates with Payload's `req.user` and access control systems.

## Installation

```bash
# This is currently a manual installation. 
# Copy the plugin files into your project.
# Or use a Tool like Yalc
```

## Quick Start

```typescript
import { oAuth2 } from './plugins/oauth2'
import { buildConfig } from 'payload/config'

export default buildConfig({
  plugins: [
    oAuth2({
      serverURL: process.env.PAYLOAD_PUBLIC_SERVER_URL,
      successRedirect: '/admin',
      failureRedirect: '/login',
      strategies: [
        {
          name: 'google',
          issuerUrl: 'https://accounts.google.com',
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          scopes: ['openid', 'profile', 'email'],
          userMapper: (userinfo) => ({
            name: userinfo.name,
            avatarUrl: userinfo.picture,
          }),
        },
      ],
    }),
  ],
})
```

## How it Works

1. **Login:** Navigate to `/api/oauth/{strategy-name}/login`.
2. **Redirect:** The plugin generates a PKCE challenge and redirects the user to the provider.
3. **Callback:** The provider redirects back to `/api/oauth/{strategy-name}/callback`.
4. **Validation:** The plugin exchanges the code for tokens and fetches user info.
5. **Sync:** The plugin finds or creates a user in Payload and sets a secure JWT cookie.

## Planned Improvements (Roadmap)

While the current version is functional, the following features are planned for future releases:

- **State Management:** Move temporary PKCE/State data from cookies to a more robust server-side store or encrypted session.
- **Standardized Logout:** A dedicated endpoint to clear OAuth sessions and provider cookies simultaneously.
- **Refresh Token Support:** Implementation of offline access to keep users logged in longer without re-authentication.
- **Pre-configured Strategies:** "One-click" setups for popular providers like GitHub, Google, and Apple to reduce boilerplate.
- **Better UI Integration:** Built-in buttons for the Payload Admin UI login page.
- **Signed Cookies:** Move from plain-text cookies to signed/encrypted cookies for the transition state.

## License

MIT - See [LICENSE](LICENSE) for details.