import { OAuthStrategy } from "../types.js"

export interface GooglePresetOptions {
    clientId: string
    clientSecret: string
    userMapper?: OAuthStrategy['userMapper']
}

export const googlePreset = (options: GooglePresetOptions): OAuthStrategy => ({
  name: 'google',
  issuerUrl: 'https://accounts.google.com',
  clientId: options.clientId,
  clientSecret: options.clientSecret,
  scopes: ['openid', 'email', 'profile'],
  userMapper: options.userMapper || (async (info) => ({
    firstName: info['given_name'],
    lastName: info['family_name'],
  })),
})