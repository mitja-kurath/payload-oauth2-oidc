import { OAuthStrategy } from '../types.js'

export interface MidataPresetOptions {
  clientId: string
  clientSecret: string
  testMode?: boolean
  userMapper?: OAuthStrategy['userMapper']
}

export const midataPreset = (options: MidataPresetOptions): OAuthStrategy => ({
  name: 'midata',
  issuerUrl: options.testMode ? 'https://pbs.puzzle.ch' : 'https://db.scout.ch',
  clientId: options.clientId,
  clientSecret: options.clientSecret,
  scopes: ['openid', 'email', 'profile', 'with_roles'],
  userMapper: options.userMapper || (async (info) => {
    const roles = (info['roles'] as any[]) || []
    const isLeader = roles.some(r => 
      r.role_name?.toLowerCase().includes('leiter') || 
      r.role_name?.toLowerCase().includes('responsable')
    )
    
    return {
      role: isLeader ? 'leader' : 'member',
      firstName: info['given_name'],
      lastName: info['family_name'],
    }
  }),
})