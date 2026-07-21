import NextAuth from 'next-auth';
import Keycloak from 'next-auth/providers/keycloak';
import { eq } from 'drizzle-orm';

import { db } from '@/db';
import { users } from '@/db/schema';

if (!process.env.AUTH_URL && !process.env.NEXTAUTH_URL) {
    const defaultUrl = process.env.NODE_ENV === 'production'
        ? 'https://mycoursereviews.csclub.org.au'
        : 'http://localhost:3200';
    process.env.AUTH_URL = defaultUrl;
    process.env.NEXTAUTH_URL = defaultUrl;
}

declare module 'next-auth' {
    interface Session {
        accessToken?: string;
        user: {
            id: string;
            name?: string | null;
            email?: string | null;
            image?: string | null;
            role: 'admin' | 'user';
        };
    }
}

function extractRoles(account: any, profile: any): string[] {
    const rolesSet = new Set<string>();
    
    // 1. Try to decode access token if present
    if (account?.access_token) {
        try {
            const decoded = JSON.parse(Buffer.from(account.access_token.split('.')[1], 'base64').toString());
            const realmAccessRoles = decoded?.realm_access?.roles || [];
            const tokenRoles = decoded?.roles || [];
            realmAccessRoles.forEach((r: string) => rolesSet.add(r));
            tokenRoles.forEach((r: string) => rolesSet.add(r));
        } catch (e) {
            console.error('Error decoding access token for roles:', e);
        }
    }
    
    // 2. Fallback to profile realm_access and roles
    if (profile) {
        const realmAccessRoles = (profile as any)?.realm_access?.roles || [];
        const profileRoles = (profile as any)?.roles || [];
        realmAccessRoles.forEach((r: string) => rolesSet.add(r));
        profileRoles.forEach((r: string) => rolesSet.add(r));
    }
    
    return Array.from(rolesSet);
}

export const { handlers, signIn, signOut, auth } = NextAuth({
    providers: [
        Keycloak({
            clientId: process.env.KEYCLOAK_CLIENT_ID!,
            clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
            issuer: process.env.NEXT_PUBLIC_LOCAL_KEYCLOAK_URL
                ? `${process.env.NEXT_PUBLIC_LOCAL_KEYCLOAK_URL}/realms/cs-club`
                : process.env.KEYCLOAK_ISSUER!,
            ...(process.env.NEXT_PUBLIC_CONTAINER_KEYCLOAK_ENDPOINT
                ? {
                      jwks_endpoint: `${process.env.NEXT_PUBLIC_CONTAINER_KEYCLOAK_ENDPOINT}/realms/cs-club/protocol/openid-connect/certs`,
                      wellKnown: undefined,
                      authorization: {
                          params: {
                              scope: 'openid email profile',
                          },
                          url: `${process.env.NEXT_PUBLIC_LOCAL_KEYCLOAK_URL || 'https://auth.csclub.org.au'}/realms/cs-club/protocol/openid-connect/auth`,
                      },
                      token: `${process.env.NEXT_PUBLIC_CONTAINER_KEYCLOAK_ENDPOINT}/realms/cs-club/protocol/openid-connect/token`,
                      userinfo: `${process.env.NEXT_PUBLIC_CONTAINER_KEYCLOAK_ENDPOINT}/realms/cs-club/protocol/openid-connect/userinfo`,
                  }
                : {
                      authorization: {
                          params: {
                              scope: 'openid email profile',
                          },
                      },
                  }),
        }),
    ],
    trustHost: true,
    callbacks: {
        async signIn({ user, account, profile }) {
            if (!user.id || !user.email) return false;

            // Resolve and map standard CS Club roles to local DB roles
            const roles = extractRoles(account, profile);
            const role = roles.includes('committee') ? 'admin' : 'user';

            // Upsert Keycloak identity info into our local PostgreSQL database
            try {
                await db.insert(users)
                    .values({
                        id: user.id,
                        name: user.name || 'Adelaide Student',
                        role: role,
                    })
                    .onConflictDoUpdate({
                        target: users.id,
                        set: {
                            name: user.name || 'Adelaide Student',
                            role: role,
                        },
                    });
                return true;
            } catch (error) {
                console.error('Error syncing user on signIn:', error);
                return false;
            }
        },
        async jwt({ token, account, profile }) {
            if (account && profile) {
                token.accessToken = account.access_token;
                token.sub = profile.sub ?? undefined;
                token.roles = extractRoles(account, profile);
            } else if (token.accessToken && (!token.roles || !(token.roles as string[])?.includes('committee'))) {
                // If token.roles is missing or doesn't have committee, dynamically extract from access token for active sessions
                try {
                    const decoded = JSON.parse(Buffer.from((token.accessToken as string).split('.')[1], 'base64').toString());
                    const realmAccessRoles = decoded?.realm_access?.roles || [];
                    const tokenRoles = decoded?.roles || [];
                    token.roles = Array.from(new Set([
                        ...((token.roles as string[]) || []),
                        ...realmAccessRoles, 
                        ...tokenRoles
                    ]));
                } catch (e) {
                    console.error('Error decoding access token in subsequent jwt callback:', e);
                }
            }
            return token;
        },
        async session({ session, token }) {
            if (token.accessToken) {
                session.accessToken = token.accessToken as string;
            }
            if (token.sub) {
                session.user.id = token.sub as string;
            }
            // Map committee members to admin role for moderation page access
            let role: 'admin' | 'user' = (token.roles as string[])?.includes('committee') ? 'admin' : 'user';
            
            // Database role fallback check to ensure 100% correct roles synchronization
            if (role === 'user' && token.sub) {
                try {
                    const dbUsers = await db.select().from(users).where(eq(users.id, token.sub as string)).limit(1);
                    if (dbUsers[0]?.role === 'admin') {
                        role = 'admin';
                    }
                } catch (e) {
                    console.error('Error fetching user role from DB in session callback:', e);
                }
            }
            
            session.user.role = role;
            return session;
        },
    },
    pages: {
        signIn: '/auth/signin',
        error: '/auth/error',
    },
});
