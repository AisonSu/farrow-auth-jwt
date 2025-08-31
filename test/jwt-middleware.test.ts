import { describe, it, expect, beforeEach } from 'vitest'
import request from 'supertest'
import { Http, Response } from 'farrow-http'
import { createJWTMiddleware, createJwtDataCtx, JWTErrorContext, WhitelistRule } from '../src/jwt-middleware'
import * as jwt from 'jsonwebtoken'

// Test user data type
interface TestUser {
  id: number
  username: string
  role: 'admin' | 'user'
}

// Test configuration
const TEST_SECRET = 'test-secret-key'
const REFRESH_SECRET = 'test-refresh-secret'

describe('JWT Middleware', () => {
  let app: ReturnType<typeof Http>
  let userContext: ReturnType<typeof createJwtDataCtx<TestUser>>

  beforeEach(() => {
    app = Http()
    userContext = createJwtDataCtx<TestUser>()
  })

  describe('Basic JWT functionality', () => {
    it('should reject requests without token', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        const user = userContext.get()
        if (!user) {
          return Response.status(401).json({ error: 'Unauthorized' })
        }
        return Response.json(user as any)
      })

      const res = await request(app.server())
        .get('/protected')
        .expect(401)  // Middleware returns 401 directly when no token

      expect(res.body).toEqual({ error: 'No token' })
    })

    it('should accept valid token', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        const user = userContext.get()
        return Response.json({ user } as any)
      })

      // Create a valid token
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })

      const res = await request(app.server())
        .get('/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)

      expect(res.body.user).toMatchObject(testUser)
    })

    it('should reject expired token', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        return Response.json({ message: 'Protected' })
      })

      // Create an expired token
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '-1h' }) // Negative value means expired

      const res = await request(app.server())
        .get('/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(401)

      expect(res.body.error).toBe('Token expired')
    })

    it('should reject invalid token', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        return Response.json({ message: 'Protected' })
      })

      const res = await request(app.server())
        .get('/protected')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401)

      expect(res.body.error).toBe('Invalid token')
    })

    it('should support getting token from cookie', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        const user = userContext.get()
        return Response.json({ user } as any)
      })

      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })

      const res = await request(app.server())
        .get('/protected')
        .set('Cookie', `token=${token}`)
        .expect(200)

      expect(res.body.user).toMatchObject(testUser)
    })

    it('should support getting token from query parameters', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        const user = userContext.get()
        return Response.json({ user } as any)
      })

      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })

      const res = await request(app.server())
        .get(`/protected?token=${token}`)
        .expect(200)

      expect(res.body.user).toMatchObject(testUser)
    })
  })

  describe('Whitelist functionality', () => {
    it('should allow access to whitelisted paths (no token required)', async () => {
      const whitelist: WhitelistRule[] = [
        '/public',
        { path: '/api/docs', methods: ['GET'] }
      ]

      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        whitelist
      })

      app.use(jwtMiddleware)
      
      app.get('/public').use(() => {
        return Response.json({ message: 'Public endpoint' })
      })

      app.get('/api/docs').use(() => {
        return Response.json({ message: 'API Documentation' })
      })

      // Access whitelisted paths without token
      const res1 = await request(app.server())
        .get('/public')
        .expect(200)
      
      expect(res1.body.message).toBe('Public endpoint')

      const res2 = await request(app.server())
        .get('/api/docs')
        .expect(200)
      
      expect(res2.body.message).toBe('API Documentation')
    })

    it('should handle whitelist rules with method restrictions correctly', async () => {
      const whitelist: WhitelistRule[] = [
        { path: '/auth/login', methods: ['POST'] }
      ]

      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        whitelist
      })

      app.use(jwtMiddleware)
      
      // POST /auth/login should be allowed (in whitelist)
      app.post('/auth/login').use(() => {
        return Response.json({ message: 'Login endpoint' })
      })

      // GET /auth/login should require authentication (not in whitelist)
      app.get('/auth/login').use(() => {
        const user = userContext.get()
        if (!user) {
          return Response.status(401).json({ error: 'Unauthorized' })
        }
        return Response.json({ message: 'Should need auth' })
      })

      // POST request should succeed
      const res1 = await request(app.server())
        .post('/auth/login')
        .expect(200)
      
      expect(res1.body.message).toBe('Login endpoint')

      // GET request should fail (middleware returns 401 directly when no token)
      const res2 = await request(app.server())
        .get('/auth/login')
        .expect(401)
      
      expect(res2.body.error).toBe('No token')
    })

    it('should support wildcard paths', async () => {
      const whitelist: WhitelistRule[] = [
        '/public/{*path}',  // path-to-regexp v8 syntax
        '/api/v:version/docs'
      ]

      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        whitelist
      })

      app.use(jwtMiddleware)
      
      app.get('/public/info').use(() => {
        return Response.json({ message: 'Public info' })
      })

      app.get('/public/about').use(() => {
        return Response.json({ message: 'Public about' })
      })

      app.get('/api/v1/docs').use(() => {
        return Response.json({ message: 'API v1 docs' })
      })

      app.get('/api/v2/docs').use(() => {
        return Response.json({ message: 'API v2 docs' })
      })

      // All paths matching wildcards should be accessible
      const res1 = await request(app.server())
        .get('/public/info')
        .expect(200)
      
      const res2 = await request(app.server())
        .get('/public/about')
        .expect(200)

      const res3 = await request(app.server())
        .get('/api/v1/docs')
        .expect(200)

      const res4 = await request(app.server())
        .get('/api/v2/docs')
        .expect(200)
      
      expect(res1.body.message).toBe('Public info')
      expect(res2.body.message).toBe('Public about')
      expect(res3.body.message).toBe('API v1 docs')
      expect(res4.body.message).toBe('API v2 docs')
    })
  })

  describe('Token signing and refreshing', () => {
    it('should be able to sign new tokens', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        whitelist: ['/auth/login']
      })

      app.use(jwtMiddleware)
      
      app.post('/auth/login').use(() => {
        const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
        userContext.set(testUser)
        return userContext.sign()
      })

      const res = await request(app.server())
        .post('/auth/login')
        .expect(200)
      
      expect(res.body).toHaveProperty('token')
      
      // Verify if the signed token is valid
      const decoded = jwt.verify(res.body.token, TEST_SECRET) as TestUser
      expect(decoded.username).toBe('testuser')
    })

    it('should be able to sign tokens with data', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        whitelist: ['/auth/login']
      })

      app.use(jwtMiddleware)
      
      app.post('/auth/login').use(() => {
        const testUser: TestUser = { id: 2, username: 'admin', role: 'admin' }
        return userContext.sign(testUser)
      })

      const res = await request(app.server())
        .post('/auth/login')
        .expect(200)
      
      expect(res.body).toHaveProperty('token')
      
      // Verify the signed token contains correct data
      const decoded = jwt.verify(res.body.token, TEST_SECRET) as TestUser
      expect(decoded.username).toBe('admin')
      expect(decoded.role).toBe('admin')
    })

    it('should be able to refresh tokens', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '15m' }
        },
        refresh: {
          secret: REFRESH_SECRET,
          signOptions: { expiresIn: '7d' }
        },
        jwtDataCtx: userContext,
        whitelist: ['/auth/login']
      })

      app.use(jwtMiddleware)
      
      // Login to get token and refresh token
      app.post('/auth/login').use(() => {
        const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
        return userContext.sign(testUser)
      })

      // Refresh token
      app.post('/auth/refresh').use(async () => {
        return await userContext.refresh()
      })

      // 1. Login first to get tokens
      const loginRes = await request(app.server())
        .post('/auth/login')
        .expect(200)
      
      expect(loginRes.body).toHaveProperty('token')
      expect(loginRes.body).toHaveProperty('refreshToken')

      const { refreshToken } = loginRes.body

      // 2. Use refresh token to refresh (requires an access token first)
      const refreshRes = await request(app.server())
        .post('/auth/refresh')
        .set('Authorization', `Bearer ${loginRes.body.token}`)
        .send({ refreshToken })
        .expect(200)
      
      expect(refreshRes.body).toHaveProperty('token')
      expect(refreshRes.body).toHaveProperty('refreshToken')

      // 3. Verify if new token is valid
      const decoded = jwt.verify(refreshRes.body.token, TEST_SECRET) as TestUser
      expect(decoded.username).toBe('testuser')
    })

    it('should reject invalid refresh token', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '15m' }
        },
        refresh: {
          secret: REFRESH_SECRET,
          signOptions: { expiresIn: '7d' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      
      app.post('/auth/refresh').use(async () => {
        try {
          return await userContext.refresh()
        } catch (error: any) {
          return Response.status(400).json({ error: error.message })
        }
      })

      // Use invalid refresh token (requires a valid access token first)
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })
      
      const res = await request(app.server())
        .post('/auth/refresh')
        .set('Authorization', `Bearer ${token}`)
        .send({ refreshToken: 'invalid-refresh-token' })
        .expect(401)
      
      expect(res.body.error).toBe('Invalid refresh token')
    })
  })

  describe('Token revocation functionality', () => {
    it('should be able to revoke tokens', async () => {
      const revokedTokens = new Set<string>()

      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        isRevoked: async (payload: TestUser) => {
          return revokedTokens.has(payload.username)
        }
      })

      app.use(jwtMiddleware)
      
      app.get('/protected').use(() => {
        const user = userContext.get()
        return Response.json({ user } as any)
      })

      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })

      // 1. Token should be initially valid
      const res1 = await request(app.server())
        .get('/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
      
      expect(res1.body.user).toMatchObject(testUser)

      // 2. Revoke the token
      revokedTokens.add('testuser')

      // 3. Token should be rejected
      const res2 = await request(app.server())
        .get('/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(401)
      
      expect(res2.body.error).toBe('Token has been revoked')
    })
  })

  describe('Error context', () => {
    it('should set error context correctly', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext
      })

      app.use(jwtMiddleware)
      
      app.get('/check-error').use(() => {
        const error = JWTErrorContext.get()
        return Response.json({ error })
      })

      // 1. When no token (now returns 401 directly)
      const res1 = await request(app.server())
        .get('/check-error')
        .expect(401)
      
      expect(res1.body.error).toBe('No token')

      // 2. When invalid token (middleware returns error response directly)
      const res2 = await request(app.server())
        .get('/check-error')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401)
      
      // When token is invalid, middleware returns error directly, won't reach handler
      expect(res2.body.error).toBe('Invalid token')
      expect(res2.body.details.type).toBe('INVALID_TOKEN')

      // 3. When token is valid
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })
      
      const res3 = await request(app.server())
        .get('/check-error')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
      
      expect(res3.body.error).toBeNull()
    })
  })

  describe('passNoToken option', () => {
    it('should return 401 directly when passNoToken is false (default behavior)', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        passNoToken: false  // Explicitly set to false
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        // This handler should not be executed
        return Response.json({ message: 'Should not reach here' })
      })

      const res = await request(app.server())
        .get('/protected')
        .expect(401)

      expect(res.body).toEqual({ error: 'No token' })
    })

    it('should continue to next middleware when passNoToken is true', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        passNoToken: true  // Set to true
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        const user = userContext.get()
        if (!user) {
          // Return custom response when no user
          return Response.json({ message: 'Anonymous access', authenticated: false })
        }
        return Response.json({ user, authenticated: true } as any)
      })

      // Test without token
      const res1 = await request(app.server())
        .get('/protected')
        .expect(200)

      expect(res1.body).toEqual({ 
        message: 'Anonymous access', 
        authenticated: false 
      })

      // Test with token
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })

      const res2 = await request(app.server())
        .get('/protected')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)

      expect(res2.body.authenticated).toBe(true)
      expect(res2.body.user).toMatchObject(testUser)
    })

    it('should support mixed authentication scenarios (public content + personalized content)', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        passNoToken: true
      })

      app.use(jwtMiddleware)
      
      // Simulate blog post list: anonymous users see public posts, authenticated users see all posts
      app.get('/posts').use(() => {
        const user = userContext.get()
        
        const publicPosts = [
          { id: 1, title: 'Public Post 1', public: true },
          { id: 2, title: 'Public Post 2', public: true }
        ]
        
        const privatePosts = [
          { id: 3, title: 'Private Post 1', public: false },
          { id: 4, title: 'Private Post 2', public: false }
        ]
        
        if (user) {
          return Response.json({ 
            posts: [...publicPosts, ...privatePosts],
            user: user.username 
          })
        } else {
          return Response.json({ 
            posts: publicPosts,
            user: null 
          })
        }
      })

      // Anonymous access
      const res1 = await request(app.server())
        .get('/posts')
        .expect(200)
      
      expect(res1.body.posts).toHaveLength(2)
      expect(res1.body.user).toBeNull()

      // Authenticated access
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })
      
      const res2 = await request(app.server())
        .get('/posts')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
      
      expect(res2.body.posts).toHaveLength(4)
      expect(res2.body.user).toBe('testuser')
    })

    it('passNoToken should not affect handling of invalid tokens', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        passNoToken: true  // Even when set to true
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        return Response.json({ message: 'Should not reach here' })
      })

      // Invalid token should still return 401
      const res = await request(app.server())
        .get('/protected')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401)

      expect(res.body.error).toBe('Invalid token')
    })

    it('passNoToken should not affect handling of expired tokens', async () => {
      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        passNoToken: true  // Even when set to true
      })

      app.use(jwtMiddleware)
      app.get('/protected').use(() => {
        return Response.json({ message: 'Should not reach here' })
      })

      // Expired token should still return 401
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const expiredToken = jwt.sign(testUser, TEST_SECRET, { expiresIn: '-1h' })

      const res = await request(app.server())
        .get('/protected')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401)

      expect(res.body.error).toBe('Token expired')
    })
  })

  describe('custom parser', () => {
    it('should support custom token parser', async () => {
      const customParser = {
        getToken:(request: any) => {
          const customToken = request.headers?.['x-custom-token']
          return customToken ? { accessToken: customToken, refreshToken: null }:{accessToken:null,refreshToken:null}
        },
        setToken:(token: string, refreshToken?: string) => {
          return Response.json({ customToken: token, customRefresh: refreshToken })
        }
      }

      const jwtMiddleware = createJWTMiddleware<TestUser>({
        access: {
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' }
        },
        jwtDataCtx: userContext,
        parser: customParser,
        whitelist: ['/auth/login']
      })

      app.use(jwtMiddleware)
      
      app.post('/auth/login').use(() => {
        const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
        return userContext.sign(testUser)
      })

      app.get('/protected').use(() => {
        const user = userContext.get()
        return Response.json({ user } as any)
      })

      // 1. Login should return custom format
      const loginRes = await request(app.server())
        .post('/auth/login')
        .expect(200)
      
      expect(loginRes.body).toHaveProperty('customToken')

      // 2. Access using custom header
      const testUser: TestUser = { id: 1, username: 'testuser', role: 'user' }
      const token = jwt.sign(testUser, TEST_SECRET, { expiresIn: '1h' })
      
      const res = await request(app.server())
        .get('/protected')
        .set('X-Custom-Token', token)
        .expect(200)
      
      expect(res.body.user).toMatchObject(testUser)
    })
  })
})