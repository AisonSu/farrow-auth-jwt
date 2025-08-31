# farrow-auth-jwt

Type-safe JWT authentication middleware for [Farrow](https://github.com/farrow-js/farrow) HTTP framework with refresh token support.

English | [简体中文](./README.zh-CN.md)

## Features

- 🔒 **Dual Token System** - Access token + Refresh token mechanism
- 🎯 **Type-safe** - Full TypeScript support with type inference
- 🛡️ **Flexible Security** - Token revocation, whitelist rules, custom validation
- 📦 **Multiple Token Sources** - Authorization header, cookies, query parameters
- ⚡ **React Hooks Style** - Context-based state management
- 🔧 **Highly Customizable** - Custom parsers, error handlers, and token storage

## Installation

```bash
npm install farrow-auth-jwt
# or
yarn add farrow-auth-jwt
# or
pnpm add farrow-auth-jwt
```

## Quick Start

```typescript
import { Http, Response } from 'farrow-http'
import { createJWTMiddleware, createJwtDataCtx } from 'farrow-auth-jwt'

// Define your user type
interface User {
  id: number
  username: string
  role: 'admin' | 'user'
}

// Create JWT context
const userContext = createJwtDataCtx<User>()

// Create middleware
const jwtMiddleware = createJWTMiddleware({
  access: {
    secret: 'your-access-secret',
    signOptions: { expiresIn: '15m' }
  },
  refresh: {
    secret: 'your-refresh-secret',
    signOptions: { expiresIn: '7d' }
  },
  jwtDataCtx: userContext,
  whitelist: ['/login', '/register', '/refresh']
})

// Apply middleware
const app = Http()
app.use(jwtMiddleware)

// Login endpoint
app.post('/login').use((request) => {
  const { username, password } = request.body
  
  // Validate credentials...
  const user: User = { id: 1, username, role: 'user' }
  
  // Sign tokens
  return userContext.sign(user)
})

// Protected endpoint
app.get('/profile').use(() => {
  const user = userContext.get()
  // Note: Without passNoToken: true, requests without token won't reach here
  // The middleware will return 401 directly, so user is guaranteed to exist
  return Response.json(user)
})

// Refresh endpoint
app.post('/refresh').use(async () => {
  return await userContext.refresh()
})

app.listen(3000)
```

## Core Concepts

### JWT Context

The JWT context extends Farrow's Context system with authentication methods:

```typescript
const userContext = createJwtDataCtx<User>()

// Get current user
const user = userContext.get()

// Sign new tokens
const response = userContext.sign(userData)

// Refresh tokens
const response = await userContext.refresh()
```

### Middleware Options

```typescript
interface JWTMiddlewareOptions<D> {
  // Access token configuration
  access: {
    secret: string | Buffer
    signOptions?: jwt.SignOptions
    verifyOptions?: jwt.VerifyOptions
  }
  
  // Optional refresh token configuration
  refresh?: {
    secret: string | Buffer
    signOptions?: jwt.SignOptions
    verifyOptions?: jwt.VerifyOptions
  }
  
  // JWT data context
  jwtDataCtx: JwtDataCtx<D>
  
  // Optional token revocation checker
  isRevoked?: (payload: D) => boolean | Promise<boolean>
  
  // Whitelist paths that don't require authentication
  whitelist?: WhitelistRule[]
  
  // Custom token parser
  parser?: {
    getToken: (request: RequestInfo) => {
      accessToken: string | null
      refreshToken: string | null
    }
    setToken: (token: string, refreshToken?: string) => Response
  }
  
  // Allow requests without token to continue
  passNoToken?: boolean
}
```

## Advanced Usage

### Whitelist Rules

Supports [path-to-regexp](https://github.com/pillarjs/path-to-regexp) v8 syntax for path patterns and HTTP method restrictions:

```typescript
const whitelist: WhitelistRule[] = [
  // Simple path
  '/public',
  
  // Path parameters
  '/users/:id',                    // matches /users/123
  '/api/users/:id?',               // optional parameter, matches /api/users and /api/users/123
  
  // Wildcard (Note: v8 uses {*} syntax)
  '/public/{*path}',               // matches all paths under /public/
  
  // With method restriction
  { path: '/auth/login', methods: ['POST'] },
  { path: '/api/upload', methods: ['POST', 'PUT'] }
]
```

### Token Revocation

Implement token blacklisting or user-based revocation:

```typescript
const revokedTokens = new Set<string>()

const jwtMiddleware = createJWTMiddleware({
  // ... other options
  isRevoked: async (payload: User) => {
    // Check if user is banned
    const user = await db.users.findById(payload.id)
    return user.status === 'banned'
    
    // Or check token blacklist
    // return revokedTokens.has(payload.jti)
  }
})
```

### Custom Token Parser

Customize how tokens are extracted and returned:

```typescript
const customParser = {
  getToken: (request: RequestInfo) => {
    // Extract from custom header
    const accessToken = request.headers?.['x-access-token'] || null
    const refreshToken = request.headers?.['x-refresh-token'] || null
    return { accessToken, refreshToken }
  },
  
  setToken: (token: string, refreshToken?: string) => {
    // Return tokens in custom format
    return Response.json({
      auth: { accessToken: token, refreshToken },
      expiresIn: 900
    })
  }
}
```

### Mixed Authentication (Public + Protected)

Allow both authenticated and anonymous access:

```typescript
const jwtMiddleware = createJWTMiddleware({
  // ... other options
  passNoToken: true  // Don't reject requests without token
})

app.get('/posts').use(() => {
  const user = userContext.get()
  
  if (user) {
    // Return all posts for authenticated users
    return Response.json({ posts: getAllPosts(), user })
  } else {
    // Return only public posts for anonymous users
    return Response.json({ posts: getPublicPosts() })
  }
})
```

### Error Handling

Access JWT errors through context:

```typescript
import { JWTErrorContext } from 'farrow-auth-jwt'

app.use((request, next) => {
  const response = next(request)
  const error = JWTErrorContext.get()
  
  if (error) {
    // Log authentication errors
    console.log('JWT Error:', error)
    
    // Custom error response
    switch (error.type) {
      case 'TOKEN_EXPIRED':
        return Response.status(401).json({
          error: 'Session expired',
          code: 'AUTH_EXPIRED'
        })
      case 'INVALID_TOKEN':
        return Response.status(403).json({
          error: 'Invalid credentials',
          code: 'AUTH_INVALID'
        })
      // ... handle other errors
    }
  }
  
  return response
})
```

## Token Refresh Flow

The refresh token mechanism allows users to obtain new access tokens without re-authentication:

```typescript
// 1. Configure refresh tokens
const jwtMiddleware = createJWTMiddleware({
  access: {
    secret: ACCESS_SECRET,
    signOptions: { expiresIn: '15m' }  // Short-lived
  },
  refresh: {
    secret: REFRESH_SECRET,
    signOptions: { expiresIn: '7d' }   // Long-lived
  },
  jwtDataCtx: userContext,
  whitelist: ['/auth/refresh']  // Important: Add refresh endpoint to whitelist
})

// 2. Login returns both tokens
app.post('/auth/login').use((request) => {
  const user = validateCredentials(request.body)
  return userContext.sign(user)
  // Returns: { token: "...", refreshToken: "..." }
})

// 3. Refresh endpoint (must be in whitelist)
app.post('/auth/refresh').use(async (request) => {
  // Only refresh token is validated, no access token needed
  return await userContext.refresh()
  // Returns: { token: "new...", refreshToken: "new..." }
})

// 4. Client usage
// When access token expires, use refresh token to get new tokens
fetch('/auth/refresh', {
  method: 'POST',
  body: JSON.stringify({ refreshToken: savedRefreshToken })
})
```

## API Reference

### `createJwtDataCtx<D>()`

Creates a JWT context with type `D` for user data.

### `createJWTMiddleware<D>(options)`

Creates the JWT authentication middleware.

### `verifyToken<D>(token, secret, options?)`

Manually verify a JWT token. Returns `Result<D, JWTError>`.

### `extractBearerToken(authHeader)`

Extract token from Bearer authorization header.

### `JWTErrorContext`

Context containing current JWT error state.

### Types

```typescript
type JWTError = 
  | { type: 'TOKEN_EXPIRED'; expiredAt?: Date }
  | { type: 'INVALID_TOKEN'; message: string }
  | { type: 'NO_TOKEN' }
  | { type: 'TOKEN_REVOKED' }

type WhitelistRule = 
  | string  // Path pattern
  | {
      path: string
      methods?: string[]  // HTTP methods
    }
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- [Farrow Framework](https://github.com/farrow-js/farrow)
- [JSON Web Tokens](https://jwt.io/)