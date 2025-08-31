# farrow-auth-jwt

为 [Farrow](https://github.com/farrow-js/farrow) HTTP 框架提供的类型安全的 JWT 认证中间件，支持刷新令牌机制。

[English](./README.md) | 简体中文

## 特性

- 🔒 **双令牌系统** - Access Token + Refresh Token 机制
- 🎯 **类型安全** - 完整的 TypeScript 支持与类型推导
- 🛡️ **灵活的安全策略** - 支持令牌撤销、白名单规则、自定义验证
- 📦 **多种令牌来源** - 支持 Authorization 请求头、Cookie、查询参数
- ⚡ **React Hooks 风格** - 基于 Context 的状态管理
- 🔧 **高度可定制** - 自定义解析器、错误处理器和令牌存储

## 安装

```bash
npm install farrow-auth-jwt
# 或
yarn add farrow-auth-jwt
# 或
pnpm add farrow-auth-jwt
```

## 快速开始

```typescript
import { Http, Response } from 'farrow-http'
import { createJWTMiddleware, createJwtDataCtx } from 'farrow-auth-jwt'

// 定义用户类型
interface User {
  id: number
  username: string
  role: 'admin' | 'user'
}

// 创建 JWT 上下文
const userContext = createJwtDataCtx<User>()

// 创建中间件
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

// 应用中间件
const app = Http()
app.use(jwtMiddleware)

// 登录端点
app.post('/login').use((request) => {
  const { username, password } = request.body
  
  // 验证凭据...
  const user: User = { id: 1, username, role: 'user' }
  
  // 签发令牌
  return userContext.sign(user)
})

// 受保护的端点
app.get('/profile').use(() => {
  const user = userContext.get()
  // 注意：如果没有设置 passNoToken: true，无 token 的请求不会到达这里
  // 中间件会直接返回 401，所以这里的 user 一定存在
  return Response.json(user)
})

// 刷新端点
app.post('/refresh').use(async () => {
  return await userContext.refresh()
})

app.listen(3000)
```

## 核心概念

### JWT 上下文

JWT 上下文扩展了 Farrow 的 Context 系统，添加了认证方法：

```typescript
const userContext = createJwtDataCtx<User>()

// 获取当前用户
const user = userContext.get()

// 签发新令牌
const response = userContext.sign(userData)

// 刷新令牌
const response = await userContext.refresh()
```

### 中间件选项

```typescript
interface JWTMiddlewareOptions<D> {
  // Access Token 配置
  access: {
    secret: string | Buffer
    signOptions?: jwt.SignOptions
    verifyOptions?: jwt.VerifyOptions
  }
  
  // 可选的 Refresh Token 配置
  refresh?: {
    secret: string | Buffer
    signOptions?: jwt.SignOptions
    verifyOptions?: jwt.VerifyOptions
  }
  
  // JWT 数据上下文
  jwtDataCtx: JwtDataCtx<D>
  
  // 可选的令牌撤销检查器
  isRevoked?: (payload: D) => boolean | Promise<boolean>
  
  // 不需要认证的白名单路径
  whitelist?: WhitelistRule[]
  
  // 自定义令牌解析器
  parser?: {
    getToken: (request: RequestInfo) => {
      accessToken: string | null
      refreshToken: string | null
    }
    setToken: (token: string, refreshToken?: string) => Response
  }
  
  // 允许无令牌的请求继续执行
  passNoToken?: boolean
}
```

## 高级用法

### 白名单规则

支持 [path-to-regexp](https://github.com/pillarjs/path-to-regexp) v8 语法的路径模式和 HTTP 方法限制：

```typescript
const whitelist: WhitelistRule[] = [
  // 简单路径
  '/public',
  
  // 路径参数
  '/users/:id',                    // 匹配 /users/123
  '/api/users/:id?',               // 可选参数，匹配 /api/users 和 /api/users/123
  
  // 通配符（注意：v8 使用 {*} 语法）
  '/public/{*path}',               // 匹配 /public/* 的所有路径
  
  // 带方法限制
  { path: '/auth/login', methods: ['POST'] },
  { path: '/api/upload', methods: ['POST', 'PUT'] }
]
```

### 令牌撤销

实现令牌黑名单或基于用户的撤销：

```typescript
const revokedTokens = new Set<string>()

const jwtMiddleware = createJWTMiddleware({
  // ... 其他选项
  isRevoked: async (payload: User) => {
    // 检查用户是否被封禁
    const user = await db.users.findById(payload.id)
    return user.status === 'banned'
    
    // 或检查令牌黑名单
    // return revokedTokens.has(payload.jti)
  }
})
```

### 自定义令牌解析器

自定义令牌的提取和返回方式：

```typescript
const customParser = {
  getToken: (request: RequestInfo) => {
    // 从自定义请求头提取
    const accessToken = request.headers?.['x-access-token'] || null
    const refreshToken = request.headers?.['x-refresh-token'] || null
    return { accessToken, refreshToken }
  },
  
  setToken: (token: string, refreshToken?: string) => {
    // 以自定义格式返回令牌
    return Response.json({
      auth: { accessToken: token, refreshToken },
      expiresIn: 900
    })
  }
}
```

### 混合认证（公开 + 受保护）

允许同时支持已认证和匿名访问：

```typescript
const jwtMiddleware = createJWTMiddleware({
  // ... 其他选项
  passNoToken: true  // 不拒绝没有令牌的请求
})

app.get('/posts').use(() => {
  const user = userContext.get()
  
  if (user) {
    // 为已认证用户返回所有文章
    return Response.json({ posts: getAllPosts(), user })
  } else {
    // 为匿名用户返回仅公开文章
    return Response.json({ posts: getPublicPosts() })
  }
})
```

### 错误处理

通过上下文访问 JWT 错误：

```typescript
import { JWTErrorContext } from 'farrow-auth-jwt'

app.use((request, next) => {
  const response = next(request)
  const error = JWTErrorContext.get()
  
  if (error) {
    // 记录认证错误
    console.log('JWT 错误:', error)
    
    // 自定义错误响应
    switch (error.type) {
      case 'TOKEN_EXPIRED':
        return Response.status(401).json({
          error: '会话已过期',
          code: 'AUTH_EXPIRED'
        })
      case 'INVALID_TOKEN':
        return Response.status(403).json({
          error: '无效的凭据',
          code: 'AUTH_INVALID'
        })
      // ... 处理其他错误
    }
  }
  
  return response
})
```

## 令牌刷新流程

刷新令牌机制允许用户在不重新认证的情况下获取新的访问令牌：

```typescript
// 1. 配置刷新令牌
const jwtMiddleware = createJWTMiddleware({
  access: {
    secret: ACCESS_SECRET,
    signOptions: { expiresIn: '15m' }  // 短期有效
  },
  refresh: {
    secret: REFRESH_SECRET,
    signOptions: { expiresIn: '7d' }   // 长期有效
  },
  jwtDataCtx: userContext,
  whitelist: ['/auth/refresh']  // 重要：将刷新端点加入白名单
})

// 2. 登录返回两个令牌
app.post('/auth/login').use((request) => {
  const user = validateCredentials(request.body)
  return userContext.sign(user)
  // 返回: { token: "...", refreshToken: "..." }
})

// 3. 刷新端点（必须在白名单中）
app.post('/auth/refresh').use(async (request) => {
  // 只验证 refresh token，不需要 access token
  return await userContext.refresh()
  // 返回: { token: "new...", refreshToken: "new..." }
})

// 4. 客户端使用
// 当 access token 过期时，使用 refresh token 获取新令牌
fetch('/auth/refresh', {
  method: 'POST',
  body: JSON.stringify({ refreshToken: savedRefreshToken })
})
```

## API 参考

### `createJwtDataCtx<D>()`

创建一个用户数据类型为 `D` 的 JWT 上下文。

### `createJWTMiddleware<D>(options)`

创建 JWT 认证中间件。

### `verifyToken<D>(token, secret, options?)`

手动验证 JWT 令牌。返回 `Result<D, JWTError>`。

### `extractBearerToken(authHeader)`

从 Bearer 授权头中提取令牌。

### `JWTErrorContext`

包含当前 JWT 错误状态的上下文。

### 类型定义

```typescript
type JWTError = 
  | { type: 'TOKEN_EXPIRED'; expiredAt?: Date }
  | { type: 'INVALID_TOKEN'; message: string }
  | { type: 'NO_TOKEN' }
  | { type: 'TOKEN_REVOKED' }

type WhitelistRule = 
  | string  // 路径模式
  | {
      path: string
      methods?: string[]  // HTTP 方法
    }
```

## 许可证

MIT

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 相关链接

- [Farrow 框架](https://github.com/farrow-js/farrow)
- [JSON Web Tokens](https://jwt.io/)