import { Response, useRequestInfo } from 'farrow-http'
import type { RequestInfo } from 'farrow-http'
import * as jwt from 'jsonwebtoken'
import { Context, createContext } from 'farrow-pipeline'
import { Err, Ok, Result } from 'farrow-schema'
import { match, MatchFunction } from 'path-to-regexp'

type JwtDataCtx<D>=Context<D|undefined>&{
  sign: (UserData?:D) => Response
  refresh: () => Promise<Response>
}
export const createJwtDataCtx = <D>():JwtDataCtx<D> => {
  const ctx = createContext<D|undefined>(undefined)
  return {
    ...ctx,
    sign:()=>{
        throw new Error('JwtDataCtx.sign called before middleware initialization')
      },
    refresh:()=>{
        throw new Error('JwtDataCtx.refresh called before middleware initialization')
      }
    }
  }

export type JWTError = 
  | { type: 'TOKEN_EXPIRED'; expiredAt?: Date }
  | { type: 'INVALID_TOKEN'; message: string }
  | { type: 'NO_TOKEN' }
  | { type: 'TOKEN_REVOKED' }

export const verifyToken = <D>(
  token: string,
  secret: string | Buffer,
  options?: jwt.VerifyOptions
): Result<D, JWTError> => {
  try {
    const decoded = jwt.verify(token, secret, options)
    // 确保返回的是对象类型的 payload
    if (typeof decoded === 'string') {
      return Err({ type: 'INVALID_TOKEN', message: 'Unexpected string payload' })
    }
    const { iat, exp, nbf, aud, iss, sub, jti, ...userData } = decoded as any
    return Ok(userData as D)
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      return Err({ type: 'TOKEN_EXPIRED', expiredAt: error.expiredAt })
    }
    return Err({ type: 'INVALID_TOKEN', message: error.message })
  }
}

export const extractBearerToken = (authHeader: string | undefined): string | null => {
  if (!authHeader) return null
  const [scheme, token] = authHeader.split(' ')
  return scheme === 'Bearer' ? token : null
}
export const JWTErrorContext = createContext<JWTError | null>(null)
export type JWTOptions={
  secret: string | Buffer
  signOptions?:jwt.SignOptions
  verifyOptions?:jwt.VerifyOptions
}

export type RevokeChecker<D = any> = (payload: D) => boolean | Promise<boolean>

export type WhitelistRule = string | {
  path: string
  methods?: string[]
}

export interface JWTMiddlewareOptions<D>{
  access:JWTOptions
  refresh?:JWTOptions
  jwtDataCtx: JwtDataCtx<D>
  isRevoked?: RevokeChecker<D>
  whitelist?: WhitelistRule[]
  parser?:{
    getToken:(request: RequestInfo)=>{
      accessToken:string|null;
      refreshToken:string|null;
    }
    setToken:(token:string,refreshToken?:string)=>Response
  }
  passNoToken?:boolean
}
const defaultParser={
  getToken:(request: RequestInfo)=>{
    return {
      accessToken: request.headers?.authorization?extractBearerToken(request.headers?.authorization) : request.cookies?.token ?? request.query?.token ?? null,
      refreshToken: request.body?.refreshToken ?? request.cookies?.refreshToken ?? request.query?.refreshToken ?? null
    }
  },
  setToken:(token:string,refreshToken?:string)=>{
    return Response.json({token,refreshToken})
  }
}

const pathMatcher=new Map<WhitelistRule,MatchFunction<Partial<Record<string, string | string[]>>>>([])
const isWhitelisted = (pathname: string,whitelist: WhitelistRule[], method: string): boolean => {
  return whitelist.some(rule => {

    if(typeof rule === 'string'){
      let matcher=pathMatcher.get(rule)
      if(!matcher){
        matcher = match(rule)
        pathMatcher.set(rule,matcher)
      }
      return matcher(pathname)
    }
    // 检查方法是否匹配（如果指定了方法）
    if (rule.methods && !rule.methods.includes(method!.toUpperCase())) {
      return false
    }
    
    // 检查路径是否匹配
    let matcher=pathMatcher.get(rule)
    if(!matcher){
      matcher = match(rule.path)
      pathMatcher.set(rule,matcher)
    }
    return matcher(pathname)
  })
}

export const createJWTMiddleware = <D>(options: JWTMiddlewareOptions<D>) => {
  const { 
    access:{secret,verifyOptions}, 
    parser=defaultParser,
    jwtDataCtx,
    isRevoked,
    whitelist = [],
    passNoToken=false
  } = options
  jwtDataCtx.sign=(UserData?:D)=>{
      const payload= UserData || jwtDataCtx.get()
      if(!payload){
        throw new Error('Neither UserData nor JwtDataCtx is valid')
      }
      const accessToken=jwt.sign(payload as any,options.access.secret,options.access.signOptions)
      if(options.refresh){
        const refreshToken=jwt.sign(payload as any,options.refresh.secret,options.refresh.signOptions)
        return parser.setToken(accessToken,refreshToken)
      }
      return parser.setToken(accessToken) 
  }
  jwtDataCtx.refresh=async ()=>{
    if(!options.refresh){
      throw new Error('refresh is not set')
    }
    const tokens=parser.getToken(useRequestInfo())
    if(!tokens?.refreshToken){
      throw new Error('refresh token is not found')
    }
    const result=verifyToken<D>(tokens.refreshToken,options.refresh.secret,options.refresh.verifyOptions)
    if(result.isErr){
      return Response.status(401).json({ error: 'Invalid refresh token' })
    }
    const payload=result.value as any
    
    // Check if refresh token is revoked
    if (isRevoked) {
      const isRevokedResult = await isRevoked(payload)
      if (isRevokedResult) {
        return Response.status(401).json({ error: 'Refresh token has been revoked' })
      }
    }
    const accessToken=jwt.sign(payload,options.access.secret,options.access.signOptions)
    const newRefreshToken=jwt.sign(payload,options.refresh.secret,options.refresh.signOptions)
    return parser.setToken(accessToken,newRefreshToken)
  } 
  return async (request: RequestInfo, next: (request: RequestInfo) => any) => {
    // 检查是否在白名单中
    if (whitelist.length > 0 && isWhitelisted(request.pathname, whitelist,request.method!)) {
      JWTErrorContext.set(null)
      return next(request)
    }
    
    const token = parser.getToken(request)
    if (!token.accessToken) {
      JWTErrorContext.set({ type: 'NO_TOKEN' })
      if(passNoToken){
        return next(request)
      }
      return Response.status(401).json({ error: 'No token' })
    }
    const result = verifyToken<D>(token.accessToken, secret, verifyOptions)
    if (result.kind === 'Err') {
      JWTErrorContext.set(result.value)
      return Response.status(401).json({ 
          error: result.value.type === 'TOKEN_EXPIRED' 
            ? 'Token expired' 
            : 'Invalid token',
          details: result.value
        })
    }
    if (isRevoked) {
      const payload = result.value
      const isRevokeResult = await isRevoked(payload)
      
      if (isRevokeResult) {
        JWTErrorContext.set({ type: 'TOKEN_REVOKED' })
        return Response.status(401).json({ 
          error: 'Token has been revoked',
          details: { type: 'TOKEN_REVOKED' }
        })
      }
    }
    
    jwtDataCtx.set(result.value)
    JWTErrorContext.set(null)
    return next(request)
  }
}

export const JWT = createJWTMiddleware