import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Users } from '../db/database.js';

const JWT_SECRET = process.env.JWT_SECRET || 'ai-report-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d';

/**
 * 生成 JWT Token
 */
export function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      plan: user.plan
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

/**
 * 验证密码
 */
export function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

/**
 * 哈希密码
 */
export function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

/**
 * JWT 验证中间件
 * 验证成功后将用户信息挂载到 req.user
 */
export function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '请先登录' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // 从数据库获取最新用户信息
    const user = Users.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ error: '用户不存在' });
    }

    // 移除敏感信息
    delete user.password_hash;
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    return res.status(401).json({ error: '无效的登录凭证' });
  }
}

/**
 * 可选的 Token 验证中间件
 * 如果有 token 则验证，没有也放行
 */
export function optionalToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    return next();
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = Users.findById(decoded.id);
    if (user) {
      delete user.password_hash;
      req.user = user;
    } else {
      req.user = null;
    }
  } catch {
    req.user = null;
  }

  next();
}

/**
 * 管理员权限验证中间件
 * 必须在 verifyToken 之后使用
 */
export function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: '请先登录' });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: '需要管理员权限' });
  }

  next();
}

/**
 * Pro 用户权限验证中间件
 * 用于付费功能的访问控制
 */
export function requirePro(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: '请先登录' });
  }

  if (req.user.plan !== 'pro' && req.user.role !== 'admin') {
    return res.status(403).json({
      error: '此功能需要 Pro 版本',
      code: 'UPGRADE_REQUIRED'
    });
  }

  next();
}

/**
 * 用量检查中间件
 * 检查免费用户的每日使用次数
 */
export function checkUsageLimit(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: '请先登录' });
  }

  // 管理员和 Pro 用户不受限制
  if (req.user.role === 'admin' || req.user.plan === 'pro') {
    return next();
  }

  const result = Users.checkAndIncrementUsage(req.user);

  if (!result.allowed) {
    return res.status(429).json({
      error: '今日免费次数已用完',
      code: 'DAILY_LIMIT_REACHED',
      limit: result.limit,
      remaining: 0
    });
  }

  // 将剩余次数信息附加到响应
  req.usageInfo = {
    remaining: result.remaining,
    limit: result.limit
  };

  next();
}
