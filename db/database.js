import Database from 'better-sqlite3';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, mkdirSync } from 'fs';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// 数据库路径 - 支持 Railway Volume 挂载
const DATA_DIR = process.env.DATABASE_PATH
  ? dirname(process.env.DATABASE_PATH)
  : join(__dirname, '..', 'data');

const DB_PATH = process.env.DATABASE_PATH || join(DATA_DIR, 'app.db');

// 确保数据目录存在
if (!existsSync(DATA_DIR)) {
  mkdirSync(DATA_DIR, { recursive: true });
}

// 创建数据库连接
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ========== 初始化表结构 (立即执行) ==========
function initTables() {
  // 用户表 (支持手机号/用户名登录)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT UNIQUE,
      email TEXT UNIQUE,
      username TEXT UNIQUE,
      password_hash TEXT,
      nickname TEXT,
      role TEXT DEFAULT 'user',
      plan TEXT DEFAULT 'free',
      daily_usage INTEGER DEFAULT 0,
      last_usage_date TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      last_login TEXT
    )
  `);

  // 迁移：为旧表添加 username 列
  try {
    db.exec(`ALTER TABLE users ADD COLUMN username TEXT UNIQUE`);
  } catch (e) {
    // 列已存在，忽略
  }

  // 验证码表
  db.exec(`
    CREATE TABLE IF NOT EXISTS verification_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // 周报表
  db.exec(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      original_content TEXT,
      polished_content TEXT,
      role_type TEXT,
      used_template INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // 范本表
  db.exec(`
    CREATE TABLE IF NOT EXISTS templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      name TEXT DEFAULT '默认范本',
      content TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);

  // 对话历史表
  db.exec(`
    CREATE TABLE IF NOT EXISTS chat_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER REFERENCES reports(id),
      user_message TEXT,
      ai_thought TEXT,
      ai_action TEXT,
      ai_observation TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // 使用日志表 (埋点)
  db.exec(`
    CREATE TABLE IF NOT EXISTS usage_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT,
      metadata TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // 迁移：保留旧的 feedback 数据结构
  db.exec(`
    CREATE TABLE IF NOT EXISTS feedback (
      id TEXT PRIMARY KEY,
      type TEXT,
      title TEXT,
      description TEXT,
      contact TEXT,
      status TEXT DEFAULT 'pending',
      note TEXT DEFAULT '',
      created_at TEXT,
      updated_at TEXT
    )
  `);

  // 游客使用记录表（按 IP 追踪）
  db.exec(`
    CREATE TABLE IF NOT EXISTS guest_usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      usage_count INTEGER DEFAULT 0,
      usage_date TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(ip, usage_date)
    )
  `);

  // 润色结果评分表
  db.exec(`
    CREATE TABLE IF NOT EXISTS report_ratings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL,
      user_id INTEGER,
      rating INTEGER NOT NULL,
      feedback TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(report_id)
    )
  `);

  // 自定义角色表
  db.exec(`
    CREATE TABLE IF NOT EXISTS custom_roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      prompt TEXT NOT NULL,
      icon TEXT DEFAULT '🎯',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);

  // Prompt 管理表
  db.exec(`
    CREATE TABLE IF NOT EXISTS prompts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role_type TEXT NOT NULL,
      version INTEGER DEFAULT 1,
      content TEXT NOT NULL,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
  `);

  // 初始化默认 Prompts（如果为空）
  const promptCount = db.prepare('SELECT COUNT(*) as count FROM prompts').get().count;
  if (promptCount === 0) {
    const defaultPrompts = [
      {
        role_type: 'pm',
        content: `你是互联网大厂P9产品总监，带过50人团队，深谙向上汇报的艺术。

【任务】将产品经理的周报改写成能让老板看到价值的高质量周报。

【PM周报常见问题】
- 只写了"做了什么"，没写"产出了什么"
- 缺少数据支撑，成果不可衡量
- 项目进度不清晰
- 语言啰嗦，重点不突出

【改写原则】
1. 成果量化：完成率、影响用户数、预期收益
2. 价值前置：先说结果，再说过程
3. 风险透明：主动暴露问题
4. 简洁有力：每条1-2行

【输出格式】
## 本周成果
- [量化成果]

## 重点进展
- [项目]：当前阶段 → 下一里程碑（时间）

## 下周计划
- [可衡量目标]

## 风险与协调（如有）
- [问题]：需要[谁][做什么]

现在改写：`
      },
      {
        role_type: 'dev',
        content: `你是互联网大厂技术总监，带过百人研发团队。

【任务】将开发工程师的周报改写成技术领导认可的高质量周报。

【开发周报常见问题】
- 只写了"修了什么bug"，没写技术价值
- 缺少代码量、性能提升等量化指标
- 技术债务和风险没有暴露
- 协作贡献被忽略

【改写原则】
1. 技术价值量化：代码行数、性能提升百分比、bug修复数
2. 技术深度体现：用专业术语描述技术方案
3. 协作贡献：code review、技术分享、帮助同事
4. 风险前置：技术债务、性能瓶颈、依赖风险

【输出格式】
## 本周产出
- [技术成果，含量化指标]

## 技术进展
- [项目/模块]：完成XX → 下一步XX

## 下周计划
- [具体技术任务]

## 技术风险（如有）
- [风险点]：影响范围 + 建议方案

现在改写：`
      },
      {
        role_type: 'ops',
        content: `你是互联网大厂运营总监，操盘过亿级用户增长。

【任务】将运营的周报改写成老板看得到增长价值的高质量周报。

【运营周报常见问题】
- 只写了"做了什么活动"，没写效果数据
- 缺少ROI、转化率等核心指标
- 用户增长归因不清晰
- 竞品动态缺失

【改写原则】
1. 数据驱动：DAU/MAU、转化率、留存率、ROI
2. 增长归因：哪个动作带来什么结果
3. 成本意识：投入产出比、获客成本
4. 市场敏感：竞品动态、行业趋势

【输出格式】
## 本周数据
- 核心指标：[关键数据变化]

## 运营动作
- [活动/策略]：投入XX → 产出XX（ROI: XX）

## 下周计划
- [运营动作 + 预期目标]

## 市场洞察（如有）
- [竞品动态/行业趋势]

现在改写：`
      }
    ];

    const insertPrompt = db.prepare(`
      INSERT INTO prompts (role_type, content) VALUES (@role_type, @content)
    `);

    for (const prompt of defaultPrompts) {
      insertPrompt.run(prompt);
    }
  }

  console.log('数据库表初始化完成');

  // 自动创建管理员账号
  initAdminUser();
}

// 创建管理员账号（如果不存在）
function initAdminUser() {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@ai-report.com';

  const existingStmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const existing = existingStmt.get(adminEmail);

  if (!existing) {
    const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const passwordHash = bcrypt.hashSync(defaultPassword, 10);

    const insertStmt = db.prepare(`
      INSERT INTO users (email, password_hash, nickname, role, plan)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertStmt.run(adminEmail, passwordHash, '管理员', 'admin', 'pro');
    console.log(`[Admin] 创建管理员账号: ${adminEmail}`);
  }

  // 初始化 PRO 账号
  initProUsers();
}

// 创建预设 PRO 账号
function initProUsers() {
  const proUsers = [
    { username: 'tubaobei', password: '901224', nickname: '兔宝贝' },
    { username: 'lurenjia', password: '123456', nickname: '路人甲' },
    { username: 'lurenyi', password: '123456', nickname: '路人乙' }
  ];

  const checkStmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const insertStmt = db.prepare(`
    INSERT INTO users (username, password_hash, nickname, role, plan)
    VALUES (?, ?, ?, ?, ?)
  `);

  for (const user of proUsers) {
    const existing = checkStmt.get(user.username);
    if (!existing) {
      const passwordHash = bcrypt.hashSync(user.password, 10);
      insertStmt.run(user.username, passwordHash, user.nickname, 'user', 'pro');
      console.log(`[Pro] 创建 PRO 账号: ${user.username}`);
    }
  }
}

// 立即初始化表（必须在 prepared statements 之前）
initTables();

// ========== Users CRUD ==========
const userQueries = {
  createByPhone: db.prepare(`
    INSERT INTO users (phone, nickname, role, plan)
    VALUES (@phone, @nickname, @role, @plan)
  `),

  createByEmail: db.prepare(`
    INSERT INTO users (email, password_hash, nickname, role, plan)
    VALUES (@email, @password_hash, @nickname, @role, @plan)
  `),

  findByPhone: db.prepare(`
    SELECT * FROM users WHERE phone = ?
  `),

  findByEmail: db.prepare(`
    SELECT * FROM users WHERE email = ?
  `),

  findByUsername: db.prepare(`
    SELECT * FROM users WHERE username = ?
  `),

  createByUsername: db.prepare(`
    INSERT INTO users (username, password_hash, nickname, role, plan)
    VALUES (@username, @password_hash, @nickname, @role, @plan)
  `),

  findById: db.prepare(`
    SELECT * FROM users WHERE id = ?
  `),

  updateLastLogin: db.prepare(`
    UPDATE users SET last_login = datetime('now') WHERE id = ?
  `),

  updateDailyUsage: db.prepare(`
    UPDATE users SET daily_usage = @usage, last_usage_date = @date WHERE id = @id
  `),

  resetDailyUsage: db.prepare(`
    UPDATE users SET daily_usage = 0, last_usage_date = @date WHERE id = @id
  `),

  updatePlan: db.prepare(`
    UPDATE users SET plan = ? WHERE id = ?
  `),

  listAll: db.prepare(`
    SELECT id, phone, email, nickname, role, plan, daily_usage, created_at, last_login
    FROM users ORDER BY created_at DESC
  `),

  count: db.prepare(`
    SELECT COUNT(*) as count FROM users
  `)
};

export const Users = {
  // 手机号注册/登录
  createByPhone(data) {
    const result = userQueries.createByPhone.run({
      phone: data.phone,
      nickname: data.nickname || null,
      role: data.role || 'user',
      plan: data.plan || 'free'
    });
    return result.lastInsertRowid;
  },

  findByPhone(phone) {
    return userQueries.findByPhone.get(phone);
  },

  // 兼容邮箱注册（管理员）
  createByEmail(data) {
    const result = userQueries.createByEmail.run({
      email: data.email,
      password_hash: data.password_hash,
      nickname: data.nickname || null,
      role: data.role || 'user',
      plan: data.plan || 'free'
    });
    return result.lastInsertRowid;
  },

  findByEmail(email) {
    return userQueries.findByEmail.get(email);
  },

  // 用户名登录/注册
  findByUsername(username) {
    return userQueries.findByUsername.get(username);
  },

  createByUsername(data) {
    const result = userQueries.createByUsername.run({
      username: data.username,
      password_hash: data.password_hash,
      nickname: data.nickname || data.username,
      role: data.role || 'user',
      plan: data.plan || 'free'
    });
    return result.lastInsertRowid;
  },

  findById(id) {
    return userQueries.findById.get(id);
  },

  updateLastLogin(id) {
    return userQueries.updateLastLogin.run(id);
  },

  updateDailyUsage(id, usage) {
    const today = new Date().toISOString().split('T')[0];
    return userQueries.updateDailyUsage.run({ id, usage, date: today });
  },

  resetDailyUsage(id) {
    const today = new Date().toISOString().split('T')[0];
    return userQueries.resetDailyUsage.run({ id, date: today });
  },

  checkAndIncrementUsage(user) {
    const today = new Date().toISOString().split('T')[0];

    // 如果是新的一天，重置计数
    if (user.last_usage_date !== today) {
      this.resetDailyUsage(user.id);
      user.daily_usage = 0;
    }

    // Pro 用户无限制
    if (user.plan === 'pro') {
      this.updateDailyUsage(user.id, user.daily_usage + 1);
      return { allowed: true, remaining: Infinity };
    }

    // Free 用户每日 3 次
    const limit = 3;
    if (user.daily_usage >= limit) {
      return { allowed: false, remaining: 0, limit };
    }

    this.updateDailyUsage(user.id, user.daily_usage + 1);
    return { allowed: true, remaining: limit - user.daily_usage - 1, limit };
  },

  updatePlan(id, plan) {
    return userQueries.updatePlan.run(plan, id);
  },

  listAll() {
    return userQueries.listAll.all();
  },

  count() {
    return userQueries.count.get().count;
  }
};

// ========== VerificationCodes CRUD ==========
const codeQueries = {
  create: db.prepare(`
    INSERT INTO verification_codes (phone, code, expires_at)
    VALUES (@phone, @code, @expires_at)
  `),

  findValid: db.prepare(`
    SELECT * FROM verification_codes
    WHERE phone = @phone AND code = @code AND used = 0 AND expires_at > datetime('now')
    ORDER BY created_at DESC LIMIT 1
  `),

  markUsed: db.prepare(`
    UPDATE verification_codes SET used = 1 WHERE id = ?
  `),

  cleanExpired: db.prepare(`
    DELETE FROM verification_codes WHERE expires_at < datetime('now')
  `)
};

export const VerificationCodes = {
  // 生成验证码（模拟：固定返回 123456）
  generate(phone) {
    // 清理过期验证码
    codeQueries.cleanExpired.run();

    // TODO: 接入短信服务后改为随机验证码
    // 当前测试阶段固定为 123456
    const code = '123456';

    // 5分钟有效期 (使用 SQLite 兼容的日期格式)
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000)
      .toISOString()
      .replace('T', ' ')
      .slice(0, 19);

    codeQueries.create.run({
      phone,
      code,
      expires_at: expiresAt
    });

    return code;
  },

  // 验证验证码
  verify(phone, code) {
    console.log(`[验证码验证] phone=${phone}, code=${code}`);
    const record = codeQueries.findValid.get({ phone, code });
    console.log(`[验证码验证] 查询结果:`, record ? `找到记录 id=${record.id}, expires_at=${record.expires_at}` : '未找到匹配记录');
    if (record) {
      codeQueries.markUsed.run(record.id);
      return true;
    }
    return false;
  }
};

// ========== Reports CRUD ==========
const reportQueries = {
  create: db.prepare(`
    INSERT INTO reports (user_id, original_content, polished_content, role_type, used_template)
    VALUES (@user_id, @original_content, @polished_content, @role_type, @used_template)
  `),

  findById: db.prepare(`
    SELECT * FROM reports WHERE id = ?
  `),

  findByUserId: db.prepare(`
    SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC
  `),

  findByUserIdWithLimit: db.prepare(`
    SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
  `),

  update: db.prepare(`
    UPDATE reports SET polished_content = ? WHERE id = ?
  `),

  delete: db.prepare(`
    DELETE FROM reports WHERE id = ? AND user_id = ?
  `),

  count: db.prepare(`
    SELECT COUNT(*) as count FROM reports
  `),

  countByUserId: db.prepare(`
    SELECT COUNT(*) as count FROM reports WHERE user_id = ?
  `)
};

export const Reports = {
  create(data) {
    const result = reportQueries.create.run({
      user_id: data.user_id,
      original_content: data.original_content,
      polished_content: data.polished_content,
      role_type: data.role_type || 'pm',
      used_template: data.used_template ? 1 : 0
    });
    return result.lastInsertRowid;
  },

  findById(id) {
    return reportQueries.findById.get(id);
  },

  findByUserId(userId, limit = null) {
    if (limit) {
      return reportQueries.findByUserIdWithLimit.all(userId, limit);
    }
    return reportQueries.findByUserId.all(userId);
  },

  update(id, polishedContent) {
    return reportQueries.update.run(polishedContent, id);
  },

  delete(id, userId) {
    return reportQueries.delete.run(id, userId);
  },

  count() {
    return reportQueries.count.get().count;
  },

  countByUserId(userId) {
    return reportQueries.countByUserId.get(userId).count;
  }
};

// ========== Templates CRUD ==========
const templateQueries = {
  create: db.prepare(`
    INSERT INTO templates (user_id, name, content)
    VALUES (@user_id, @name, @content)
  `),

  findById: db.prepare(`
    SELECT * FROM templates WHERE id = ?
  `),

  findByUserId: db.prepare(`
    SELECT * FROM templates WHERE user_id = ? ORDER BY created_at DESC
  `),

  update: db.prepare(`
    UPDATE templates SET name = @name, content = @content, updated_at = datetime('now')
    WHERE id = @id AND user_id = @user_id
  `),

  delete: db.prepare(`
    DELETE FROM templates WHERE id = ? AND user_id = ?
  `)
};

export const Templates = {
  create(data) {
    const result = templateQueries.create.run({
      user_id: data.user_id,
      name: data.name || '默认范本',
      content: data.content
    });
    return result.lastInsertRowid;
  },

  findById(id) {
    return templateQueries.findById.get(id);
  },

  findByUserId(userId) {
    return templateQueries.findByUserId.all(userId);
  },

  update(id, userId, data) {
    return templateQueries.update.run({
      id,
      user_id: userId,
      name: data.name,
      content: data.content
    });
  },

  delete(id, userId) {
    return templateQueries.delete.run(id, userId);
  }
};

// ========== ChatHistory CRUD ==========
const chatHistoryQueries = {
  create: db.prepare(`
    INSERT INTO chat_history (report_id, user_message, ai_thought, ai_action, ai_observation)
    VALUES (@report_id, @user_message, @ai_thought, @ai_action, @ai_observation)
  `),

  findByReportId: db.prepare(`
    SELECT * FROM chat_history WHERE report_id = ? ORDER BY created_at ASC
  `)
};

export const ChatHistory = {
  create(data) {
    const result = chatHistoryQueries.create.run({
      report_id: data.report_id,
      user_message: data.user_message,
      ai_thought: data.ai_thought,
      ai_action: data.ai_action,
      ai_observation: data.ai_observation
    });
    return result.lastInsertRowid;
  },

  findByReportId(reportId) {
    return chatHistoryQueries.findByReportId.all(reportId);
  }
};

// ========== UsageLogs CRUD ==========
const usageLogQueries = {
  create: db.prepare(`
    INSERT INTO usage_logs (user_id, action, metadata)
    VALUES (@user_id, @action, @metadata)
  `),

  findByUserId: db.prepare(`
    SELECT * FROM usage_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
  `),

  findAll: db.prepare(`
    SELECT * FROM usage_logs ORDER BY created_at DESC LIMIT ? OFFSET ?
  `),

  findByAction: db.prepare(`
    SELECT * FROM usage_logs WHERE action = ? ORDER BY created_at DESC LIMIT ?
  `),

  countByAction: db.prepare(`
    SELECT action, COUNT(*) as count FROM usage_logs GROUP BY action
  `),

  countTotal: db.prepare(`
    SELECT COUNT(*) as count FROM usage_logs
  `),

  recentActions: db.prepare(`
    SELECT * FROM usage_logs ORDER BY created_at DESC LIMIT ?
  `)
};

export const UsageLogs = {
  create(data) {
    const result = usageLogQueries.create.run({
      user_id: data.user_id || null,
      action: data.action,
      metadata: JSON.stringify(data.metadata || {})
    });
    return result.lastInsertRowid;
  },

  findByUserId(userId, limit = 100) {
    return usageLogQueries.findByUserId.all(userId, limit);
  },

  findAll(limit = 100, offset = 0) {
    return usageLogQueries.findAll.all(limit, offset);
  },

  findByAction(action, limit = 100) {
    return usageLogQueries.findByAction.all(action, limit);
  },

  countByAction() {
    return usageLogQueries.countByAction.all();
  },

  countTotal() {
    return usageLogQueries.countTotal.get().count;
  },

  recentActions(limit = 100) {
    return usageLogQueries.recentActions.all(limit);
  },

  getStats() {
    const byAction = usageLogQueries.countByAction.all();
    const total = usageLogQueries.countTotal.get().count;
    return { byAction, total };
  }
};

// ========== GuestUsage CRUD ==========
const guestUsageQueries = {
  findByIpAndDate: db.prepare(`
    SELECT * FROM guest_usage WHERE ip = ? AND usage_date = ?
  `),

  create: db.prepare(`
    INSERT INTO guest_usage (ip, usage_count, usage_date)
    VALUES (@ip, @usage_count, @usage_date)
  `),

  increment: db.prepare(`
    UPDATE guest_usage SET usage_count = usage_count + 1 WHERE ip = ? AND usage_date = ?
  `),

  cleanOld: db.prepare(`
    DELETE FROM guest_usage WHERE usage_date < date('now', '-7 days')
  `)
};

export const GuestUsage = {
  // 检查并增加游客使用次数
  checkAndIncrement(ip, limit = 3) {
    const today = new Date().toISOString().split('T')[0];

    // 清理7天前的记录
    guestUsageQueries.cleanOld.run();

    // 查找今日记录
    let record = guestUsageQueries.findByIpAndDate.get(ip, today);

    if (!record) {
      // 首次使用，创建记录
      guestUsageQueries.create.run({
        ip,
        usage_count: 1,
        usage_date: today
      });
      return { allowed: true, remaining: limit - 1, used: 1, limit };
    }

    // 检查是否超限
    if (record.usage_count >= limit) {
      return { allowed: false, remaining: 0, used: record.usage_count, limit };
    }

    // 增加使用次数
    guestUsageQueries.increment.run(ip, today);
    return {
      allowed: true,
      remaining: limit - record.usage_count - 1,
      used: record.usage_count + 1,
      limit
    };
  },

  // 获取游客今日使用情况
  getUsage(ip) {
    const today = new Date().toISOString().split('T')[0];
    const record = guestUsageQueries.findByIpAndDate.get(ip, today);
    return record ? record.usage_count : 0;
  }
};

// ========== ReportRatings CRUD ==========
const ratingQueries = {
  create: db.prepare(`
    INSERT INTO report_ratings (report_id, user_id, rating, feedback)
    VALUES (@report_id, @user_id, @rating, @feedback)
  `),

  update: db.prepare(`
    UPDATE report_ratings SET rating = @rating, feedback = @feedback
    WHERE report_id = @report_id
  `),

  findByReportId: db.prepare(`
    SELECT * FROM report_ratings WHERE report_id = ?
  `),

  getAverageRating: db.prepare(`
    SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM report_ratings
  `),

  getRatingDistribution: db.prepare(`
    SELECT rating, COUNT(*) as count FROM report_ratings GROUP BY rating ORDER BY rating
  `)
};

export const ReportRatings = {
  upsert(data) {
    const existing = ratingQueries.findByReportId.get(data.report_id);
    if (existing) {
      ratingQueries.update.run({
        report_id: data.report_id,
        rating: data.rating,
        feedback: data.feedback || null
      });
      return existing.id;
    } else {
      const result = ratingQueries.create.run({
        report_id: data.report_id,
        user_id: data.user_id || null,
        rating: data.rating,
        feedback: data.feedback || null
      });
      return result.lastInsertRowid;
    }
  },

  findByReportId(reportId) {
    return ratingQueries.findByReportId.get(reportId);
  },

  getStats() {
    const avg = ratingQueries.getAverageRating.get();
    const distribution = ratingQueries.getRatingDistribution.all();
    return {
      averageRating: avg.avg_rating ? Math.round(avg.avg_rating * 10) / 10 : null,
      totalRatings: avg.count,
      distribution
    };
  }
};

// ========== CustomRoles CRUD ==========
const customRoleQueries = {
  create: db.prepare(`
    INSERT INTO custom_roles (user_id, name, description, prompt, icon)
    VALUES (@user_id, @name, @description, @prompt, @icon)
  `),

  findById: db.prepare(`
    SELECT * FROM custom_roles WHERE id = ?
  `),

  findByUserId: db.prepare(`
    SELECT * FROM custom_roles WHERE user_id = ? ORDER BY created_at DESC
  `),

  countByUserId: db.prepare(`
    SELECT COUNT(*) as count FROM custom_roles WHERE user_id = ?
  `),

  update: db.prepare(`
    UPDATE custom_roles
    SET name = @name, description = @description, prompt = @prompt, icon = @icon, updated_at = datetime('now')
    WHERE id = @id AND user_id = @user_id
  `),

  delete: db.prepare(`
    DELETE FROM custom_roles WHERE id = ? AND user_id = ?
  `)
};

export const CustomRoles = {
  create(data) {
    const result = customRoleQueries.create.run({
      user_id: data.user_id,
      name: data.name,
      description: data.description || '',
      prompt: data.prompt,
      icon: data.icon || '🎯'
    });
    return result.lastInsertRowid;
  },

  findById(id) {
    return customRoleQueries.findById.get(id);
  },

  findByUserId(userId) {
    return customRoleQueries.findByUserId.all(userId);
  },

  countByUserId(userId) {
    return customRoleQueries.countByUserId.get(userId).count;
  },

  update(id, userId, data) {
    return customRoleQueries.update.run({
      id,
      user_id: userId,
      name: data.name,
      description: data.description || '',
      prompt: data.prompt,
      icon: data.icon || '🎯'
    });
  },

  delete(id, userId) {
    return customRoleQueries.delete.run(id, userId);
  }
};

// ========== Feedback CRUD (兼容旧数据) ==========
const feedbackQueries = {
  create: db.prepare(`
    INSERT INTO feedback (id, type, title, description, contact, status, note, created_at, updated_at)
    VALUES (@id, @type, @title, @description, @contact, @status, @note, @created_at, @updated_at)
  `),

  findAll: db.prepare(`
    SELECT * FROM feedback ORDER BY created_at DESC
  `),

  findById: db.prepare(`
    SELECT * FROM feedback WHERE id = ?
  `),

  update: db.prepare(`
    UPDATE feedback SET status = @status, note = @note, updated_at = @updated_at
    WHERE id = @id
  `),

  count: db.prepare(`
    SELECT COUNT(*) as count FROM feedback
  `)
};

export const Feedback = {
  create(data) {
    return feedbackQueries.create.run({
      id: data.id,
      type: data.type,
      title: data.title,
      description: data.description,
      contact: data.contact || '',
      status: data.status || 'pending',
      note: data.note || '',
      created_at: data.createdAt || new Date().toISOString(),
      updated_at: data.updatedAt || new Date().toISOString()
    });
  },

  findAll(filters = {}) {
    let results = feedbackQueries.findAll.all();
    if (filters.type && filters.type !== 'all') {
      results = results.filter(item => item.type === filters.type);
    }
    if (filters.status && filters.status !== 'all') {
      results = results.filter(item => item.status === filters.status);
    }
    return results;
  },

  findById(id) {
    return feedbackQueries.findById.get(id);
  },

  update(id, data) {
    return feedbackQueries.update.run({
      id,
      status: data.status,
      note: data.note,
      updated_at: new Date().toISOString()
    });
  },

  count() {
    return feedbackQueries.count.get().count;
  },

  getStats() {
    const all = feedbackQueries.findAll.all();
    return {
      total: all.length,
      byType: {
        bug: all.filter(item => item.type === 'bug').length,
        suggestion: all.filter(item => item.type === 'suggestion').length,
        inquiry: all.filter(item => item.type === 'inquiry').length
      },
      byStatus: {
        pending: all.filter(item => item.status === 'pending').length,
        processing: all.filter(item => item.status === 'processing').length,
        completed: all.filter(item => item.status === 'completed').length
      }
    };
  }
};

// ========== 管理统计 ==========
export const AdminStats = {
  getOverview() {
    return {
      users: Users.count(),
      reports: Reports.count(),
      feedback: Feedback.count()
    };
  },

  getUsageTrends(days = 7) {
    const stmt = db.prepare(`
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM usage_logs
      WHERE created_at >= datetime('now', '-${days} days')
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `);
    return stmt.all();
  },

  getUsersByPlan() {
    const stmt = db.prepare(`
      SELECT plan, COUNT(*) as count FROM users GROUP BY plan
    `);
    return stmt.all();
  },

  // 活跃用户统计
  getActiveUsers() {
    const daily = db.prepare(`
      SELECT COUNT(DISTINCT user_id) as count FROM usage_logs
      WHERE created_at >= datetime('now', '-1 day') AND user_id IS NOT NULL
    `).get();

    const weekly = db.prepare(`
      SELECT COUNT(DISTINCT user_id) as count FROM usage_logs
      WHERE created_at >= datetime('now', '-7 days') AND user_id IS NOT NULL
    `).get();

    const monthly = db.prepare(`
      SELECT COUNT(DISTINCT user_id) as count FROM usage_logs
      WHERE created_at >= datetime('now', '-30 days') AND user_id IS NOT NULL
    `).get();

    return {
      daily: daily.count,
      weekly: weekly.count,
      monthly: monthly.count
    };
  },

  // 角色使用分布
  getRoleDistribution() {
    const stmt = db.prepare(`
      SELECT role_type, COUNT(*) as count FROM reports
      GROUP BY role_type ORDER BY count DESC
    `);
    return stmt.all();
  },

  // 满意度统计
  getRatingStats() {
    const avg = db.prepare(`
      SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM report_ratings
    `).get();

    const distribution = db.prepare(`
      SELECT rating, COUNT(*) as count FROM report_ratings GROUP BY rating ORDER BY rating
    `).all();

    return {
      averageRating: avg.avg_rating ? Math.round(avg.avg_rating * 10) / 10 : null,
      totalRatings: avg.count,
      distribution
    };
  },

  // 今日统计
  getTodayStats() {
    const polishCount = db.prepare(`
      SELECT COUNT(*) as count FROM usage_logs
      WHERE action = 'polish' AND DATE(created_at) = DATE('now')
    `).get();

    const chatCount = db.prepare(`
      SELECT COUNT(*) as count FROM usage_logs
      WHERE action = 'chat' AND DATE(created_at) = DATE('now')
    `).get();

    const newUsers = db.prepare(`
      SELECT COUNT(*) as count FROM users
      WHERE DATE(created_at) = DATE('now')
    `).get();

    return {
      polishCount: polishCount.count,
      chatCount: chatCount.count,
      newUsers: newUsers.count
    };
  }
};

// ========== Prompts CRUD ==========
const promptQueries = {
  findAll: db.prepare(`
    SELECT * FROM prompts ORDER BY role_type, version DESC
  `),

  findActive: db.prepare(`
    SELECT * FROM prompts WHERE is_active = 1
  `),

  findByRoleType: db.prepare(`
    SELECT * FROM prompts WHERE role_type = ? AND is_active = 1 ORDER BY version DESC LIMIT 1
  `),

  findById: db.prepare(`
    SELECT * FROM prompts WHERE id = ?
  `),

  create: db.prepare(`
    INSERT INTO prompts (role_type, version, content, is_active)
    VALUES (@role_type, @version, @content, @is_active)
  `),

  update: db.prepare(`
    UPDATE prompts SET content = @content, updated_at = datetime('now')
    WHERE id = @id
  `),

  deactivate: db.prepare(`
    UPDATE prompts SET is_active = 0, updated_at = datetime('now')
    WHERE role_type = ? AND is_active = 1
  `),

  getMaxVersion: db.prepare(`
    SELECT MAX(version) as max_version FROM prompts WHERE role_type = ?
  `)
};

export const Prompts = {
  findAll() {
    return promptQueries.findAll.all();
  },

  findActive() {
    return promptQueries.findActive.all();
  },

  findByRoleType(roleType) {
    return promptQueries.findByRoleType.get(roleType);
  },

  findById(id) {
    return promptQueries.findById.get(id);
  },

  update(id, content) {
    return promptQueries.update.run({ id, content });
  },

  createNewVersion(roleType, content) {
    // 获取当前最大版本号
    const maxVersion = promptQueries.getMaxVersion.get(roleType)?.max_version || 0;

    // 停用当前活跃版本
    promptQueries.deactivate.run(roleType);

    // 创建新版本
    const result = promptQueries.create.run({
      role_type: roleType,
      version: maxVersion + 1,
      content,
      is_active: 1
    });

    return result.lastInsertRowid;
  },

  getActivePrompts() {
    const prompts = {};
    const active = promptQueries.findActive.all();
    for (const p of active) {
      prompts[p.role_type] = p.content;
    }
    return prompts;
  }
};

// 导出数据库实例（用于特殊操作）
export default db;
