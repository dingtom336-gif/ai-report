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
  // 用户表 (支持手机号登录)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT UNIQUE,
      email TEXT UNIQUE,
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
  }
};

// 导出数据库实例（用于特殊操作）
export default db;
