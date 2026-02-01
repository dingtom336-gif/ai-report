/**
 * 数据库初始化和迁移脚本
 * 运行: node db/init.js
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import db, { Feedback, Users } from './database.js';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('========== 数据库初始化 ==========\n');

// 迁移旧的 feedback.json 数据
function migrateFeedback() {
  const feedbackFile = join(__dirname, '..', 'data', 'feedback.json');

  if (!existsSync(feedbackFile)) {
    console.log('[Feedback] 没有找到 feedback.json，跳过迁移');
    return;
  }

  try {
    const data = JSON.parse(readFileSync(feedbackFile, 'utf-8') || '[]');

    if (data.length === 0) {
      console.log('[Feedback] feedback.json 为空，跳过迁移');
      return;
    }

    // 检查是否已迁移
    const existingCount = Feedback.count();
    if (existingCount > 0) {
      console.log(`[Feedback] 数据库已有 ${existingCount} 条反馈，跳过迁移`);
      return;
    }

    console.log(`[Feedback] 开始迁移 ${data.length} 条反馈...`);

    for (const item of data) {
      try {
        Feedback.create({
          id: item.id,
          type: item.type,
          title: item.title,
          description: item.description,
          contact: item.contact,
          status: item.status,
          note: item.note,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt
        });
      } catch (e) {
        console.log(`  - 跳过重复项: ${item.id}`);
      }
    }

    console.log(`[Feedback] 迁移完成!`);
  } catch (e) {
    console.error('[Feedback] 迁移失败:', e.message);
  }
}

// 创建管理员账号
function createAdminUser() {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@ai-report.com';

  const existing = Users.findByEmail(adminEmail);
  if (existing) {
    console.log(`[Admin] 管理员账号已存在: ${adminEmail}`);
    return;
  }

  const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const passwordHash = bcrypt.hashSync(defaultPassword, 10);

  Users.create({
    email: adminEmail,
    password_hash: passwordHash,
    nickname: '管理员',
    role: 'admin',
    plan: 'pro'
  });

  console.log(`[Admin] 创建管理员账号: ${adminEmail}`);
  console.log(`[Admin] 默认密码: ${defaultPassword} (请尽快修改!)`);
}

// 验证表结构
function verifyTables() {
  const tables = db.prepare(`
    SELECT name FROM sqlite_master WHERE type='table' ORDER BY name
  `).all();

  console.log('\n[Tables] 已创建的表:');
  tables.forEach(t => {
    const count = db.prepare(`SELECT COUNT(*) as count FROM ${t.name}`).get().count;
    console.log(`  - ${t.name}: ${count} 条记录`);
  });
}

// 执行迁移
console.log('1. 迁移 feedback.json 数据...');
migrateFeedback();

console.log('\n2. 创建管理员账号...');
createAdminUser();

console.log('\n3. 验证表结构...');
verifyTables();

console.log('\n========== 初始化完成 ==========');
