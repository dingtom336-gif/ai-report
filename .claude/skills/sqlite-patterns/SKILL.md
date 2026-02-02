---
name: sqlite-patterns
description: SQLite数据库操作规范（better-sqlite3）。当创建表、写SQL查询、修改数据库时使用。
---

# SQLite 操作规范

## 核心原则
- 所有数据库操作写在 db/database.js 中
- 使用 prepare() 预编译，防止SQL注入
- better-sqlite3 是同步API，不需要await

## 常用写法
```javascript
// 查单条
const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

// 查多条
const reports = db.prepare('SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').all(userId, limit);

// 插入并获取新ID
const result = db.prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)').run(userId, content);
const newId = result.lastInsertRowid;

// 计数
const { count } = db.prepare('SELECT COUNT(*) as count FROM reports WHERE user_id = ?').get(userId);
```

## 禁止
- 不要字符串拼接SQL（安全隐患）
- 不要在路由文件里直接写db操作（统一放database.js）
- 不要忘记 user_id 权限校验（防止A看到B的数据）
