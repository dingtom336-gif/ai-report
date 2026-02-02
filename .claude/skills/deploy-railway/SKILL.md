---
name: deploy-railway
description: Railway部署注意事项。当修改服务器配置、端口、文件路径、数据库路径时使用。
---

# Railway 部署规范

## 必须遵守
- 端口：process.env.PORT || 3000（Railway动态分配端口，写死3000会挂）
- 静态文件：path.join(__dirname, 'public')（必须绝对路径）
- 数据库：process.env.DATABASE_PATH || path.join(__dirname, 'data', 'app.db')

## package.json 必须有
```json
{
  "scripts": { "start": "node server.js" },
  "engines": { "node": ">=18.0.0" }
}
```

## 部署流程
git add . → git commit → git push origin main → 等2-5分钟

## 常见坑
- 不要用相对路径 './public'（Railway工作目录不确定）
- 不要hardcode端口3000
- 新CDN资源（如html2canvas、Chart.js）确认Railway网络可访问
- 新数据库表必须在 db/database.js 初始化函数中创建
