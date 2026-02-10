# AI周报润色工具 (ai-report)

## 技术栈
- 后端：Node.js (>=18) + Express + better-sqlite3
- 前端：原生HTML/CSS/JS（无框架）
- AI服务：DeepSeek API（deepseek-chat模型）
- 部署：Railway（GitHub自动部署）
- 测试：Playwright（E2E）
- 模块系统：ES Modules（"type": "module"）

## 关键命令
- 启动：`npm start`（端口3000，浏览器打开 http://localhost:3000）
- 开发：`npm run dev`（带 --watch 自动重启）
- 测试：`npx playwright test`
- 部署：`git push origin main` → Railway 2-5分钟自动部署

## 线上地址
- 产品：https://ai-report-production-1b54.up.railway.app/
- Railway控制台：https://railway.com/project/d850dd65-b337-4ad1-b273-1ff41bd085fe

## 文件结构
```
server.js             # 所有API路由（1688行，待拆分到routes/）
db/database.js        # 数据库初始化和所有CRUD操作（1281行，待拆分）
db/init.js            # 数据库初始化脚本
middleware/auth.js     # JWT验证、密码哈希、token生成
middleware/paywall.js  # 付费墙、角色权限、用量限制
public/index.html      # 主页面（5483行，待拆分CSS/JS）
public/landing.html    # 落地页
public/login.html      # 登录页
public/history.html    # 历史记录页
public/admin.html      # 管理后台
public/submit.html     # 反馈提交页
public/mobile.html     # 移动端页面
public/js/performance-monitor.js  # 性能监控
public/vendor/         # 第三方库（chart.js, html2canvas）
docs/                  # 项目文档
tests/e2e/             # E2E测试用例
tests/screenshots/     # 测试截图（gitignore）
```

## 数据库表
users, verification_codes, reports, templates, chat_history, usage_logs, feedback, guest_usage, report_ratings, custom_roles, prompts

## 代码规范
- ES Modules：使用 import/export，不用 require
- API成功返回：`{ success: true, data: {} }`
- API失败返回：`{ success: false, message: '' }`
- 数据库操作全部写在 db/database.js，不散落在路由里
- better-sqlite3 是同步API，不需要 await
- 单文件不超过500行（当前有超标文件待重构）
- const/let，禁止var；2空格缩进

## 部署注意
- 端口必须用 `process.env.PORT || 3000`
- 静态文件：`path.join(__dirname, 'public')`
- 数据库：`process.env.DATABASE_PATH || path.join(__dirname, 'data', 'app.db')`
- 不要用相对路径
- Railway会自动运行 `npm start`

## 环境变量（Railway控制台设置）
- DEEPSEEK_API_KEY
- JWT_SECRET
- DATABASE_PATH
- ADMIN_EMAIL
- ADMIN_PASSWORD

## 当前版本
v2.6.1

## 已知问题
- index.html 超过5000行，需要拆分CSS和JS到独立文件
- server.js 1688行，路由未拆分到 routes/ 目录
- db/database.js 1281行，需要按领域拆分
