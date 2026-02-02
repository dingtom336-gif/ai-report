# AI周报润色工具 (ai-report)

## 技术栈
- 后端：Node.js + Express + better-sqlite3
- 前端：原生HTML/CSS/JS（无框架）
- AI服务：DeepSeek API（deepseek-chat模型）
- 部署：Railway（GitHub自动部署）

## 关键命令
- 启动：npm start（端口3000，浏览器打开 http://localhost:3000）
- 部署：git push origin main → Railway 2-5分钟自动部署

## 线上地址
- 产品：https://ai-report-production-1b54.up.railway.app/
- Railway控制台：https://railway.com/project/d850dd65-b337-4ad1-b273-1ff41bd085fe

## 文件结构
- server.js：所有API路由（待拆分到routes/）
- db/database.js：数据库初始化和所有CRUD操作
- middleware/auth.js：JWT验证中间件
- middleware/paywall.js：付费墙中间件
- public/index.html：主页面（当前3000+行，待拆分）
- public/landing.html：落地页
- public/login.html：登录页
- public/history.html：历史记录页
- public/admin.html：管理后台
- public/submit.html：反馈提交页

## 数据库表
users, verification_codes, reports, templates, chat_history, usage_logs, feedback

## 代码规范
- API成功返回：{ success: true, data: {} }
- API失败返回：{ success: false, message: '' }
- 数据库操作全部写在 db/database.js，不散落在路由里
- better-sqlite3 是同步API，不需要 await

## 部署注意
- 端口必须用 process.env.PORT || 3000
- 静态文件：path.join(__dirname, 'public')
- 数据库：process.env.DATABASE_PATH || path.join(__dirname, 'data', 'app.db')
- 不要用相对路径

## 环境变量（Railway控制台设置）
- DEEPSEEK_API_KEY
- JWT_SECRET
- DATABASE_PATH
- ADMIN_EMAIL
- ADMIN_PASSWORD

## 当前版本
v2.0.0

## 已知问题
- index.html 超过3000行，需要拆分CSS和JS到独立文件
- server.js 路由未拆分到 routes/ 目录
