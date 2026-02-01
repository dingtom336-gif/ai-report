# AI Report 项目

## Claude 工作模式（重要）

- **默认使用 Plan Mode**：每次开始新对话时，自动进入计划模式
- 先分析需求、制定实施计划，等用户确认后再执行
- 用户会手动输入命令切换到正常模式

## 项目信息
- **项目名称**：ai-report（AI周报润色工具）
- **本地开发路径**：/Users/xiaozhang/Desktop/claude-test/feedback-system
- **Git 仓库路径**：/Users/xiaozhang/Desktop/claude-test/ai-report
- **线上地址**：https://ai-report-production-1b54.up.railway.app/
- **GitHub**：https://github.com/dingtom336-gif/ai-report
- **技术栈**：Node.js + Express

## 开发工作流（必须遵守）

每次修改代码后，必须执行以下步骤：

1. **同步文件**：将 feedback-system 的修改同步到 ai-report
   ```bash
   cp /Users/xiaozhang/Desktop/claude-test/feedback-system/server.js /Users/xiaozhang/Desktop/claude-test/ai-report/
   cp /Users/xiaozhang/Desktop/claude-test/feedback-system/public/index.html /Users/xiaozhang/Desktop/claude-test/ai-report/public/
   ```

2. **提交推送**：
   ```bash
   cd /Users/xiaozhang/Desktop/claude-test/ai-report
   git add .
   git commit -m "修改描述"
   git push origin main
   ```

3. **通知用户**：告知"已推送，等待 2-5 分钟后刷新线上验证"

4. **验证上线**：https://ai-report-production-1b54.up.railway.app/

## 关键原则

- **不要让修改停留在本地**：改完就推，不要攒着
- **用户测试环境是线上**：不是 localhost，是 Railway 部署的线上版本
- **先推送再继续**：不要连续修改多次才推送一次

## Railway 部署信息
- 控制台：https://railway.com/project/d850dd65-b337-4ad1-b273-1ff41bd085fe
- 部署方式：GitHub 自动部署（push 后自动触发）
- 部署时间：约 2-5 分钟
