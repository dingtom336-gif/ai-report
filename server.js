import express from 'express';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import https from 'https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { randomUUID } from 'crypto';

// 数据库和认证模块
import { Users, Reports, Templates, ChatHistory, UsageLogs, Feedback, AdminStats } from './db/database.js';
import { generateToken, verifyPassword, hashPassword, verifyToken, optionalToken, requireAdmin, checkUsageLimit } from './middleware/auth.js';
import { checkRoleAccess, checkChatAccess, checkTemplateAccess, getHistoryLimit, getUserPermissions } from './middleware/paywall.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '.env') });

console.log('API Key loaded:', process.env.DEEPSEEK_API_KEY ? process.env.DEEPSEEK_API_KEY.substring(0, 10) + '...' : 'NOT SET');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(join(__dirname, 'public')));

// 根路径重定向
app.get('/', (req, res) => {
  res.redirect('/index.html');
});

// 代理配置
const proxyUrl = process.env.HTTP_PROXY || process.env.https_proxy || process.env.http_proxy;
const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;
console.log('Proxy:', proxyUrl || 'disabled');

// 各角色的 Prompt
const ROLE_PROMPTS = {
  dev: `你是互联网大厂技术总监，带过百人研发团队。

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

现在改写：`,

  ops: `你是互联网大厂运营总监，操盘过亿级用户增长。

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

现在改写：`,

  pm: `你是互联网大厂P9产品总监，带过50人团队，深谙向上汇报的艺术。

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
};

// 构建 Prompt
function buildPrompt(content, role, template, useTemplate) {
  if (useTemplate && template) {
    return `你是互联网大厂资深总监。

【任务】将用户的随意输入，改写成结构化的高质量周报。

【用户提供的范本】
以下是用户认可的周报风格，请学习其结构、语气、表达方式：
"""
${template}
"""

【改写要求】
1. 模仿范本的结构和分段方式
2. 学习范本的语气和措辞风格
3. 保持范本的专业程度
4. 从用户输入中提取关键信息，按范本格式重组
5. 补充量化数据（如用户未提供，用[待补充]标记）

【用户原始输入】
"""
${content}
"""

请输出改写后的周报：`;
  }

  const rolePrompt = ROLE_PROMPTS[role] || ROLE_PROMPTS.pm;
  return rolePrompt + '\n' + content;
}

// 调用 DeepSeek API
function callDeepSeekAPI(prompt) {
  return new Promise((resolve, reject) => {
    const apiKey = process.env.DEEPSEEK_API_KEY;

    const postData = JSON.stringify({
      model: 'deepseek-chat',
      messages: [{ role: 'user', content: prompt }]
    });

    const options = {
      hostname: 'api.deepseek.com',
      port: 443,
      path: '/v1/chat/completions',
      method: 'POST',
      ...(agent && { agent }),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode !== 200) {
            const error = new Error(parsed.error?.message || 'API 调用失败');
            error.status = res.statusCode;
            error.data = parsed;
            reject(error);
          } else {
            resolve(parsed);
          }
        } catch (e) {
          reject(new Error('解析响应失败'));
        }
      });
    });

    req.on('error', (e) => reject(e));
    req.write(postData);
    req.end();
  });
}

// ReAct Agent Prompt 构建
function buildChatPrompt(currentReport, message, history = []) {
  const historyText = history.slice(-10).map(h =>
    `用户: ${h.user}\n助手: ${h.assistant}`
  ).join('\n\n');

  return `你是一个周报修改助手，采用ReAct模式工作。

【当前周报内容】
"""
${currentReport}
"""

${historyText ? `【对话历史】\n${historyText}\n\n` : ''}【用户指令】
${message}

【你的工作流程】
1. **Thought**: 分析用户想要什么修改，识别修改类型：
   - 内容修改（增/删/改具体内容）
   - 风格调整（语气、措辞、专业度）
   - 结构调整（顺序、分组、格式）
   - 细节优化（数据、用词、标点）

2. **Action**: 执行修改，输出完整的新版周报

3. **Observation**: 简要说明做了什么改动（一句话）

【输出格式要求】
必须严格按以下XML格式输出，不要有其他内容：

<thought>
[你的分析，1-2句话]
</thought>

<action>
[完整的修改后周报，保持原有的markdown格式]
</action>

<observation>
[改动说明，1句话，以"已"开头]
</observation>`;
}

// 解析 ReAct 响应
function parseReActResponse(response) {
  const thoughtMatch = response.match(/<thought>([\s\S]*?)<\/thought>/);
  const actionMatch = response.match(/<action>([\s\S]*?)<\/action>/);
  const observationMatch = response.match(/<observation>([\s\S]*?)<\/observation>/);

  return {
    thought: thoughtMatch ? thoughtMatch[1].trim() : '正在分析修改需求...',
    newReport: actionMatch ? actionMatch[1].trim() : response,
    observation: observationMatch ? observationMatch[1].trim() : '已完成修改'
  };
}

// ========== 认证 API ==========

// 注册
app.post('/api/auth/register', async (req, res) => {
  const { email, password, nickname } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: '邮箱和密码不能为空' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: '密码至少6位' });
  }

  // 检查邮箱是否已存在
  const existing = Users.findByEmail(email);
  if (existing) {
    return res.status(400).json({ error: '该邮箱已注册' });
  }

  try {
    const passwordHash = hashPassword(password);
    const userId = Users.create({
      email,
      password_hash: passwordHash,
      nickname: nickname || email.split('@')[0]
    });

    const user = Users.findById(userId);
    Users.updateLastLogin(userId);

    // 记录注册日志
    UsageLogs.create({ user_id: userId, action: 'register' });

    const token = generateToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        plan: user.plan
      }
    });
  } catch (error) {
    console.error('注册失败:', error);
    res.status(500).json({ error: '注册失败，请稍后重试' });
  }
});

// 登录
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: '邮箱和密码不能为空' });
  }

  const user = Users.findByEmail(email);
  if (!user) {
    return res.status(401).json({ error: '邮箱或密码错误' });
  }

  if (!verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: '邮箱或密码错误' });
  }

  Users.updateLastLogin(user.id);
  UsageLogs.create({ user_id: user.id, action: 'login' });

  const token = generateToken(user);
  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      nickname: user.nickname,
      role: user.role,
      plan: user.plan
    }
  });
});

// 获取当前用户信息
app.get('/api/auth/me', verifyToken, (req, res) => {
  const permissions = getUserPermissions(req.user);
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      nickname: req.user.nickname,
      role: req.user.role,
      plan: req.user.plan,
      daily_usage: req.user.daily_usage
    },
    permissions
  });
});

// ========== 润色接口 (支持登录和游客) ==========
app.post('/api/polish', optionalToken, checkRoleAccess, async (req, res) => {
  const { content, role = 'pm', template, useTemplate } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: '请输入周报内容' });
  }

  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(500).json({ error: 'API Key 未配置' });
  }

  // 登录用户检查用量
  if (req.user) {
    const usageResult = Users.checkAndIncrementUsage(req.user);
    if (!usageResult.allowed) {
      return res.status(429).json({
        error: '今日免费次数已用完',
        code: 'DAILY_LIMIT_REACHED',
        limit: usageResult.limit
      });
    }
  }

  const validRoles = ['dev', 'ops', 'pm'];
  const finalRole = validRoles.includes(role) ? role : 'pm';

  try {
    const prompt = buildPrompt(content, finalRole, template, useTemplate);
    const data = await callDeepSeekAPI(prompt);
    const result = data.choices[0].message.content;

    // 登录用户保存周报
    let reportId = null;
    if (req.user) {
      reportId = Reports.create({
        user_id: req.user.id,
        original_content: content,
        polished_content: result,
        role_type: finalRole,
        used_template: useTemplate && template
      });
      UsageLogs.create({
        user_id: req.user.id,
        action: 'polish',
        metadata: { role: finalRole, reportId }
      });
    }

    res.json({
      result,
      reportId,
      usageInfo: req.user ? {
        remaining: req.user.plan === 'pro' ? null : (3 - req.user.daily_usage - 1),
        limit: req.user.plan === 'pro' ? null : 3
      } : null
    });
  } catch (error) {
    console.error('API 调用失败:', error.status, error.data || error.message);

    if (error.status === 401) {
      return res.status(401).json({ error: 'API Key 无效' });
    }
    if (error.status === 429) {
      return res.status(429).json({ error: '请求过于频繁，请稍后重试' });
    }

    res.status(500).json({ error: `润色失败: ${error.message || '请稍后重试'}` });
  }
});

// ========== AI 对话修改接口 (需要登录+Pro) ==========
app.post('/api/chat', verifyToken, checkChatAccess, async (req, res) => {
  const { currentReport, message, history = [], reportId } = req.body;

  if (!currentReport || !currentReport.trim()) {
    return res.status(400).json({ error: '当前周报内容不能为空' });
  }

  if (!message || !message.trim()) {
    return res.status(400).json({ error: '请输入修改指令' });
  }

  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(500).json({ error: 'API Key 未配置' });
  }

  try {
    const prompt = buildChatPrompt(currentReport, message, history);
    const data = await callDeepSeekAPI(prompt);
    const rawResponse = data.choices[0].message.content;
    const parsed = parseReActResponse(rawResponse);

    // 保存对话历史
    if (reportId) {
      ChatHistory.create({
        report_id: reportId,
        user_message: message,
        ai_thought: parsed.thought,
        ai_action: parsed.newReport,
        ai_observation: parsed.observation
      });

      // 更新周报内容
      Reports.update(reportId, parsed.newReport);
    }

    UsageLogs.create({
      user_id: req.user.id,
      action: 'chat',
      metadata: { reportId }
    });

    res.json(parsed);
  } catch (error) {
    console.error('Chat API 调用失败:', error.status, error.data || error.message);

    if (error.status === 401) {
      return res.status(401).json({ error: 'API Key 无效' });
    }
    if (error.status === 429) {
      return res.status(429).json({ error: '请求过于频繁，请稍后重试' });
    }

    res.status(500).json({ error: `修改失败: ${error.message || '请稍后重试'}` });
  }
});

// ========== 周报历史 API ==========
app.get('/api/reports', verifyToken, (req, res) => {
  const limit = getHistoryLimit(req.user);
  const reports = Reports.findByUserId(req.user.id, limit);
  res.json({
    reports,
    limit,
    total: Reports.countByUserId(req.user.id)
  });
});

app.get('/api/reports/:id', verifyToken, (req, res) => {
  const report = Reports.findById(req.params.id);
  if (!report || report.user_id !== req.user.id) {
    return res.status(404).json({ error: '周报不存在' });
  }

  const chatHistory = ChatHistory.findByReportId(report.id);
  res.json({ report, chatHistory });
});

app.delete('/api/reports/:id', verifyToken, (req, res) => {
  const result = Reports.delete(req.params.id, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: '周报不存在' });
  }
  res.json({ success: true });
});

// ========== 范本 API (Pro) ==========
app.get('/api/templates', verifyToken, (req, res) => {
  const templates = Templates.findByUserId(req.user.id);
  res.json(templates);
});

app.post('/api/templates', verifyToken, checkTemplateAccess, (req, res) => {
  const { name, content } = req.body;
  if (!content) {
    return res.status(400).json({ error: '范本内容不能为空' });
  }

  const id = Templates.create({
    user_id: req.user.id,
    name: name || '默认范本',
    content
  });

  res.json({ success: true, id });
});

app.put('/api/templates/:id', verifyToken, checkTemplateAccess, (req, res) => {
  const { name, content } = req.body;
  Templates.update(req.params.id, req.user.id, { name, content });
  res.json({ success: true });
});

app.delete('/api/templates/:id', verifyToken, (req, res) => {
  Templates.delete(req.params.id, req.user.id);
  res.json({ success: true });
});

// ========== 用户统计 ==========
app.get('/api/user/stats', verifyToken, (req, res) => {
  const reportCount = Reports.countByUserId(req.user.id);
  const templates = Templates.findByUserId(req.user.id);

  res.json({
    reports: reportCount,
    templates: templates.length,
    plan: req.user.plan,
    daily_usage: req.user.daily_usage,
    permissions: getUserPermissions(req.user)
  });
});

// ========== 埋点 API ==========
app.post('/api/log', optionalToken, (req, res) => {
  const { action, metadata } = req.body;
  UsageLogs.create({
    user_id: req.user?.id || null,
    action,
    metadata
  });
  res.json({ success: true });
});

// ========== 反馈系统 API (使用数据库) ==========
app.post('/api/feedback', optionalToken, (req, res) => {
  const { type, title, description, contact } = req.body;
  if (!type || !title || !description) {
    return res.status(400).json({ error: '请填写完整信息' });
  }

  Feedback.create({
    id: randomUUID(),
    type,
    title,
    description,
    contact: contact || '',
    status: 'pending',
    note: ''
  });

  res.json({ success: true });
});

app.get('/api/feedback', (req, res) => {
  const { type, status } = req.query;
  const data = Feedback.findAll({ type, status });
  res.json(data);
});

app.put('/api/feedback/:id', verifyToken, requireAdmin, (req, res) => {
  const { status, note } = req.body;
  const feedback = Feedback.findById(req.params.id);
  if (!feedback) {
    return res.status(404).json({ error: '反馈不存在' });
  }

  Feedback.update(req.params.id, { status, note });
  res.json({ success: true });
});

app.get('/api/stats', (req, res) => {
  res.json(Feedback.getStats());
});

// ========== 管理后台 API ==========
app.get('/api/admin/stats', verifyToken, requireAdmin, (req, res) => {
  const overview = AdminStats.getOverview();
  const feedbackStats = Feedback.getStats();

  res.json({
    ...overview,
    feedback: feedbackStats
  });
});

app.get('/api/admin/users', verifyToken, requireAdmin, (req, res) => {
  const users = Users.listAll();
  res.json(users);
});

app.get('/api/admin/trends', verifyToken, requireAdmin, (req, res) => {
  const days = parseInt(req.query.days) || 7;
  const trends = AdminStats.getUsageTrends(days);
  const usersByPlan = AdminStats.getUsersByPlan();

  res.json({ trends, usersByPlan });
});

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
