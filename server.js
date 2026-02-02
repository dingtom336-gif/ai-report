import express from 'express';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import https from 'https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { randomUUID } from 'crypto';

// 数据库和认证模块
import { Users, Reports, Templates, ChatHistory, UsageLogs, Feedback, AdminStats, VerificationCodes, GuestUsage, ReportRatings, CustomRoles, Prompts } from './db/database.js';
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

// 根路径重定向到 Landing Page
app.get('/', (req, res) => {
  res.redirect('/landing.html');
});

// 获取客户端真实 IP（支持代理）
function getClientIp(req) {
  return req.headers['x-real-ip'] ||
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.ip ||
         req.connection?.remoteAddress ||
         'unknown';
}

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
function buildPrompt(content, role, template, useTemplate, customPrompt = null) {
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

  // 自定义角色 prompt
  if (customPrompt) {
    return customPrompt + '\n\n现在改写以下周报：\n' + content;
  }

  // 优先从数据库获取 prompt，如果没有则使用硬编码的默认值
  const dbPrompt = Prompts.findByRoleType(role);
  if (dbPrompt) {
    return dbPrompt.content + '\n' + content;
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

// 流式调用 DeepSeek API
function callDeepSeekAPIStream(prompt, onChunk, onDone, onError) {
  const apiKey = process.env.DEEPSEEK_API_KEY;

  const postData = JSON.stringify({
    model: 'deepseek-chat',
    messages: [{ role: 'user', content: prompt }],
    stream: true
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
    if (res.statusCode !== 200) {
      let errorData = '';
      res.on('data', (chunk) => errorData += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(errorData);
          onError(new Error(parsed.error?.message || `API 错误: ${res.statusCode}`));
        } catch {
          onError(new Error(`API 错误: ${res.statusCode}`));
        }
      });
      return;
    }

    let buffer = '';
    let fullContent = '';

    res.on('data', (chunk) => {
      buffer += chunk.toString();

      // 处理 SSE 格式数据
      const lines = buffer.split('\n');
      buffer = lines.pop() || ''; // 保留不完整的行

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data:')) continue;

        const data = trimmed.slice(5).trim();
        if (data === '[DONE]') {
          onDone(fullContent);
          return;
        }

        try {
          const parsed = JSON.parse(data);
          const content = parsed.choices?.[0]?.delta?.content;
          if (content) {
            fullContent += content;
            onChunk(content);
          }
        } catch {
          // 忽略解析错误
        }
      }
    });

    res.on('end', () => {
      // 处理剩余 buffer
      if (buffer.trim()) {
        const trimmed = buffer.trim();
        if (trimmed.startsWith('data:')) {
          const data = trimmed.slice(5).trim();
          if (data !== '[DONE]') {
            try {
              const parsed = JSON.parse(data);
              const content = parsed.choices?.[0]?.delta?.content;
              if (content) {
                fullContent += content;
                onChunk(content);
              }
            } catch {}
          }
        }
      }
      onDone(fullContent);
    });

    res.on('error', onError);
  });

  req.on('error', onError);
  req.write(postData);
  req.end();

  return req;
}

// ReAct Agent Prompt 构建（含反思机制和意图理解增强）
function buildChatPrompt(currentReport, message, history = []) {
  const historyText = history.slice(-10).map(h =>
    `用户: ${h.user}\n助手: ${h.assistant}`
  ).join('\n\n');

  return `你是一个专业的周报修改助手，采用 ReAct + Reflection 模式工作。

【核心能力：意图理解】
你必须具备以下意图理解能力：

1. **错别字/谐音纠正**：
   - "型号" → "星号" → "*"
   - "井号" → "#"
   - "斜杠" → "/"
   - "冒号" → ":"
   - 理解用户口语化、非标准表达

2. **模糊意图推断**：
   - "简洁点" → 删除冗余修饰词，缩短句子
   - "专业点" → 使用行业术语，量化表达
   - "去掉那些符号" → 根据上下文判断指哪些符号

3. **复合意图拆解**：
   - "去掉星号和井号" → 同时执行两个操作
   - "第一条简洁点，第二条加数据" → 针对不同段落不同操作

4. **概率意图选择**：
   - 当意图有多种可能时，选择最合理的解释
   - 如不确定，在 thought 中说明你的理解，让用户可以纠正

【当前周报内容】
"""
${currentReport}
"""

${historyText ? `【对话历史】\n${historyText}\n\n` : ''}【用户指令】
${message}

【工作流程：ReAct + Reflection】

**Step 1 - Thought（思考）**：
- 解析用户的真实意图（注意错别字、口语化表达）
- 明确要修改什么、怎么改
- 如果意图模糊，说明你的理解

**Step 2 - Action（执行）**：
- 根据理解执行修改
- 输出完整的新版周报

**Step 3 - Reflection（反思）**：
- 检查修改是否完全满足用户意图
- 是否有遗漏或误解
- 确认无误后输出 observation

【输出格式要求】
严格按以下XML格式输出：

<thought>
[1-2句话：解析用户意图，说明你理解的修改需求]
</thought>

<action>
[完整的修改后周报，保持原有格式]
</action>

<observation>
[1句话：以"已"开头，说明具体改动]
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

// 发送验证码
app.post('/api/auth/send-code', async (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ error: '请输入手机号' });
  }

  // 验证手机号格式
  if (!/^1[3-9]\d{9}$/.test(phone)) {
    return res.status(400).json({ error: '手机号格式不正确' });
  }

  try {
    const code = VerificationCodes.generate(phone);

    // TODO: 接入真实短信服务发送验证码
    // 模拟模式下，验证码固定为 123456
    console.log(`[验证码] ${phone}: ${code}`);

    UsageLogs.create({ action: 'send_code', metadata: { phone: phone.slice(0, 3) + '****' + phone.slice(-4) } });

    // TODO: 接入短信服务后移除 code 返回
    // 当前测试阶段始终返回验证码
    res.json({
      success: true,
      message: '验证码已发送',
      devMode: true,
      code
    });
  } catch (error) {
    console.error('发送验证码失败:', error);
    res.status(500).json({ error: '发送失败，请稍后重试' });
  }
});

// 手机号验证码登录（自动注册）
app.post('/api/auth/login', async (req, res) => {
  const { phone, code, email, password } = req.body;

  // 管理员邮箱密码登录
  if (email && password) {
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
    return res.json({
      token,
      user: {
        id: user.id,
        phone: user.phone,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        plan: user.plan
      }
    });
  }

  // 手机号验证码登录
  if (!phone || !code) {
    return res.status(400).json({ error: '请输入手机号和验证码' });
  }

  // 验证验证码
  const isValid = VerificationCodes.verify(phone, code);

  // 记录验证结果日志
  UsageLogs.create({
    action: 'verify_code',
    metadata: {
      phone: phone.slice(0, 3) + '****' + phone.slice(-4),
      success: isValid
    }
  });

  if (!isValid) {
    return res.status(401).json({ error: '验证码错误或已过期' });
  }

  try {
    // 查找或创建用户
    let user = Users.findByPhone(phone);
    let isNewUser = false;

    if (!user) {
      // 自动注册
      const userId = Users.createByPhone({
        phone,
        nickname: '用户' + phone.slice(-4)
      });
      user = Users.findById(userId);
      isNewUser = true;
      UsageLogs.create({ user_id: userId, action: 'register' });
    }

    Users.updateLastLogin(user.id);
    UsageLogs.create({ user_id: user.id, action: 'login' });

    const token = generateToken(user);
    res.json({
      token,
      isNewUser,
      user: {
        id: user.id,
        phone: user.phone,
        nickname: user.nickname,
        role: user.role,
        plan: user.plan
      }
    });
  } catch (error) {
    console.error('登录失败:', error);
    res.status(500).json({ error: '登录失败，请稍后重试' });
  }
});

// 获取当前用户信息
app.get('/api/auth/me', verifyToken, (req, res) => {
  const permissions = getUserPermissions(req.user);
  res.json({
    user: {
      id: req.user.id,
      phone: req.user.phone,
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

  // 用量检查
  let usageInfo = null;

  if (req.user) {
    // 登录用户检查用量
    const usageResult = Users.checkAndIncrementUsage(req.user);
    if (!usageResult.allowed) {
      return res.status(429).json({
        error: '今日免费次数已用完',
        code: 'DAILY_LIMIT_REACHED',
        limit: usageResult.limit
      });
    }
    usageInfo = {
      remaining: req.user.plan === 'pro' ? null : usageResult.remaining,
      limit: req.user.plan === 'pro' ? null : usageResult.limit
    };
  } else {
    // 游客检查 IP 用量限制（3 次/天）
    const clientIp = getClientIp(req);
    const guestResult = GuestUsage.checkAndIncrement(clientIp, 3);
    if (!guestResult.allowed) {
      return res.status(429).json({
        error: '游客试用次数已用完，请登录后继续使用',
        code: 'GUEST_LIMIT_REACHED',
        limit: guestResult.limit
      });
    }
    usageInfo = {
      remaining: guestResult.remaining,
      limit: guestResult.limit,
      isGuest: true
    };
  }

  const validRoles = ['dev', 'ops', 'pm'];
  let finalRole = validRoles.includes(role) ? role : 'pm';
  let customPrompt = null;

  // 检查是否使用自定义角色
  if (role && role.startsWith('custom_')) {
    const customRoleId = parseInt(role.split('_')[1], 10);
    if (!isNaN(customRoleId)) {
      const customRole = CustomRoles.findById(customRoleId);
      if (customRole && req.user && customRole.user_id === req.user.id) {
        customPrompt = customRole.prompt;
        finalRole = 'custom';
      }
    }
  }

  try {
    const prompt = buildPrompt(content, finalRole, template, useTemplate, customPrompt);
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
      usageInfo
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

// ========== 流式润色接口 ==========
app.post('/api/polish/stream', optionalToken, checkRoleAccess, async (req, res) => {
  const { content, role = 'pm', template, useTemplate } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: '请输入周报内容' });
  }

  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(500).json({ error: 'API Key 未配置' });
  }

  // 用量检查
  let usageInfo = null;

  if (req.user) {
    const usageResult = Users.checkAndIncrementUsage(req.user);
    if (!usageResult.allowed) {
      return res.status(429).json({
        error: '今日免费次数已用完',
        code: 'DAILY_LIMIT_REACHED',
        limit: usageResult.limit
      });
    }
    usageInfo = {
      remaining: req.user.plan === 'pro' ? null : usageResult.remaining,
      limit: req.user.plan === 'pro' ? null : usageResult.limit
    };
  } else {
    const clientIp = getClientIp(req);
    const guestResult = GuestUsage.checkAndIncrement(clientIp, 3);
    if (!guestResult.allowed) {
      return res.status(429).json({
        error: '游客试用次数已用完，请登录后继续使用',
        code: 'GUEST_LIMIT_REACHED',
        limit: guestResult.limit
      });
    }
    usageInfo = {
      remaining: guestResult.remaining,
      limit: guestResult.limit,
      isGuest: true
    };
  }

  const validRoles = ['dev', 'ops', 'pm'];
  let finalRole = validRoles.includes(role) ? role : 'pm';
  let customPrompt = null;

  // 检查是否使用自定义角色
  if (role && role.startsWith('custom_')) {
    const customRoleId = parseInt(role.split('_')[1], 10);
    if (!isNaN(customRoleId)) {
      const customRole = CustomRoles.findById(customRoleId);
      if (customRole && req.user && customRole.user_id === req.user.id) {
        customPrompt = customRole.prompt;
        finalRole = 'custom';
      }
    }
  }

  const prompt = buildPrompt(content, finalRole, template, useTemplate, customPrompt);

  // 设置 SSE 响应头
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // 禁用 Nginx/代理缓冲
  res.flushHeaders(); // 立即发送响应头

  // 禁用 Nagle 算法，确保数据立即发送
  if (res.socket) {
    res.socket.setNoDelay(true);
  }

  // 发送初始事件（用量信息）
  res.write(`data: ${JSON.stringify({ type: 'start', usageInfo })}\n\n`);

  callDeepSeekAPIStream(
    prompt,
    // onChunk
    (chunk) => {
      res.write(`data: ${JSON.stringify({ type: 'chunk', content: chunk })}\n\n`);
    },
    // onDone
    (fullContent) => {
      // 登录用户保存周报
      let reportId = null;
      if (req.user) {
        reportId = Reports.create({
          user_id: req.user.id,
          original_content: content,
          polished_content: fullContent,
          role_type: finalRole,
          used_template: useTemplate && template
        });
        UsageLogs.create({
          user_id: req.user.id,
          action: 'polish',
          metadata: { role: finalRole, reportId, stream: true }
        });
      }

      res.write(`data: ${JSON.stringify({ type: 'done', reportId })}\n\n`);
      res.end();
    },
    // onError
    (error) => {
      console.error('流式 API 调用失败:', error.message);
      res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`);
      res.end();
    }
  );

  // 客户端断开连接时清理
  res.on('close', () => {
    // 响应关闭，无需额外处理
  });
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

// ========== 流式 AI 对话修改接口 ==========
app.post('/api/chat/stream', verifyToken, checkChatAccess, async (req, res) => {
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

  const prompt = buildChatPrompt(currentReport, message, history);

  // 设置 SSE 响应头
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  if (res.socket) {
    res.socket.setNoDelay(true);
  }

  res.write(`data: ${JSON.stringify({ type: 'start' })}\n\n`);

  callDeepSeekAPIStream(
    prompt,
    // onChunk
    (chunk) => {
      res.write(`data: ${JSON.stringify({ type: 'chunk', content: chunk })}\n\n`);
    },
    // onDone
    (fullContent) => {
      const parsed = parseReActResponse(fullContent);

      // 保存对话历史
      if (reportId) {
        ChatHistory.create({
          report_id: reportId,
          user_message: message,
          ai_thought: parsed.thought,
          ai_action: parsed.newReport,
          ai_observation: parsed.observation
        });

        Reports.update(reportId, parsed.newReport);
      }

      UsageLogs.create({
        user_id: req.user.id,
        action: 'chat',
        metadata: { reportId, stream: true }
      });

      res.write(`data: ${JSON.stringify({ type: 'done', parsed })}\n\n`);
      res.end();
    },
    // onError
    (error) => {
      console.error('流式 Chat API 调用失败:', error.message);
      res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`);
      res.end();
    }
  );

  // 客户端断开连接时清理
  res.on('close', () => {
    // 响应关闭，无需额外处理
  });
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

// ========== 评分 API ==========
app.post('/api/reports/:id/rating', optionalToken, (req, res) => {
  const { rating, feedback } = req.body;
  const reportId = parseInt(req.params.id);

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: '评分必须是1-5之间的整数' });
  }

  try {
    ReportRatings.upsert({
      report_id: reportId,
      user_id: req.user?.id || null,
      rating: Math.round(rating),
      feedback: feedback || null
    });

    res.json({ success: true });
  } catch (error) {
    console.error('保存评分失败:', error);
    res.status(500).json({ error: '保存失败' });
  }
});

app.get('/api/reports/:id/rating', (req, res) => {
  const reportId = parseInt(req.params.id);
  const rating = ReportRatings.findByReportId(reportId);
  res.json(rating || { rating: null });
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

// ========== 自定义角色 API (Pro) ==========
const MAX_CUSTOM_ROLES = 5;

app.get('/api/roles', verifyToken, (req, res) => {
  const roles = CustomRoles.findByUserId(req.user.id);
  res.json(roles);
});

app.post('/api/roles', verifyToken, checkTemplateAccess, async (req, res) => {
  const { name, description, icon } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ error: '请输入角色名称' });
  }

  // 检查数量限制
  const count = CustomRoles.countByUserId(req.user.id);
  if (count >= MAX_CUSTOM_ROLES) {
    return res.status(400).json({
      error: `最多创建 ${MAX_CUSTOM_ROLES} 个自定义角色`,
      code: 'ROLE_LIMIT_REACHED'
    });
  }

  try {
    // 使用 DeepSeek 生成 prompt
    const promptGenRequest = `你是一个 prompt 工程专家。用户想创建一个周报润色角色。

角色名称：${name}
角色描述：${description || '无'}

请为这个角色生成一个专业的 prompt，用于指导 AI 如何润色周报。
要求：
1. 理解该角色的工作特点和汇报风格
2. 包含具体的改写原则（3-5条）
3. 包含输出格式示例
4. 语言简洁专业

直接输出 prompt 内容，不要有其他说明。`;

    const data = await callDeepSeekAPI(promptGenRequest);
    const generatedPrompt = data.choices[0].message.content;

    const id = CustomRoles.create({
      user_id: req.user.id,
      name: name.trim(),
      description: description?.trim() || '',
      prompt: generatedPrompt,
      icon: icon || '🎯'
    });

    res.json({
      success: true,
      id,
      prompt: generatedPrompt
    });
  } catch (error) {
    console.error('创建自定义角色失败:', error);
    res.status(500).json({ error: '创建失败，请稍后重试' });
  }
});

app.get('/api/roles/:id', verifyToken, (req, res) => {
  const role = CustomRoles.findById(req.params.id);
  if (!role || role.user_id !== req.user.id) {
    return res.status(404).json({ error: '角色不存在' });
  }
  res.json(role);
});

app.put('/api/roles/:id', verifyToken, checkTemplateAccess, (req, res) => {
  const { name, description, prompt, icon } = req.body;

  const role = CustomRoles.findById(req.params.id);
  if (!role || role.user_id !== req.user.id) {
    return res.status(404).json({ error: '角色不存在' });
  }

  CustomRoles.update(req.params.id, req.user.id, {
    name: name || role.name,
    description: description !== undefined ? description : role.description,
    prompt: prompt || role.prompt,
    icon: icon || role.icon
  });

  res.json({ success: true });
});

app.delete('/api/roles/:id', verifyToken, (req, res) => {
  const result = CustomRoles.delete(req.params.id, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: '角色不存在' });
  }
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

app.get('/api/feedback', verifyToken, requireAdmin, (req, res) => {
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

app.get('/api/stats', verifyToken, requireAdmin, (req, res) => {
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

// 增强的统计数据
app.get('/api/admin/enhanced-stats', verifyToken, requireAdmin, (req, res) => {
  const activeUsers = AdminStats.getActiveUsers();
  const roleDistribution = AdminStats.getRoleDistribution();
  const ratingStats = AdminStats.getRatingStats();
  const todayStats = AdminStats.getTodayStats();

  res.json({
    activeUsers,
    roleDistribution,
    ratingStats,
    todayStats
  });
});

// 获取用户详情（包含周报）
app.get('/api/admin/users/:id', verifyToken, requireAdmin, (req, res) => {
  const user = Users.findById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: '用户不存在' });
  }

  const reports = Reports.findByUserId(user.id);
  const customRolesCount = CustomRoles.countByUserId(user.id);

  res.json({
    ...user,
    password_hash: undefined,
    reports,
    customRolesCount
  });
});

// 更新用户计划
app.put('/api/admin/users/:id/plan', verifyToken, requireAdmin, (req, res) => {
  const { plan } = req.body;
  const validPlans = ['free', 'pro'];

  if (!validPlans.includes(plan)) {
    return res.status(400).json({ error: '无效的计划类型' });
  }

  const user = Users.findById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: '用户不存在' });
  }

  Users.updatePlan(req.params.id, plan);

  UsageLogs.create({
    user_id: req.user.id,
    action: 'admin_update_plan',
    metadata: { targetUserId: req.params.id, newPlan: plan, oldPlan: user.plan }
  });

  res.json({ success: true, plan });
});

// ========== Prompt 管理 API ==========
// 获取所有 Prompts
app.get('/api/admin/prompts', verifyToken, requireAdmin, (req, res) => {
  const prompts = Prompts.findAll();
  res.json(prompts);
});

// 获取活跃 Prompts
app.get('/api/admin/prompts/active', verifyToken, requireAdmin, (req, res) => {
  const prompts = Prompts.findActive();
  res.json(prompts);
});

// 更新 Prompt
app.put('/api/admin/prompts/:id', verifyToken, requireAdmin, (req, res) => {
  const { content } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: 'Prompt 内容不能为空' });
  }

  const prompt = Prompts.findById(req.params.id);
  if (!prompt) {
    return res.status(404).json({ error: 'Prompt 不存在' });
  }

  Prompts.update(req.params.id, content.trim());

  UsageLogs.create({
    user_id: req.user.id,
    action: 'admin_update_prompt',
    metadata: { promptId: req.params.id, roleType: prompt.role_type }
  });

  res.json({ success: true });
});

// 创建新版本 Prompt
app.post('/api/admin/prompts', verifyToken, requireAdmin, (req, res) => {
  const { roleType, content } = req.body;

  if (!roleType || !content || !content.trim()) {
    return res.status(400).json({ error: '角色类型和内容不能为空' });
  }

  const validRoles = ['pm', 'dev', 'ops'];
  if (!validRoles.includes(roleType)) {
    return res.status(400).json({ error: '无效的角色类型' });
  }

  const id = Prompts.createNewVersion(roleType, content.trim());

  UsageLogs.create({
    user_id: req.user.id,
    action: 'admin_create_prompt',
    metadata: { promptId: id, roleType }
  });

  res.json({ success: true, id });
});

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
