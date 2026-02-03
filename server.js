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

// ========== 性能监测配置 ==========
const API_TIMEOUT = 30000; // 30秒超时
const MAX_CONCURRENT_REQUESTS = 5; // 最大并发数

// API 性能统计
const apiMetrics = {
  polish: { count: 0, totalTime: 0, errors: 0, timeouts: 0 },
  chat: { count: 0, totalTime: 0, errors: 0, timeouts: 0 },
  deepseek: { count: 0, totalTime: 0, errors: 0, timeouts: 0 }
};

// 当前并发请求计数
let currentConcurrentRequests = 0;
const requestQueue = [];

// 性能日志函数
function logApiPerformance(endpoint, startTime, success, extra = {}) {
  const duration = Date.now() - startTime;
  const metric = apiMetrics[endpoint];
  if (metric) {
    metric.count++;
    metric.totalTime += duration;
    if (!success) metric.errors++;
    if (extra.timeout) metric.timeouts++;
  }

  const logData = {
    timestamp: new Date().toISOString(),
    endpoint,
    duration_ms: duration,
    success,
    avg_ms: metric ? Math.round(metric.totalTime / metric.count) : 0,
    concurrent: currentConcurrentRequests,
    ...extra
  };

  console.log(`[Performance] ${JSON.stringify(logData)}`);
  return duration;
}

// 并发控制 - 获取执行槽
function acquireSlot() {
  return new Promise((resolve) => {
    if (currentConcurrentRequests < MAX_CONCURRENT_REQUESTS) {
      currentConcurrentRequests++;
      resolve();
    } else {
      requestQueue.push(resolve);
    }
  });
}

// 并发控制 - 释放执行槽
function releaseSlot() {
  currentConcurrentRequests--;
  if (requestQueue.length > 0) {
    currentConcurrentRequests++;
    const next = requestQueue.shift();
    next();
  }
}

// 获取性能指标API
app.get('/api/metrics', requireAdmin, (req, res) => {
  res.json({
    success: true,
    data: {
      metrics: apiMetrics,
      currentConcurrent: currentConcurrentRequests,
      queueLength: requestQueue.length
    }
  });
});

// ========== 精准润色模式提示词 ==========
const PRECISE_PROMPT = `你是「周报编辑」，一位严谨的文字工作者。你的职责是：在完全保留用户原始信息的前提下，优化文字表达、调整结构层次、提升专业度。

【核心原则 - 铁律】
1. 信息守恒：输出的每一条信息都必须能在原文中找到来源，不能凭空添加
2. 不做推断：用户没写的内容，绝对不能替用户写
3. 不做假设：不推测用户的意图、数据、结果
4. 缺啥标啥：信息不足的地方用 [待补充：XX] 明确标记

【允许的操作】
✅ 修正错别字、语病
✅ 优化句子结构，让表达更清晰
✅ 调整段落顺序，让逻辑更顺畅
✅ 将口语化表达改为书面语
✅ 添加合适的标点符号和换行
✅ 使用更专业的措辞替换口语词汇
✅ 为内容添加清晰的分类标题
✅ 统一格式和排版风格

【禁止的操作】
❌ 添加原文中没有提到的工作内容
❌ 编造任何数据、指标、百分比
❌ 推断用户没有明说的业务目标
❌ 脑补项目进度、完成状态
❌ 替用户总结"洞察"或"思考"
❌ 假设风险或问题
❌ 编造下周计划

【输出结构】
根据原文内容，选择性使用以下模块（原文没有的模块不要生成）：

## 本周完成
- 仅包含原文明确提到的已完成事项

## 进行中
- 仅包含原文提到的进行中事项

## 问题/卡点
- 仅包含原文提到的问题

## 下周计划
- 仅包含原文明确提到的计划

【输出规范】
- 语言专业、简洁，使用 Markdown 格式
- 如果原文信息太少（少于3个有效信息点），在末尾提示：「💡 内容较少，建议补充：具体完成了什么、关键数据、遇到的问题、下周计划」
- 如果原文是无意义内容（乱码、无关文字、骂人、测试内容），直接回复：「⚠️ 未检测到有效的周报内容，请输入您本周的工作内容。」

现在润色以下内容：
`;

// ========== 智能扩写模式提示词 ==========
const SMART_PROMPT = `你是「周报架构师」，一位拥有 20 年互联网行业经验的高级战略沟通顾问。你的核心能力是：将用户随意输入的工作流水文字，精准提取信息要素，重构为一份让高管在 90 秒内获取全部关键信息的高质量周报。

【底层方法论】（内化使用，不要在输出中提及）
- Amazon 逆向工作法：从成果和业务价值出发反推叙述
- McKinsey 金字塔原理：结论先行，MECE 分组
- 字节跳动 Context-Not-Control：提供充分上下文
- 丰田 5 Why：问题挖到根因
- 艾森豪威尔矩阵：只保留重要的事

【处理流程】

Step 1 - 信息萃取：
从用户输入中识别完成事项、量化数据、问题/风险、下周计划、协作关系、隐含的业务目标

Step 2 - 智能补全：
- 从内容推断最可能的业务目标
- 缺少量化数据时，保留定性描述
- 无法推断的信息用 [待补充：XX] 标记
- 显性化隐含的因果关系

Step 3 - SPARK 框架重构：

## S — 本周战报
一句话概括核心成果，句式：「做了什么 → 达成什么 → 业务意义」，不超过 50 字

## P — 重点进展
按业务目标分组，最多 5 项，格式：
📌 事项名称
   状态：🟢 已完成 / 🟡 进行中(XX%) / 🔴 延期
   交付物：具体产出
   价值：对目标的推进意义

## A — 本周洞察
1 个有深度的思考或发现（3-5 句话），如原文无明显素材则从问题/卡点中挖掘

## R — 风险与卡点
最多 2 条，格式：
⚠️ 风险描述
   影响：影响哪些目标
   等级：P0 紧急 / P1 高风险 / P2 需关注
   需要支持：需要谁、做什么
无风险则输出「本周无重大风险」

## K — 下周聚焦
最多 3 件事，格式：
▶ 事项名称
  完成标志：可验证的完成标准

【输出规范】
- 信息密度高，零废话
- 量化表达："大幅提升" → "提升 37%"
- 全文 400-700 字，Markdown 格式
- 禁止模糊动词：推进中、跟进中、沟通中、对齐中

【特殊场景】
- 输入极短（少于 50 字）：尽力生成框架，不足处用 [待补充：XX]，末尾添加补充建议
- 输入包含无关内容（吐槽/情绪）：静默过滤，只提取工作相关信息
- 输入为无意义内容（乱码、骂人、测试）：直接回复「⚠️ 未检测到有效的周报内容，请输入您本周的工作内容。」

直接输出周报正文，无前言、无解释，从 Summary 开始。

现在处理以下内容：
`;

// 旧版兼容（保留用于自定义角色等场景）
const ROLE_PROMPTS = {
  dev: SMART_PROMPT,
  ops: SMART_PROMPT,
  pm: SMART_PROMPT
};

// 构建 Prompt
function buildPrompt(content, role, template, useTemplate, customPrompt = null, polishMode = 'smart') {
  // 范本模式优先
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

  // 根据润色模式选择提示词
  if (polishMode === 'precise') {
    return PRECISE_PROMPT + content;
  } else {
    return SMART_PROMPT + content;
  }
}

// 调用 DeepSeek API（带超时和性能监测）
function callDeepSeekAPI(prompt, timeout = API_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const apiKey = process.env.DEEPSEEK_API_KEY;
    let timeoutId = null;
    let isCompleted = false;

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
        if (isCompleted) return;
        isCompleted = true;
        clearTimeout(timeoutId);

        try {
          const parsed = JSON.parse(data);
          if (res.statusCode !== 200) {
            logApiPerformance('deepseek', startTime, false, { status: res.statusCode });
            const error = new Error(parsed.error?.message || 'API 调用失败');
            error.status = res.statusCode;
            error.data = parsed;
            reject(error);
          } else {
            logApiPerformance('deepseek', startTime, true);
            resolve(parsed);
          }
        } catch (e) {
          logApiPerformance('deepseek', startTime, false, { parseError: true });
          reject(new Error('解析响应失败'));
        }
      });
    });

    // 超时处理
    timeoutId = setTimeout(() => {
      if (isCompleted) return;
      isCompleted = true;
      req.destroy();
      logApiPerformance('deepseek', startTime, false, { timeout: true });
      reject(new Error(`DeepSeek API 超时 (${timeout}ms)`));
    }, timeout);

    req.on('error', (e) => {
      if (isCompleted) return;
      isCompleted = true;
      clearTimeout(timeoutId);
      logApiPerformance('deepseek', startTime, false, { error: e.message });
      reject(e);
    });

    req.write(postData);
    req.end();
  });
}

// 流式调用 DeepSeek API（带超时和性能监测）
function callDeepSeekAPIStream(prompt, onChunk, onDone, onError, timeout = API_TIMEOUT) {
  const startTime = Date.now();
  let firstChunkTime = null;
  const apiKey = process.env.DEEPSEEK_API_KEY;
  let timeoutId = null;
  let isCompleted = false;

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

  // Reset timeout on each chunk received
  const resetTimeout = () => {
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(() => {
      if (isCompleted) return;
      isCompleted = true;
      req.destroy();
      logApiPerformance('deepseek', startTime, false, { timeout: true, stream: true });
      onError(new Error(`DeepSeek API 流式超时 (${timeout}ms 无数据)`));
    }, timeout);
  };

  const req = https.request(options, (res) => {
    if (res.statusCode !== 200) {
      let errorData = '';
      res.on('data', (chunk) => errorData += chunk);
      res.on('end', () => {
        if (isCompleted) return;
        isCompleted = true;
        clearTimeout(timeoutId);
        logApiPerformance('deepseek', startTime, false, { status: res.statusCode, stream: true });
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
      resetTimeout(); // Reset timeout on each chunk

      // Record first chunk time
      if (!firstChunkTime) {
        firstChunkTime = Date.now() - startTime;
        console.log(`[Performance] First chunk: ${firstChunkTime}ms`);
      }

      buffer += chunk.toString();

      // 处理 SSE 格式数据
      const lines = buffer.split('\n');
      buffer = lines.pop() || ''; // 保留不完整的行

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data:')) continue;

        const data = trimmed.slice(5).trim();
        if (data === '[DONE]') {
          if (isCompleted) return;
          isCompleted = true;
          clearTimeout(timeoutId);
          logApiPerformance('deepseek', startTime, true, {
            stream: true,
            firstChunk_ms: firstChunkTime,
            contentLength: fullContent.length
          });
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
      if (isCompleted) return;
      isCompleted = true;
      clearTimeout(timeoutId);

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
      logApiPerformance('deepseek', startTime, true, {
        stream: true,
        firstChunk_ms: firstChunkTime,
        contentLength: fullContent.length
      });
      onDone(fullContent);
    });

    res.on('error', (e) => {
      if (isCompleted) return;
      isCompleted = true;
      clearTimeout(timeoutId);
      logApiPerformance('deepseek', startTime, false, { stream: true, error: e.message });
      onError(e);
    });
  });

  req.on('error', (e) => {
    if (isCompleted) return;
    isCompleted = true;
    clearTimeout(timeoutId);
    logApiPerformance('deepseek', startTime, false, { stream: true, error: e.message });
    onError(e);
  });

  resetTimeout(); // Start initial timeout
  req.write(postData);
  req.end();

  return req;
}

// ReAct Agent Prompt 构建（含完整四阶段循环和反思机制）
function buildChatPrompt(currentReport, message, history = [], polishMode = 'smart') {
  const historyText = history.slice(-10).map(h =>
    `用户: ${h.user}\n助手: ${h.assistant}`
  ).join('\n\n');

  const modeContext = polishMode === 'precise'
    ? '【精准润色模式】用户初次润色选择了精准模式，修改时同样遵循"不编造信息"原则，只能基于用户明确提供的信息。'
    : '【智能扩写模式】用户初次润色选择了智能扩写，修改时可以适度补充和优化表达。';

  return `你是「周报打磨助手」，一位精通互联网行业沟通策略的资深编辑。

用户已有一份周报初稿，现在通过对话方式进行修改。你采用 ReAct + Reflection 模式工作。

# 工作模式

每次收到用户指令，你必须完成四个阶段的思考和执行：

**阶段1 - Thought（推理）**
分析用户意图，包含三个判断：
- 意图识别：属于哪种修改类型
- 影响范围：LOCAL（单点）/ CASCADE（需同步）/ GLOBAL（全文）
- 置信度：HIGH（直接执行）/ MEDIUM（执行+确认）/ LOW（先追问）

**阶段2 - Action（执行）**
根据意图执行修改，输出完整的新版周报。
如果置信度为 LOW，则不执行修改，只输出追问问题。

**阶段3 - Observation（观察）**
记录本次修改的变更清单。

**阶段4 - Reflection（反思）**
执行五维质检，决定后续行为：
- NONE：完成，无需后续动作
- SELF_CORRECT：发现小问题，静默修复（最多2次循环）
- SUGGEST：修改完成，附带优化建议
- WARN：警告用户潜在问题

# 意图类型矩阵（10种）

1. **定位修改**：用户指定某位置修改（"把第二条改成..."）
2. **内容增删**：添加或删除信息（"加一条..."、"删掉那个..."）
3. **语气调整**：调整表达风格（"语气软一点"、"更自信"）
4. **数据修正**：修正数据或事实（"数据不对，应该是85%"）
5. **结构调整**：调整排序或结构（"这两条合并"、"提到前面"）
6. **深度优化**：整体提升质量（"帮我优化一下"、"更专业"）
7. **格式调整**：调整格式符号（"去掉星号"、"换成数字列表"）
8. **撤销回退**：撤销修改（"撤销"、"改回去"）
9. **确认定稿**：结束修改（"可以了"、"就这样"）
10. **模糊意图**：意图不明确，需要澄清

# 置信度策略

**HIGH (>80%)**：用户意图明确，直接执行
**MEDIUM (50-80%)**：基本明确但有细节不确定，执行修改后附带一句确认
**LOW (<50%)**：意图模糊，先问一个封闭式问题再执行

LOW 置信度时的追问原则：
- 只问一个问题
- 提供2-3个选项让用户选择
- 不要问开放式问题

# 意图理解能力

1. **错别字/谐音纠正**："型号"→"星号"→"*"，"井号"→"#"
2. **模糊意图推断**："简洁点"→删除冗余，"专业点"→量化表达
3. **复合意图拆解**："第一条简洁点，第二条加数据"→分别处理

# 级联同步规则

当修改涉及以下情况时，自动检查关联部分：
- 修改了数据 → 检查 Summary 是否引用了同一数据
- 新增事项 → 检查目标分组是否失衡（超过5条需提醒）
- 删除事项 → 检查是否影响 Summary 或下周计划的连贯性

# 反思门控

- 发现需要自修正时，最多循环2次
- Self-Correction 只处理小问题（格式错误、遗漏emoji等），大问题走 WARN

# 上下文协同

${modeContext}

# 当前周报

"""
${currentReport}
"""

${historyText ? `# 对话历史\n${historyText}\n\n` : ''}# 用户指令

${message}

# 输出格式

严格按以下格式输出（前端会解析展示为时间线）：

<thought>
[自然语言描述你的分析过程]
意图类型：[10种之一]
影响范围：[LOCAL/CASCADE/GLOBAL]
置信度：[HIGH/MEDIUM/LOW]
[如果是 LOW，说明为什么不确定]
</thought>

<action>
[如果置信度 HIGH/MEDIUM：输出完整的修改后周报，在修改处用 ✏️ 标记]
[如果置信度 LOW：输出追问问题，格式如"你是想改 A 还是 B？"]
</action>

<observation>
[简短列出本次改动，格式：已将 X 从"A"改为"B"]
[如果是追问则写：等待用户澄清]
</observation>

<reflection>
意图满足度：[是否完全满足用户需求]
质量变化：[+1/0/-1]
一致性检查：[PASS/需要同步XX处]
反模式扫描：[是否存在模糊动词、缺少量化等问题]
后续行为：[NONE/SELF_CORRECT/SUGGEST/WARN]
[如果是 SUGGEST，写出建议内容]
[如果是 WARN，写出警告内容]
</reflection>`;
}

// 解析 ReAct 响应（支持完整四阶段）
function parseReActResponse(response) {
  const thoughtMatch = response.match(/<thought>([\s\S]*?)<\/thought>/);
  const actionMatch = response.match(/<action>([\s\S]*?)<\/action>/);
  const observationMatch = response.match(/<observation>([\s\S]*?)<\/observation>/);
  const reflectionMatch = response.match(/<reflection>([\s\S]*?)<\/reflection>/);

  const thought = thoughtMatch ? thoughtMatch[1].trim() : '正在分析修改需求...';
  const action = actionMatch ? actionMatch[1].trim() : response;
  const observation = observationMatch ? observationMatch[1].trim() : '已完成修改';
  const reflection = reflectionMatch ? reflectionMatch[1].trim() : '';

  // 从 thought 中提取结构化信息
  const confidenceMatch = thought.match(/置信度：(HIGH|MEDIUM|LOW)/);
  const intentMatch = thought.match(/意图类型：(.+)/);

  // 判断是追问还是修改（追问时 action 中没有 ## 标题）
  const isQuestion = action.includes('？') && !action.includes('##');

  return {
    thought,
    newReport: isQuestion ? null : action,
    observation,
    reflection,
    confidence: confidenceMatch ? confidenceMatch[1] : 'HIGH',
    intent: intentMatch ? intentMatch[1].trim() : '修改',
    isQuestion,
    question: isQuestion ? action : null
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

    // 验证码已保存，返回成功（不再返回验证码到前端）
    res.json({
      success: true,
      message: '验证码已发送'
    });
  } catch (error) {
    console.error('发送验证码失败:', error);
    res.status(500).json({ error: '发送失败，请稍后重试' });
  }
});

// 登录（支持多种方式：用户名密码、手机号验证码、邮箱密码）
app.post('/api/auth/login', async (req, res) => {
  const { phone, code, email, password, username } = req.body;

  // 用户名/邮箱 + 密码登录
  if (username && password) {
    // 判断是邮箱还是用户名
    const isEmail = username.includes('@');
    const user = isEmail ? Users.findByEmail(username) : Users.findByUsername(username);

    if (!user) {
      return res.status(401).json({ error: '账号或密码错误' });
    }

    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: '账号或密码错误' });
    }

    Users.updateLastLogin(user.id);
    UsageLogs.create({ user_id: user.id, action: 'login' });

    const token = generateToken(user);
    return res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        plan: user.plan
      }
    });
  }

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
    return res.status(400).json({ error: '请输入登录信息' });
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

// 用户名注册
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;

  // 验证参数
  if (!username || !password) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }

  // 验证用户名格式（4-16位字母数字）
  if (!/^[a-zA-Z0-9]{4,16}$/.test(username)) {
    return res.status(400).json({ error: '用户名需为4-16位字母或数字' });
  }

  // 验证密码长度
  if (password.length < 6) {
    return res.status(400).json({ error: '密码至少6位' });
  }

  try {
    // 检查用户名是否已存在
    const existing = Users.findByUsername(username);
    if (existing) {
      return res.status(400).json({ error: '用户名已被使用' });
    }

    // 创建用户（默认 free 计划）
    const userId = Users.createByUsername({
      username,
      password_hash: hashPassword(password),
      nickname: username
    });

    const user = Users.findById(userId);
    UsageLogs.create({ user_id: userId, action: 'register' });

    const token = generateToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
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
  const { content, role = 'pm', template, useTemplate, polishMode = 'smart' } = req.body;

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
    // Acquire concurrent slot
    await acquireSlot();
    const polishStartTime = Date.now();

    const prompt = buildPrompt(content, finalRole, template, useTemplate, customPrompt, polishMode);
    let data;
    try {
      data = await callDeepSeekAPI(prompt);
    } finally {
      releaseSlot();
    }
    logApiPerformance('polish', polishStartTime, true);
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
        metadata: { role: finalRole, reportId, polishMode }
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
  const { content, role = 'pm', template, useTemplate, polishMode = 'smart' } = req.body;

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

  const prompt = buildPrompt(content, finalRole, template, useTemplate, customPrompt, polishMode);

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

  // Acquire concurrent slot
  await acquireSlot();
  const polishStartTime = Date.now();
  let slotReleased = false;

  const releaseSlotOnce = () => {
    if (!slotReleased) {
      slotReleased = true;
      releaseSlot();
    }
  };

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
      releaseSlotOnce();
      logApiPerformance('polish', polishStartTime, true, { stream: true });

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
          metadata: { role: finalRole, reportId, stream: true, polishMode }
        });
      }

      res.write(`data: ${JSON.stringify({ type: 'done', reportId })}\n\n`);
      res.end();
    },
    // onError
    (error) => {
      releaseSlotOnce();
      logApiPerformance('polish', polishStartTime, false, { stream: true, error: error.message });
      console.error('流式 API 调用失败:', error.message);
      res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`);
      res.end();
    }
  );

  // 客户端断开连接时清理
  res.on('close', () => {
    releaseSlotOnce();
  });
});

// ========== AI 对话修改接口 (需要登录+Pro) ==========
app.post('/api/chat', verifyToken, checkChatAccess, async (req, res) => {
  const { currentReport, message, history = [], reportId, polishMode = 'smart' } = req.body;

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
    const prompt = buildChatPrompt(currentReport, message, history, polishMode);
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
  const { currentReport, message, history = [], reportId, polishMode = 'smart' } = req.body;

  if (!currentReport || !currentReport.trim()) {
    return res.status(400).json({ error: '当前周报内容不能为空' });
  }

  if (!message || !message.trim()) {
    return res.status(400).json({ error: '请输入修改指令' });
  }

  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(500).json({ error: 'API Key 未配置' });
  }

  const prompt = buildChatPrompt(currentReport, message, history, polishMode);

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
