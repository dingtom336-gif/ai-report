import express from 'express';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import https from 'https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomUUID } from 'crypto';

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

// 润色接口
app.post('/api/polish', async (req, res) => {
  const { content, role = 'pm', template, useTemplate } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: '请输入周报内容' });
  }

  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(500).json({ error: 'API Key 未配置' });
  }

  const validRoles = ['dev', 'ops', 'pm'];
  const finalRole = validRoles.includes(role) ? role : 'pm';

  try {
    const prompt = buildPrompt(content, finalRole, template, useTemplate);
    const data = await callDeepSeekAPI(prompt);
    const result = data.choices[0].message.content;
    res.json({ result });
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

// ========== 反馈系统 API ==========
const DATA_DIR = join(__dirname, 'data');
const FEEDBACK_FILE = join(DATA_DIR, 'feedback.json');

if (!existsSync(DATA_DIR)) {
  mkdirSync(DATA_DIR, { recursive: true });
}

function readFeedback() {
  if (!existsSync(FEEDBACK_FILE)) {
    writeFileSync(FEEDBACK_FILE, '[]');
    return [];
  }
  return JSON.parse(readFileSync(FEEDBACK_FILE, 'utf-8') || '[]');
}

function writeFeedback(data) {
  writeFileSync(FEEDBACK_FILE, JSON.stringify(data, null, 2));
}

app.post('/api/feedback', (req, res) => {
  const { type, title, description, contact } = req.body;
  if (!type || !title || !description) {
    return res.status(400).json({ error: '请填写完整信息' });
  }

  const feedback = {
    id: randomUUID(),
    type, title, description,
    contact: contact || '',
    status: 'pending',
    note: '',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  const data = readFeedback();
  data.unshift(feedback);
  writeFeedback(data);
  res.json({ success: true, id: feedback.id });
});

app.get('/api/feedback', (req, res) => {
  const { type, status } = req.query;
  let data = readFeedback();
  if (type && type !== 'all') data = data.filter(item => item.type === type);
  if (status && status !== 'all') data = data.filter(item => item.status === status);
  res.json(data);
});

app.put('/api/feedback/:id', (req, res) => {
  const { status, note } = req.body;
  const data = readFeedback();
  const index = data.findIndex(item => item.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: '反馈不存在' });

  if (status) data[index].status = status;
  if (note !== undefined) data[index].note = note;
  data[index].updatedAt = new Date().toISOString();

  writeFeedback(data);
  res.json({ success: true, feedback: data[index] });
});

app.get('/api/stats', (req, res) => {
  const data = readFeedback();
  res.json({
    total: data.length,
    byType: {
      bug: data.filter(item => item.type === 'bug').length,
      suggestion: data.filter(item => item.type === 'suggestion').length,
      inquiry: data.filter(item => item.type === 'inquiry').length
    },
    byStatus: {
      pending: data.filter(item => item.status === 'pending').length,
      processing: data.filter(item => item.status === 'processing').length,
      completed: data.filter(item => item.status === 'completed').length
    }
  });
});

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
