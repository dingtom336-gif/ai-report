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

// 指定 .env 文件路径
dotenv.config({ path: join(__dirname, '.env') });

// 调试：打印 API Key 前缀
console.log('API Key loaded:', process.env.DEEPSEEK_API_KEY ? process.env.DEEPSEEK_API_KEY.substring(0, 10) + '...' : 'NOT SET');

const app = express();
const PORT = process.env.PORT || 3000;

// 中间件
app.use(express.json());

// 检测移动设备
function isMobile(userAgent) {
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
}

// 根据设备类型返回不同页面
app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  if (isMobile(userAgent)) {
    res.sendFile(join(__dirname, 'public', 'mobile.html'));
  } else {
    res.sendFile(join(__dirname, 'public', 'index.html'));
  }
});

app.use(express.static(join(__dirname, 'public')));

// 代理配置（本地开发需要，生产环境不需要）
const proxyUrl = process.env.HTTP_PROXY || process.env.https_proxy || process.env.http_proxy;
const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;
console.log('Proxy:', proxyUrl || 'disabled');

// 风格描述映射
const STYLE_DESC = {
  stable: '稳健务实：客观陈述进展和计划，语气平稳专业',
  achievement: '突出成果：强调个人贡献和价值产出，适合晋升期/绩效季',
  risk: '风险预警：着重说明问题和所需支持，适合项目有风险时'
};

// 构建 Prompt
function buildPrompt(content, template, useTemplate, style) {
  const styleDesc = STYLE_DESC[style] || STYLE_DESC.stable;

  if (useTemplate && template) {
    // 有范本时的 Prompt
    return `你是互联网大厂P9产品总监。

【任务】
将用户的随意输入，改写成结构化的高质量周报。

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

【当前风格要求】
${styleDesc}

【用户原始输入】
"""
${content}
"""

请输出改写后的周报：`;
  } else {
    // 无范本时的 Prompt
    return `你是互联网大厂P9产品总监，带过50人团队，深谙向上汇报的艺术。

【你的任务】
将产品经理的周报草稿改写成能让老板看到价值的高质量周报。

【PM周报常见问题】
- 只写了"做了什么"，没写"产出了什么"
- 缺少数据支撑，成果不可衡量
- 项目进度不清晰，老板无法判断风险
- 语言啰嗦，重点不突出

【改写原则】
1. 成果量化：用数字说话（完成率、提升比例、影响用户数）
2. 价值前置：先说结果，再说过程
3. 风险透明：主动暴露问题比被动发现强
4. 简洁有力：每条控制在1-2行，删除所有废话

【当前风格要求】
${styleDesc}

【输出格式】
## 本周成果
- [量化成果1]
- [量化成果2]

## 重点进展
- [项目A]：当前阶段 → 下一里程碑（预计时间）
- [项目B]：当前阶段 → 下一里程碑（预计时间）

## 下周计划
- [可衡量目标1]
- [可衡量目标2]

## 风险与协调（如有）
- [问题]：需要[谁][做什么]

【改写示例】
原文：这周跟进了A项目的开发进度，感觉有点慢
改写：A项目开发进度75%，较计划延迟2天，已协调增加1名后端资源，预计下周三完成联调

现在改写以下内容：
${content}`;
  }
}

// 调用 DeepSeek API
function callDeepSeekAPI(prompt) {
  return new Promise((resolve, reject) => {
    const apiKey = process.env.DEEPSEEK_API_KEY;

    const postData = JSON.stringify({
      model: 'deepseek-chat',
      messages: [
        {
          role: 'user',
          content: prompt
        }
      ]
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
  const { content, template, useTemplate, style } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: '请输入周报内容' });
  }

  // 检查 API Key 是否配置
  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(500).json({ error: 'API Key 未配置，请在 .env 文件中设置 DEEPSEEK_API_KEY' });
  }

  // 验证 style 参数
  const validStyles = ['stable', 'achievement', 'risk'];
  const finalStyle = validStyles.includes(style) ? style : 'stable';

  try {
    const prompt = buildPrompt(content, template, useTemplate, finalStyle);
    const data = await callDeepSeekAPI(prompt);
    const result = data.choices[0].message.content;
    res.json({ result });
  } catch (error) {
    console.error('DeepSeek API 调用失败:', error.status, error.data || error.message);

    if (error.status === 401) {
      return res.status(401).json({ error: 'API Key 无效，请检查 DEEPSEEK_API_KEY' });
    }
    if (error.status === 403) {
      return res.status(403).json({ error: 'API Key 没有访问权限' });
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

// 确保数据目录存在
if (!existsSync(DATA_DIR)) {
  mkdirSync(DATA_DIR, { recursive: true });
}

// 读取反馈数据
function readFeedback() {
  if (!existsSync(FEEDBACK_FILE)) {
    writeFileSync(FEEDBACK_FILE, '[]');
    return [];
  }
  return JSON.parse(readFileSync(FEEDBACK_FILE, 'utf-8') || '[]');
}

// 写入反馈数据
function writeFeedback(data) {
  writeFileSync(FEEDBACK_FILE, JSON.stringify(data, null, 2));
}

// 提交反馈
app.post('/api/feedback', (req, res) => {
  const { type, title, description, contact } = req.body;

  if (!type || !title || !description) {
    return res.status(400).json({ error: '请填写完整信息' });
  }

  const feedback = {
    id: randomUUID(),
    type,
    title,
    description,
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

// 获取反馈列表
app.get('/api/feedback', (req, res) => {
  const { type, status, ids } = req.query;
  let data = readFeedback();

  if (ids) {
    const idList = ids.split(',');
    data = data.filter(item => idList.includes(item.id));
  }

  if (type && type !== 'all') {
    data = data.filter(item => item.type === type);
  }

  if (status && status !== 'all') {
    data = data.filter(item => item.status === status);
  }

  res.json(data);
});

// 更新反馈
app.put('/api/feedback/:id', (req, res) => {
  const { status, note } = req.body;
  const data = readFeedback();
  const index = data.findIndex(item => item.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ error: '反馈不存在' });
  }

  if (status) data[index].status = status;
  if (note !== undefined) data[index].note = note;
  data[index].updatedAt = new Date().toISOString();

  writeFeedback(data);
  res.json({ success: true, feedback: data[index] });
});

// 获取统计数据
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
