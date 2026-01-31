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

// 调用 DeepSeek API
function callDeepSeekAPI(content) {
  return new Promise((resolve, reject) => {
    const apiKey = process.env.DEEPSEEK_API_KEY;

    const postData = JSON.stringify({
      model: 'deepseek-chat',
      messages: [
        {
          role: 'user',
          content: `你是一位专业的职场写作顾问。请润色以下周报，要求：
1. 语言更专业、简洁
2. 突出成果和价值
3. 保持原意不变
4. 使用纯文本格式输出，不要使用 Markdown 符号（如 *、**、# 等）

周报内容：
${content}`
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
  const { content } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: '请输入周报内容' });
  }

  // 检查 API Key 是否配置
  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(500).json({ error: 'API Key 未配置，请在 .env 文件中设置 DEEPSEEK_API_KEY' });
  }

  try {
    const data = await callDeepSeekAPI(content);
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
