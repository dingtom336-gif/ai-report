import express from 'express';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import https from 'https';
import { HttpsProxyAgent } from 'https-proxy-agent';

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

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
