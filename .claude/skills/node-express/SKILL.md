---
name: node-express
description: Node.js Express后端开发规范。当编写API路由、中间件、Express服务器代码时使用。
---

# Express 后端规范

## 路由结构
- 路由拆分到 routes/ 目录，每个模块一个文件
- server.js 只做初始化和路由注册
- 每个路由文件导出 express.Router()

## 错误处理
- 所有async路由用try/catch包裹
- 统一成功：{ success: true, data: {} }
- 统一失败：{ success: false, message: '具体错误' }

## 中间件用法
- 认证：middleware/auth.js 的 verifyToken
- 付费墙：middleware/paywall.js 的 requirePro
- 写法：router.post('/api/xxx', verifyToken, requirePro, handler)

## 示例
```javascript
// ✅ 正确写法
router.post('/api/polish', verifyToken, async (req, res) => {
  try {
    const { content, role } = req.body;
    if (!content) return res.status(400).json({ success: false, message: '内容不能为空' });
    const result = await polishContent(content, role);
    res.json({ success: true, data: result });
  } catch (err) {
    console.error('Polish error:', err);
    res.status(500).json({ success: false, message: '服务暂时不可用' });
  }
});
```
