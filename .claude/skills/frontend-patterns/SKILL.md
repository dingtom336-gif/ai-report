---
name: frontend-patterns
description: 前端HTML/CSS/JS开发规范。当创建页面、修改UI、编写前端交互时使用。
---

# 前端开发规范

## 文件组织
- HTML文件只放结构，不超过200行
- CSS在 public/css/ 目录
- JS按功能拆到 public/js/ 目录
- 所有页面引用 nav.js 和 utils.js

## UI暗色主题（保持全站统一）
- 背景：#0f0f1a
- 卡片：rgba(255,255,255,0.05) + backdrop-filter: blur(10px)
- 主色渐变：#667eea → #764ba2
- 文字：#ffffff / rgba(255,255,255,0.7)
- 圆角：16px
- Pro标签：金色渐变 #f5af19 → #f12711

## 禁止
- 不要往index.html里塞JS/CSS代码（拆到独立文件）
- 不要裸写fetch，用utils.js的apiRequest封装
- 移动端必须响应式（< 768px 用 flex-direction: column）
