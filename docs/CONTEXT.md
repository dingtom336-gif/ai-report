# Project Context

## Current State
- Version: v2.6.1
- Status: Production (Railway deployed)
- Last updated: 2026-02-11

## Architecture
- Monolithic Express server with SQLite database
- Vanilla JS frontend (no framework)
- DeepSeek API for AI report polishing
- JWT auth with email verification codes

## Recent Changes
<!-- Keep latest 5 entries, archive older ones -->
1. [2026-02-11] Initialized Claude Code configs (CLAUDE.md, commands, Playwright)

## Tech Debt
- [ ] index.html (5483 lines) → split CSS/JS into separate files
- [ ] server.js (1688 lines) → split routes into routes/ directory
- [ ] db/database.js (1281 lines) → split by domain (users, reports, etc.)

## Key Decisions
- DeepSeek over OpenAI: cost-effective for Chinese text processing
- SQLite over PostgreSQL: simpler deployment, sufficient for current scale
- Vanilla JS over React/Vue: lightweight, no build step needed
- Railway over Vercel: better SQLite support with persistent volumes
