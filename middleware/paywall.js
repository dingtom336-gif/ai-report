/**
 * 付费墙规则
 * Free: 每日3次润色，仅PM角色，禁用AI对话、范本、完整历史
 * Pro: 无限制
 */

/**
 * 检查角色选择权限
 * Free 用户只能使用 PM 角色
 */
export function checkRoleAccess(req, res, next) {
  const { role } = req.body;

  // 未登录用户使用默认规则
  if (!req.user) {
    return next();
  }

  // Pro 用户和管理员可以使用所有角色
  if (req.user.plan === 'pro' || req.user.role === 'admin') {
    return next();
  }

  // Free 用户只能使用 PM 角色
  if (role && role !== 'pm') {
    return res.status(403).json({
      error: '免费版仅支持"产品经理"角色，升级 Pro 解锁全部角色',
      code: 'ROLE_RESTRICTED',
      allowedRoles: ['pm']
    });
  }

  next();
}

/**
 * 检查 AI 对话功能权限
 * 仅 Pro 用户可用
 */
export function checkChatAccess(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: '请先登录' });
  }

  if (req.user.plan !== 'pro' && req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'AI 对话修改功能需要 Pro 版本',
      code: 'FEATURE_RESTRICTED',
      feature: 'ai_chat'
    });
  }

  next();
}

/**
 * 检查范本学习功能权限
 * 仅 Pro 用户可用
 */
export function checkTemplateAccess(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: '请先登录' });
  }

  if (req.user.plan !== 'pro' && req.user.role !== 'admin') {
    return res.status(403).json({
      error: '范本学习功能需要 Pro 版本',
      code: 'FEATURE_RESTRICTED',
      feature: 'template'
    });
  }

  next();
}

/**
 * 获取用户的历史记录限制
 * Free: 7 条
 * Pro: 无限
 */
export function getHistoryLimit(user) {
  if (!user) return 0;
  if (user.plan === 'pro' || user.role === 'admin') return null; // null = 无限制
  return 7;
}

/**
 * 获取用户功能权限列表
 */
export function getUserPermissions(user) {
  if (!user) {
    return {
      polish: false,
      aiChat: false,
      template: false,
      historyLimit: 0,
      dailyLimit: 0,
      allowedRoles: []
    };
  }

  const isPro = user.plan === 'pro' || user.role === 'admin';

  return {
    polish: true,
    aiChat: isPro,
    template: isPro,
    historyLimit: isPro ? null : 7,
    dailyLimit: isPro ? null : 3,
    allowedRoles: isPro ? ['dev', 'ops', 'pm'] : ['pm']
  };
}
