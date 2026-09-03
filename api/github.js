// api/github.js
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { action, username, hash, salt, data } = req.body;
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPO;
  const basePath = 'users';

  if (!token || !repo) {
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const api = (path, options = {}) => {
    const url = `https://api.github.com/repos/${repo}/contents/${path}`;
    return fetch(url, {
      ...options,
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    }).then(r => r.json());
  };

  const readFile = async (path) => {
    try {
      const result = await api(path);
      if (result.content) {
        const content = Buffer.from(result.content, 'base64').toString('utf-8');
        return { content: JSON.parse(content), sha: result.sha };
      }
      return null;
    } catch (e) {
      return null;
    }
  };

  const writeFile = async (path, content, message, sha) => {
    const body = {
      message: message || 'Update data',
      content: Buffer.from(JSON.stringify(content, null, 2)).toString('base64'),
    };
    if (sha) body.sha = sha;
    const result = await api(path, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
    return result;
  };

  try {
    if (action === 'register') {
      const profilePath = `${basePath}/${username}/profile.json`;
      const dataPath = `${basePath}/${username}/data.json`;
      const existing = await readFile(profilePath);
      if (existing) {
        return res.status(400).json({ error: '用户名已存在' });
      }
      if (!salt || !hash) {
        return res.status(400).json({ error: '缺少密码哈希参数' });
      }
      const profile = { username, salt, hash, createdAt: new Date().toISOString() };
      await writeFile(profilePath, profile, `Create user ${username}`);
      const emptyData = { records: {}, settings: {}, goal: 160 };
      await writeFile(dataPath, emptyData, `Initialize data for ${username}`);
      return res.status(200).json({ success: true });
    }

    if (action === 'login') {
      const profilePath = `${basePath}/${username}/profile.json`;
      const profile = await readFile(profilePath);
      if (!profile) {
        return res.status(404).json({ error: '用户不存在' });
      }
      const { salt: storedSalt, hash: storedHash } = profile.content;
      if (hash !== storedHash) {
        return res.status(401).json({ error: '密码错误' });
      }
      return res.status(200).json({
        success: true,
        username: profile.content.username,
        createdAt: profile.content.createdAt,
      });
    }

    if (action === 'getData') {
      const dataPath = `${basePath}/${username}/data.json`;
      const result = await readFile(dataPath);
      if (!result) {
        return res.status(200).json({ records: {}, settings: {}, goal: 160 });
      }
      return res.status(200).json(result.content);
    }

    if (action === 'setData') {
      const dataPath = `${basePath}/${username}/data.json`;
      if (!data) {
        return res.status(400).json({ error: '缺少数据' });
      }
      const existing = await readFile(dataPath);
      const sha = existing ? existing.sha : undefined;
      await writeFile(dataPath, data, `Update data for ${username}`, sha);
      return res.status(200).json({ success: true });
    }

    return res.status(400).json({ error: '无效的 action' });
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: '服务器内部错误' });
  }
  }
