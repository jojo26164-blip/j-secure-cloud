import { test, expect, APIRequestContext } from '@playwright/test';

const API = process.env.API ?? 'http://127.0.0.1:8081/api';

function randEmail() {
  return `t_${Date.now()}_${Math.floor(Math.random() * 1e9)}@example.com`;
}

function randIp() {
  const a = 10;
  const b = Math.floor(Math.random() * 200) + 1;
  const c = Math.floor(Math.random() * 200) + 1;
  const d = Math.floor(Math.random() * 200) + 1;
  return `${a}.${b}.${c}.${d}`;
}

async function register(request: APIRequestContext, email: string, password: string, ip: string) {
  return await request.post(`${API}/auth/register`, {
    data: { email, password },
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': ip,
    },
  });
}

async function login(request: APIRequestContext, email: string, password: string, ip: string) {
  return await request.post(`${API}/auth/login`, {
    data: { email, password },
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': ip,
    },
  });
}

test('health ok', async ({ request }) => {
  const res = await request.get(`${API}/health`);
  expect(res.status()).toBe(200);
  const txt = await res.text();
  expect(txt.toLowerCase()).toContain('ok');
});

test('register ok then login ok (token)', async ({ request }) => {
  const ip = randIp();
  const email = randEmail();
  const password = 'Test1234!';

  const r1 = await register(request, email, password, ip);
  expect([200, 201]).toContain(r1.status());

  const r2 = await login(request, email, password, ip);
  expect(r2.status()).toBe(200);

  const j2 = await r2.json();
  expect(typeof j2.token).toBe('string');
  expect((j2.token as string).length).toBeGreaterThan(20);
});

test('login wrong password -> 401', async ({ request }) => {
  const ip = randIp();
  const email = randEmail();
  const password = 'Test1234!';

  await register(request, email, password, ip);

  const r2 = await login(request, email, 'WrongPassword!', ip);
  expect(r2.status()).toBe(401);
});

test('list files without token -> 401', async ({ request }) => {
  const res = await request.get(`${API}/files`);
  expect(res.status()).toBe(401);
});

test('upload without token -> 401', async ({ request }) => {
  const res = await request.post(`${API}/files/upload`, {
    multipart: {
      file: {
        name: 'a.txt',
        mimeType: 'text/plain',
        buffer: Buffer.from('hello'),
      },
    },
  });
  expect(res.status()).toBe(401);
});

test('upload forbidden extension (.exe) -> refused', async ({ request }) => {
  const ip = randIp();
  const email = randEmail();
  const password = 'Test1234!';

  await register(request, email, password, ip);
  const l = await login(request, email, password, ip);
  const token = (await l.json()).token as string;

  const res = await request.post(`${API}/files/upload`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'x-forwarded-for': ip,
    },
    multipart: {
      file: {
        name: 'evil.exe',
        mimeType: 'application/octet-stream',
        buffer: Buffer.from('MZ....fake'),
      },
    },
  });

  expect([400, 403]).toContain(res.status());
  const txt = await res.text();
  expect(txt.toLowerCase()).toMatch(/interdit|refus|forbid|virus|clamav|fail|danger|rate/i);
});

test('upload + list files -> file appears', async ({ request }) => {
  const ip = randIp();
  const email = randEmail();
  const password = 'Test1234!';

  await register(request, email, password, ip);
  const l = await login(request, email, password, ip);
  expect(l.status()).toBe(200);
  const token = (await l.json()).token as string;

  const filename = `hello_${Date.now()}.txt`;
  const up = await request.post(`${API}/files/upload`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'x-forwarded-for': ip,
    },
    multipart: {
      file: {
        name: filename,
        mimeType: 'text/plain',
        buffer: Buffer.from('hello world'),
      },
    },
  });

  expect(up.status()).toBe(200);

  const list = await request.get(`${API}/files`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'x-forwarded-for': ip,
    },
  });

  expect(list.status()).toBe(200);
  const items = await list.json();
  expect(Array.isArray(items)).toBe(true);
  const names = items.map((x: any) => x.filename);
  expect(names).toContain(filename);
});

test('download forbidden (other user) -> 403', async ({ request }) => {
  const ip1 = randIp();
  const ip2 = randIp();

  const email1 = randEmail();
  const pass1 = 'Test1234!';
  await register(request, email1, pass1, ip1);
  const l1 = await login(request, email1, pass1, ip1);
  const t1 = (await l1.json()).token as string;

  // user1 upload
  const up = await request.post(`${API}/files/upload`, {
    headers: {
      Authorization: `Bearer ${t1}`,
      'x-forwarded-for': ip1,
    },
    multipart: {
      file: {
        name: `u1_${Date.now()}.txt`,
        mimeType: 'text/plain',
        buffer: Buffer.from('secret'),
      },
    },
  });
  expect(up.status()).toBe(200);

  // get file id from list
  const list1 = await request.get(`${API}/files`, {
    headers: {
      Authorization: `Bearer ${t1}`,
      'x-forwarded-for': ip1,
    },
  });
  expect(list1.status()).toBe(200);
  const files1 = await list1.json();
  expect(files1.length).toBeGreaterThan(0);
  const fileId = files1[0].id;

  // user2 tries download -> 403
  const email2 = randEmail();
  const pass2 = 'Test1234!';
  await register(request, email2, pass2, ip2);
  const l2 = await login(request, email2, pass2, ip2);
  const t2 = (await l2.json()).token as string;

  const dl = await request.get(`${API}/files/${fileId}/download`, {
    headers: {
      Authorization: `Bearer ${t2}`,
      'x-forwarded-for': ip2,
    },
  });

  expect(dl.status()).toBe(403);
});
