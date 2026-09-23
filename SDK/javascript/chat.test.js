const assert = require('node:assert/strict');
const { Authenticity } = require('./src/Authenticity');

async function main() {
  const client = new Authenticity('owner', 'app', 'https://example.test/api/v1/client', '1');
  client._session.token = 'token';
  client._session.isValid = true;
  const calls = [];
  client._request = async (path, body, authorized, method = 'POST') => {
    calls.push({ path, body, authorized, method });
    if (path === '/chat/profile') {
      return { success: 'true', profileId: 'user-1', nickname: 'أهلا', avatarId: 'avatar-2' };
    }
    if (path === '/chat/messages') {
      return { success: 'true', messages: [{ id: 'm1', channelId: 'general', senderId: 'user-1', sender: 'أهلا', avatarId: 'avatar-2', content: '**مرحبا**', timeSent: '2026-01-01T00:00:00Z' }] };
    }
    throw new Error(`Unexpected path: ${path}`);
  };

  assert.deepEqual(await client.getChatProfile(), { id: 'user-1', nickname: 'أهلا', avatarId: 'avatar-2' });
  assert.deepEqual(await client.updateChatProfile('أهلا', 'avatar-2'), { id: 'user-1', nickname: 'أهلا', avatarId: 'avatar-2' });
  assert.deepEqual(await client.getMessages('all'), [{ id: 'm1', channelId: 'general', senderId: 'user-1', sender: 'أهلا', avatarId: 'avatar-2', content: '**مرحبا**', timeSent: '2026-01-01T00:00:00Z' }]);
  assert.deepEqual(calls.map(({ path, method }) => `${method} ${path}`), [
    'POST /chat/profile', 'PUT /chat/profile', 'POST /chat/messages',
  ]);
  assert.equal(calls[1].body.nickname, 'أهلا');
  assert.equal(calls[1].body.avatarId, 'avatar-2');
  assert.equal(calls[2].body.channelId, 'all');
  assert.ok(calls.every(({ body, authorized }) => body.token === 'token' && body.appId === 'app' && authorized));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
