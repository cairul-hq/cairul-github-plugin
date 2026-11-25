import { Buffer } from 'node:buffer';
import { createPrivateKey, sign } from 'node:crypto';
import { URL } from 'node:url';
import { credential, positiveID, requireSecureTransport } from '@cairul/pdk';

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

export function installationCredential(base, config) {
  const appId = positiveID.safeParse(config.appId);
  const installationId = positiveID.safeParse(config.installationId);
  if (!appId.success || !installationId.success)
    throw new Error('GitHub App auth requires a numeric app ID and installation ID.');
  requireSecureTransport(base);
  const getKey = credential('GITHUB', 'APP_PRIVATE_KEY', {
    file: config.privateKeyFile,
    legacy: 'GITHUB_APP_PRIVATE_KEY',
    required: true,
  });
  const endpoint = new URL(base);
  endpoint.pathname = base.pathname.replace(/\/$/, '') + '/app/installations/' + installationId.data + '/access_tokens';
  let cached;
  let refresh;

  async function exchange(signal) {
    const pem = await getKey(signal);
    let assertion;
    try {
      const key = createPrivateKey(pem);
      if (key.asymmetricKeyType !== 'rsa') throw new Error('Expected RSA.');
      const now = Math.floor(Date.now() / 1000);
      const unsigned =
        encode({ alg: 'RS256', typ: 'JWT' }) +
        '.' +
        encode({
          iss: appId.data,
          iat: now - 60,
          exp: now + 540,
        });
      assertion = unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), key).toString('base64url');
    } catch {
      throw new Error('GitHub App private key is invalid. Use an unencrypted RSA PEM key.');
    }
    let response;
    try {
      response = await globalThis.fetch(endpoint, {
        method: 'POST',
        signal,
        redirect: 'error',
        headers: {
          accept: 'application/vnd.github+json',
          authorization: 'Bearer ' + assertion,
          'x-github-api-version': '2022-11-28',
        },
      });
    } catch {
      throw new Error('GitHub App token exchange failed.');
    }
    if (!response.ok) throw new Error('GitHub App token exchange returned HTTP ' + response.status + '.');
    const payload = await response.json().catch(() => undefined);
    const expires = Date.parse(payload?.expires_at);
    if (typeof payload?.token !== 'string' || !payload.token || !(expires > Date.now())) {
      throw new Error('GitHub returned an invalid installation token.');
    }
    cached = { token: payload.token, expires };
    return cached.token;
  }

  return (signal) => {
    if (cached && Date.now() < cached.expires - 60_000) return cached.token;
    refresh ??= exchange(signal).finally(() => {
      refresh = undefined;
    });
    return refresh;
  };
}
