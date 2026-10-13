// AC3: real upstream client methods; the wrapper supplies Fetch header/cookie transport.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import Client from './node_modules/vanilla-token-auth/dist/index.mjs';

const [baseUrl, mailpitUrl, profile] = process.argv.slice(2);
const email = `js-${randomUUID()}@example.com`;
const password = 'test-password';
const target = 'https://client.example.test/done';
const memory = new Map();
const storage = {
  persistData: (key, val) => memory.set(key, val),
  retrieveData: key => memory.get(key),
  deleteData: key => memory.delete(key),
};
const localStorage = {
  setItem: (key, val) => memory.set(`local-${key}`, val),
  getItem: key => memory.get(`local-${key}`) ?? null,
  removeItem: key => memory.delete(`local-${key}`),
};
// Browser facilities used by the client for persistence and expiry scheduling.
// Native Node Fetch carries actual HTTP; no auth endpoint is simulated.
globalThis.window = {
  localStorage, sessionStorage: localStorage,
  location: {search: '', pathname: '/', href: target},
  setInterval: (...args) => {const timer = setInterval(...args); timer.unref(); return timer;},
  clearInterval, setTimeout, clearTimeout,
};
let cookie = '';
let csrf = '';
let captured = {};
let client;
const trace = [];
const httpWrapper = async (url, init = {}) => {
  const headers = new Headers(init.headers);
  if (profile === 'cookie') {
    if (cookie || csrf) headers.set('Cookie', [cookie, csrf].filter(Boolean).join('; '));
    if (csrf && !['GET', 'HEAD', 'OPTIONS'].includes(init.method ?? 'GET')) {
      headers.set('X-XSRF-TOKEN', decodeURIComponent(csrf.split('=').slice(1).join('=')));
    }
  } else {
    for (const [key, value] of Object.entries(memory.get('auth_headers') ?? {})) {
      headers.set(key, value);
    }
  }
  const response = await fetch(url, {...init, headers, redirect: 'manual'});
  trace.push({method: init.method ?? 'GET', path: new URL(url).pathname, status: response.status});
  // Apply every write in order, as a browser does when Spring clears then replaces XSRF.
  for (const value of response.headers.getSetCookie()) {
    if (value.startsWith('auth_cookie=')) cookie = value.split(';')[0];
    if (value.startsWith('XSRF-TOKEN=')) csrf = value.split(';')[0];
  }
  const next = {};
  for (const key of ['access-token', 'client', 'uid', 'expiry', 'token-type']) {
    const value = response.headers.get(key);
    if (value?.trim()) next[key] = value;
  }
  if (Object.keys(next).length === 5) {
    captured = next;
    if (profile !== 'cookie') client.setAuthHeaders(next);
  }
  return response;
};
client = new Client({
  apiUrl: baseUrl, storage, transport: profile === 'cookie' ? 'cookies' : 'headers',
  httpWrapper, validateOnPageLoad: false, confirmationSuccessUrl: target,
});
if (profile === 'cookie') {
  const bootstrap = await fetch(baseUrl + '/auth/sign_in');
  csrf = bootstrap.headers.getSetCookie().find(c => c.startsWith('XSRF-TOKEN=')).split(';')[0];
}
const registration = await client.submitRegistration({email, password, password_confirmation: password});
assert.equal(registration.status, 200);
assert.equal(registration.data.status, 'success');
if (profile === 'strict') {
  const listing = await (await fetch(`${mailpitUrl}/api/v1/messages`)).json();
  const message = listing.messages.find(m => m.To.some(t => t.Address === email));
  assert.ok(message, 'confirmation email delivered');
  const details = await (await fetch(`${mailpitUrl}/api/v1/message/${message.ID}`)).json();
  const link = details.HTML.match(/href="([^"]+)"/)[1].replaceAll('&amp;', '&');
  const url = new URL(link);
  const confirmation = await fetch(baseUrl + url.pathname + url.search, {redirect: 'manual'});
  assert.equal(confirmation.status, 302);
  assert.equal(new URL(confirmation.headers.get('location')).searchParams.get('account_confirmation_success'), 'true');
}
await client.submitLogin({email, password});
assert.equal(client.user.email, email);
const validate = await client.validateToken();
assert.equal(validate.status, 200);
assert.equal(validate.data.success, true);
assert.equal(validate.data.data.email, email);
const revoked = {...captured};
const signout = await client.signOut();
assert.equal(signout.status, 200);
assert.deepEqual(signout.data, {success: true});
const rejected = await fetch(baseUrl + '/auth/validate_token', {headers: revoked});
assert.equal(rejected.status, 401);
assert.deepEqual(await rejected.json(), {success: false, errors: ['Invalid login credentials']});
console.log(JSON.stringify({client: 'vanilla-token-auth@1.0.6', trace, revoked: true}));
