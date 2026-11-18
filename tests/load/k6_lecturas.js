// Prueba de carga (Grafana k6) de la analítica de noticias, con comportamiento real de lectores y del panel.
//
//   1. .venv/Scripts/python tests/load/preparar_bd.py            (BD desechable k6_load en noticias_test)
//   2. backend de carga en :8006 con DATABASE_URL = la que imprime el paso 1, como en producción:
//      uvicorn app.main:app --port 8006 --workers 4   (sin --reload)
//   3. k6 run tests/load/k6_lecturas.js        (variables: BASE, PICO, MESETA, NOTICIAS, K6_ADMIN_PASSWORD)
//   4. .venv/Scripts/python tests/load/preparar_bd.py --borrar
//
// Escenarios simultáneos:
// - lectores: cada usuario virtual abre una noticia (vista), lee enviando un latido cada 15 s (como el
//   navegador, solo mientras hay actividad), a veces comparte, y pasa a otra. Cada lector tiene su propia IP
//   (X-Forwarded-For, que uvicorn acepta desde 127.0.0.1) para que el límite por IP sea el real.
// - panel: administradores con el panel abierto: «En vivo» cada 10 s; panel completo y ranking cada minuto.
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE || 'http://127.0.0.1:8006';
const PICO = Number(__ENV.PICO || 600); // lectores simultáneos en el pico
const MESETA = Number(__ENV.MESETA || 300); // lectores simultáneos sostenidos
const NOTICIAS = Number(__ENV.NOTICIAS || 40); // ids 1..N publicados (ver preparar_bd.py)

const UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
];
const REFERRERS = ['', 'https://www.google.com/', 'https://l.facebook.com/', 'https://t.co/x', 'http://localhost:5173/noticias'];
const CHANNELS = ['whatsapp', 'facebook', 'email', 'copy_link', 'x', 'linkedin'];
const pick = (a) => a[Math.floor(Math.random() * a.length)];

export const options = {
  scenarios: {
    lectores: {
      executor: 'ramping-vus',
      exec: 'lector',
      startVUs: 0,
      stages: [
        { duration: '30s', target: MESETA / 3 },
        { duration: '1m', target: MESETA },
        { duration: '2m', target: MESETA },
        { duration: '30s', target: PICO }, // pico: una noticia se vuelve viral
        { duration: '1m', target: PICO },
        { duration: '30s', target: 0 },
      ],
      gracefulRampDown: '20s',
    },
    panel: { executor: 'constant-vus', exec: 'panel', vus: 5, duration: '5m30s' },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
    'http_req_duration{name:vista}': ['p(95)<250'],
    'http_req_duration{name:latido}': ['p(95)<250'],
    'http_req_duration{name:compartir}': ['p(95)<250'],
    'http_req_duration{name:en_vivo}': ['p(95)<300'],
    'http_req_duration{name:panel}': ['p(95)<2000'],
    'http_req_duration{name:ranking}': ['p(95)<1000'],
    'http_req_duration{name:consentimiento}': ['p(95)<250'],
  },
};

export function setup() {
  const r = http.post(
    `${BASE}/api/auth/login`,
    JSON.stringify({
      email: 'k6-admin@unisimon.edu.co',
      password: __ENV.K6_ADMIN_PASSWORD || 'Carga-K6-Prueba-2026!',
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(r, { 'login 200': (x) => x.status === 200 });
  const name = Object.keys(r.cookies).find((k) => k.includes('session'));
  return { cookie: `${name}=${r.cookies[name][0].value}` };
}

function send(ip, ua, sid, events, name) {
  const r = http.post(`${BASE}/api/news/lecturas`, JSON.stringify({ session_id: sid, events }), {
    headers: { 'Content-Type': 'application/json', 'User-Agent': ua, 'X-Forwarded-For': ip },
    tags: { name },
  });
  check(r, { [`${name} 202`]: (x) => x.status === 202 });
}

export function lector() {
  const ip = `10.${(__VU >> 8) & 255}.${__VU & 255}.${1 + (__ITER % 250)}`;
  const ua = pick(UAS);
  const sid = crypto.randomUUID();
  // 70 % de las lecturas van a 5 noticias (las del momento); el resto se reparte.
  const news = Math.random() < 0.7 ? 1 + Math.floor(Math.random() * 5) : 1 + Math.floor(Math.random() * NOTICIAS);
  const ref = pick(REFERRERS);
  // Primera visita: el aviso de privacidad. 80 % autoriza la analítica; el resto rechaza y el servidor
  // descarta sus eventos (también se mide ese camino). La cookie cris_consent queda en el jar del VU.
  const accepts = Math.random() < 0.8;
  const c = http.post(`${BASE}/api/privacy/consents`,
    JSON.stringify({ functional: accepts, analytics: accepts, method: accepts ? 'accept_all' : 'reject_optional' }),
    { headers: { 'Content-Type': 'application/json', 'User-Agent': ua, 'X-Forwarded-For': ip }, tags: { name: 'consentimiento' } });
  check(c, { 'consentimiento 200': (x) => x.status === 200 });
  send(ip, ua, sid, [{ type: 'view', news_id: news, referrer: ref || undefined, is_entry: !ref.includes('localhost') }], 'vista');
  const beats = 1 + Math.floor(Math.random() * 8); // lee entre 15 s y 2 min
  for (let i = 0; i < beats; i++) {
    sleep(15);
    send(ip, ua, sid, [{ type: 'heartbeat', news_id: news }], 'latido');
  }
  if (Math.random() < 0.1) send(ip, ua, sid, [{ type: 'share', news_id: news, channel: pick(CHANNELS) }], 'compartir');
  sleep(1 + Math.random() * 3); // pasa a otra noticia
}

export function panel(data) {
  const params = (name) => ({ headers: { Cookie: data.cookie }, tags: { name } });
  const today = new Date(Date.now() - 5 * 3600 * 1000).toISOString().slice(0, 10); // día en Bogotá
  const from = new Date(Date.now() - (5 + 29 * 24) * 3600 * 1000).toISOString().slice(0, 10);
  const q = `start_date=${from}&end_date=${today}`;
  if (__ITER % 6 === 0) {
    // el navegador pide el panel completo y la tabla cada minuto
    const o = http.get(`${BASE}/api/news/analytics/overview?${q}`, params('panel'));
    check(o, { 'panel 200': (x) => x.status === 200 });
    const rk = http.get(`${BASE}/api/news/analytics/news?${q}&sort=views&page=1&page_size=20`, params('ranking'));
    check(rk, { 'ranking 200': (x) => x.status === 200 });
  }
  const l = http.get(`${BASE}/api/news/analytics/live?${q}`, params('en_vivo'));
  check(l, { 'en vivo 200': (x) => x.status === 200 });
  sleep(10);
}
