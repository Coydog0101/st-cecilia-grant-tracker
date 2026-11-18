/* St. Cecilia Grant Tracker - runs entirely in the browser.
 *
 * data/grants.enc.json    written every other Monday by the GitHub Action (scanner/scan.py)
 * data/decisions.enc.json written by this page via the GitHub API (Apply / Decline / team notes)
 * Both are AES-256-GCM encrypted with a key derived from the shared password
 * (same format as scanner/crypto_util.py), so the public repo only holds ciphertext.
 */
'use strict';

const DATA_URL = 'data/grants.enc.json';
const STAGES = ['Preparing', 'Submitted', 'Awarded', 'Not awarded'];
const NEW_DAYS = 15;  // scans run every other week
const te = new TextEncoder();
const td = new TextDecoder();
const $ = (sel) => document.querySelector(sel);
const PAGE = document.body.dataset.page || 'tracker';  // 'tracker' (index.html) or 'activity' (activity.html)
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;

const S = {
  password: '', who: '', data: null, grants: [], decisions: {}, activity: [], decisionsSha: null,
  tab: 'open', query: '', category: '', sort: 'deadline', showClosed: false, selected: null,
};

/* ------------------------------------------------------------------ crypto */
const b64decode = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
function b64encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
const keyCache = new Map();
async function deriveKey(password, salt, iterations) {
  const id = `${password}\u0000${b64encode(salt)}:${iterations}`;
  if (!keyCache.has(id)) {
    const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
    keyCache.set(id, crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']));
  }
  return keyCache.get(id);
}
async function decryptEnvelope(env, password) {
  const key = await deriveKey(password, b64decode(env.salt), env.iter || 310000);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(env.iv) }, key, b64decode(env.ct));
  return JSON.parse(td.decode(plain));
}
let writeSalt = null;
async function encryptObject(obj, password) {
  writeSalt ||= crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iter = 310000;
  const key = await deriveKey(password, writeSalt, iter);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj))));
  return { v: 1, kdf: 'PBKDF2-SHA256', iter, salt: b64encode(writeSalt), iv: b64encode(iv), ct: b64encode(ct) };
}

/* ------------------------------------------------------------------ storage helpers */
const store = {
  get(k) { try { return sessionStorage.getItem(k) ?? localStorage.getItem(k); } catch { return null; } },
  set(k, v, persist) { try { (persist ? localStorage : sessionStorage).setItem(k, v); } catch { /* unavailable */ } },
  clear(k) { try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch { /* ignore */ } },
};

/* ------------------------------------------------------------------ GitHub (decisions + notes) */
function gh(path, opts = {}) {
  const g = S.data.github;
  return fetch(`https://api.github.com/repos/${g.repo}/${path}`, {
    ...opts,
    cache: 'no-store',
    headers: {
      Authorization: `Bearer ${g.token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(opts.headers || {}),
    },
  });
}
function canSave() { return !!(S.data?.github?.token && S.data?.github?.repo); }

const MAX_ACTIVITY = 5000;   // keep the newest events; older ones roll off

/** Shared file: { decisions: {grantId: record}, activity: [event, ...] } */
async function fetchDecisions() {
  if (!canSave()) return { sha: null, decisions: {}, activity: [] };
  const g = S.data.github;
  const r = await gh(`contents/${g.decisions_path}?ref=${encodeURIComponent(g.branch)}&t=${Date.now()}`);
  if (r.status === 404) return { sha: null, decisions: {}, activity: [] };
  if (!r.ok) throw new Error(`GitHub returned ${r.status} reading decisions`);
  const j = await r.json();
  const env = JSON.parse(td.decode(b64decode(j.content.replace(/\s/g, ''))));
  let data;
  try { data = await decryptEnvelope(env, S.password); } catch {
    throw new Error('The saved decisions could not be unlocked with this password.');
  }
  return { sha: j.sha, decisions: data.decisions || {}, activity: data.activity || [] };
}

async function refreshDecisions() {
  try {
    const { sha, decisions, activity } = await fetchDecisions();
    if (sha && sha === S.decisionsSha) return;
    S.decisionsSha = sha;
    S.decisions = decisions;
    S.activity = activity;
    render();
  } catch (e) { toast(e.message, true); }
}

/** Read-modify-write the shared file, retrying if someone else saved first. */
async function commitShared(mutate) {
  const g = S.data.github;
  for (let attempt = 0; attempt < 4; attempt++) {
    const latest = await fetchDecisions();             // merge with what others saved
    const next = mutate({ decisions: { ...latest.decisions }, activity: [...latest.activity] });
    next.activity = next.activity.slice(-MAX_ACTIVITY);
    const envelope = await encryptObject({ ...next, updated_at: new Date().toISOString() }, S.password);
    const body = {
      message: 'Update decisions',                     // never put names or grant details in public commit messages
      content: b64encode(te.encode(JSON.stringify(envelope) + '\n')),
      branch: g.branch,
    };
    if (latest.sha) body.sha = latest.sha;
    const r = await gh(`contents/${g.decisions_path}`, { method: 'PUT', body: JSON.stringify(body) });
    if (r.ok) {
      const j = await r.json();
      S.decisionsSha = j.content?.sha || null;
      S.decisions = next.decisions;
      S.activity = next.activity;
      return;
    }
    if (r.status !== 409 && r.status !== 422) throw new Error(`GitHub returned ${r.status} while saving`);
  }
  throw new Error('Could not save (someone else was saving at the same time). Try again.');
}

function deviceLabel() {
  const ua = navigator.userAgent;
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android'
    : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'Mac' : /CrOS/.test(ua) ? 'Chromebook' : 'Other';
  const br = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  return `${os} · ${br}`;
}

/** Record one visit per person per day per device (quietly; never blocks the page). */
async function logVisit() {
  if (!canSave() || !S.who) return;
  const day = new Date().toLocaleDateString('en-CA');
  const key = `stc-visit-${S.who.toLowerCase()}-${day}`;
  if (store.get(key)) return;
  try {
    await commitShared((d) => { d.activity.push({ type: 'visit', by: S.who, at: new Date().toISOString(), device: deviceLabel() }); return d; });
    store.set(key, '1', true);
  } catch { /* visit logging is best-effort */ }
}

/** Replace one grant's record (status + notes), log the action, and save. */
async function saveRecord(id, record, okMsg = 'Saved', action = 'notes') {
  if (!canSave()) { toast('Saving is not set up yet (GH_DATA_TOKEN secret missing). See README.', true); return; }
  const before = S.decisions[id];
  S.decisions[id] = record;
  render();
  const g = S.grants.find((x) => x.id === id);
  try {
    await commitShared((d) => {
      d.decisions[id] = record;
      d.activity.push({ type: action, by: S.who || 'Someone', at: new Date().toISOString(), id, title: g?.title || '' });
      return d;
    });
    render();
    toast(okMsg);
  } catch (e) {
    if (before) S.decisions[id] = before; else delete S.decisions[id];
    render();
    toast(e.message, true);
  }
}

/* ------------------------------------------------------------------ dates */
function daysUntil(iso) {
  if (!iso) return null;
  const [y, m, d] = iso.split('-').map(Number);
  const t = new Date(); t.setHours(0, 0, 0, 0);
  return Math.round((new Date(y, m - 1, d) - t) / 86400000);
}
function parts(iso) { const [y, m, d] = iso.slice(0, 10).split('-').map(Number); return new Date(y, m - 1, d); }
const fmtDate = (iso) => (iso ? parts(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '');
const fmtDateTime = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '');
function deadlineBadge(g) {
  const n = daysUntil(g.deadline);
  if (n === null) return `<span class="badge">${esc(g.deadline_note ? short(g.deadline_note, 34) : 'No deadline listed')}</span>`;
  if (n < 0) return `<span class="badge closed">Closed ${esc(fmtDate(g.deadline))}</span>`;
  const label = n === 0 ? 'Due today' : n === 1 ? 'Due tomorrow' : `${n} days left`;
  const cls = n <= 14 ? 'red' : n <= 45 ? 'amber' : 'green';
  return `<span class="badge ${cls}">${icon('cal')}${label}</span>`;
}
const isClosed = (g) => g.deadline && daysUntil(g.deadline) < 0;
const isNew = (g) => g.first_seen && (Date.now() - new Date(g.first_seen)) / 86400000 <= NEW_DAYS;
function fitBadge(g) {
  const n = Number(g.fit_score) || 0;
  if (!n) return '';
  const label = n >= 5 ? 'Excellent fit' : n === 4 ? 'Strong fit' : n === 3 ? 'Possible fit' : 'Weak fit';
  return `<span class="badge ${n >= 4 ? 'navy' : ''}" title="How well this suits a Catholic PreK–8 school (AI estimate, 1–5)">${'★'.repeat(n)}${'☆'.repeat(5 - n)} ${label}</span>`;
}

/* ------------------------------------------------------------------ utils */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const safeUrl = (u) => (/^https?:\/\//i.test(u || '') ? u : '');
const points = (s) => String(s || '').split(/\n+/).map((x) => x.replace(/^\s*[-•*]\s*/, '').trim()).filter(Boolean);
let toastTimer;
function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg; t.className = 'toast' + (err ? ' err' : ''); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, err ? 6000 : 2200);
}
const statusOf = (id) => S.decisions[id]?.status || 'open';
const hasNotes = (d) => !!(d && (d.pros_note || d.cons_note || d.note));

/* ------------------------------------------------------------------ rendering */
function visibleGrants() {
  const q = S.query.trim().toLowerCase();
  let list = S.grants.filter((g) => statusOf(g.id) === S.tab);
  if (S.tab === 'open' && !S.showClosed) list = list.filter((g) => !isClosed(g));
  if (S.category) list = list.filter((g) => g.category === S.category);
  if (q) {
    list = list.filter((g) => {
      const d = S.decisions[g.id] || {};
      return [g.title, g.funder, g.description, g.eligibility, g.fit, g.pros, g.cons, g.category, g.amount, g.grade_levels,
        d.note, d.pros_note, d.cons_note, d.by, d.stage].join(' ').toLowerCase().includes(q);
    });
  }
  const dl = (g) => (g.deadline && !isClosed(g) ? g.deadline : g.deadline ? 'zz' + g.deadline : 'zzzz');
  const sorters = {
    deadline: (a, b) => dl(a).localeCompare(dl(b)) || a.title.localeCompare(b.title),
    fit: (a, b) => (Number(b.fit_score) || 0) - (Number(a.fit_score) || 0) || dl(a).localeCompare(dl(b)),
    new: (a, b) => (b.first_seen || '').localeCompare(a.first_seen || ''),
    title: (a, b) => a.title.localeCompare(b.title),
    decided: (a, b) => (S.decisions[b.id]?.at || '').localeCompare(S.decisions[a.id]?.at || ''),
  };
  return list.sort(sorters[S.sort] || sorters.deadline);
}

function renderStats() {
  const open = S.grants.filter((g) => statusOf(g.id) === 'open' && !isClosed(g));
  const soon = S.grants.filter((g) => statusOf(g.id) !== 'declined' && g.deadline && daysUntil(g.deadline) >= 0 && daysUntil(g.deadline) <= 30);
  const fresh = S.grants.filter((g) => statusOf(g.id) === 'open' && isNew(g));
  const applying = S.grants.filter((g) => statusOf(g.id) === 'applying');
  const stat = (n, l, ic, cls = '') => `<div class="stat ${cls}"><div class="ic">${icon(ic)}</div><div><div class="n">${n}</div><div class="l">${l}</div></div></div>`;
  $('#stats').innerHTML = stat(open.length, 'Open opportunities', 'list') + stat(fresh.length, `New since last search`, 'spark')
    + stat(soon.length, 'Due in the next 30 days', 'cal', 'hot') + stat(applying.length, 'We’re applying', 'send', 'good');

  const up = S.grants
    .filter((g) => statusOf(g.id) !== 'declined' && g.deadline && daysUntil(g.deadline) >= 0 && daysUntil(g.deadline) <= 60)
    .sort((a, b) => a.deadline.localeCompare(b.deadline)).slice(0, 10);
  $('#upcoming').innerHTML = up.length
    ? `<ul class="dl-row">${up.map((g) => {
        const d = parts(g.deadline); const n = daysUntil(g.deadline);
        return `<li><button type="button" class="dl-tile" data-jump="${esc(g.id)}">
          <div class="cal ${n <= 14 ? 'urgent' : ''}"><div class="m">${d.toLocaleDateString(undefined, { month: 'short' }).toUpperCase()}</div><div class="d">${d.getDate()}</div></div>
          <div class="dl-body"><span class="t">${esc(g.title)}</span><span class="f">${esc(g.funder)}</span>
            <span>${deadlineBadge(g)} ${statusOf(g.id) === 'applying' ? '<span class="badge green">Applying</span>' : ''}</span></div>
        </button></li>`;
      }).join('')}</ul>`
    : `<div class="empty-soft">${icon('cal')}<span>No deadlines in the next 60 days. New opportunities are added every other Monday.</span></div>`;

  for (const t of ['open', 'applying', 'declined']) {
    $(`#c-${t}`).textContent = S.grants.filter((g) => statusOf(g.id) === t && (t !== 'open' || !isClosed(g))).length;
  }
}

function renderList() {
  const list = visibleGrants();
  document.querySelectorAll('.tab').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === S.tab)));
  $('#list-title').textContent = { open: 'Opportunities', applying: 'Applying', declined: 'Declined' }[S.tab];
  if (!list.length) {
    const msg = S.query || S.category ? 'Nothing matches your search.'
      : S.tab === 'open' ? 'No open opportunities right now. The next search runs on the next scan Monday.'
      : S.tab === 'applying' ? 'Nothing here yet. Choose “Apply” on an opportunity to track it here.'
      : 'Nothing declined yet.';
    $('#list').innerHTML = `<div class="empty">${icon(S.tab === 'applying' ? 'send' : 'note')}<span>${msg}</span></div>`;
    return;
  }
  $('#list').innerHTML = list.map((g) => {
    const d = S.decisions[g.id];
    return `<button type="button" class="card" data-id="${esc(g.id)}" aria-current="${g.id === S.selected}">
      <span class="funder">${esc(g.funder)}</span>
      <span class="ttl">${esc(g.title)}</span>
      <span class="meta">${deadlineBadge(g)}
        ${g.amount ? `<span class="badge">${esc(short(g.amount, 36))}</span>` : ''}
        ${isNew(g) && S.tab === 'open' ? '<span class="badge new">New</span>' : ''}
        ${Number(g.fit_score) >= 4 ? `<span class="badge navy">${'★'.repeat(Number(g.fit_score))}</span>` : ''}
        ${d?.stage && d.status === 'applying' ? `<span class="badge">${esc(d.stage)}</span>` : ''}
        ${hasNotes(d) ? `<span class="badge" title="Team notes">${icon('pen')}Notes</span>` : ''}
      </span></button>`;
  }).join('');
}

function proconHtml(g, d) {
  const list = (s) => { const p = points(s); return p.length ? `<ul>${p.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p class="none">No suggestions yet.</p>'; };
  return `<div class="procon">
    <div class="pc pro">
      <h3>${icon('thumb')}Why we’re a good candidate</h3>
      <span class="sub">Suggested</span>${list(g.pros || g.fit)}
      <label><span class="sub">Our notes</span><textarea id="pros-note" placeholder="e.g. We already have the STEM lab plan and budget ready">${esc(d?.pros_note || '')}</textarea></label>
    </div>
    <div class="pc con">
      <h3>${icon('alert')}Why we might not be</h3>
      <span class="sub">Suggested</span>${list(g.cons)}
      <label><span class="sub">Our notes</span><textarea id="cons-note" placeholder="e.g. Requires a 1:1 match we may not have this year">${esc(d?.cons_note || '')}</textarea></label>
    </div>
  </div>`;
}

function renderDetail() {
  const g = S.grants.find((x) => x.id === S.selected);
  const el = $('#detail');
  if (!g) {
    el.innerHTML = `<div class="placeholder">${icon('book')}<strong>Choose an opportunity</strong><span>Select one from the list to read what it funds, why it may suit St. Cecilia, and to record your decision.</span></div>`;
    document.body.classList.remove('show-detail');
    return;
  }
  const d = S.decisions[g.id];
  const status = statusOf(g.id);
  const url = safeUrl(g.url);
  const page = safeUrl(g.source_page);
  const n = daysUntil(g.deadline);
  const section = (h, body) => (body ? `<section><h3>${h}</h3><p>${esc(body)}</p></section>` : '');
  const who = d?.by ? `<span class="decided-by">${status === 'open' ? 'Notes by' : 'Decided by'} ${esc(d.by)} · ${esc(fmtDateTime(d.at))}${d.edited_by ? ` · last edit ${esc(d.edited_by)}` : ''}</span>` : '';

  let actions;
  if (status === 'open') {
    actions = `
      <label>Other notes<textarea id="note" placeholder="Anything else: who could write it, what project it would fund…">${esc(d?.note || '')}</textarea></label>
      <div class="row">
        <button class="btn apply" data-act="apply" type="button">${icon('check')}Apply</button>
        <button class="btn decline" data-act="decline" type="button">${icon('x')}Decline</button>
        <button class="btn" data-act="save-notes" type="button">${icon('pen')}Save notes only</button>
      </div>${who}`;
  } else {
    actions = `
      <div class="status">${status === 'applying' ? '<span class="badge green">Applying</span>' : '<span class="badge red">Declined</span>'} ${who}</div>
      ${status === 'applying' ? `<label>Stage<select id="stage">${STAGES.map((s) => `<option ${d.stage === s ? 'selected' : ''}>${s}</option>`).join('')}</select></label>` : ''}
      <label>Other notes<textarea id="note">${esc(d.note || '')}</textarea></label>
      <div class="row">
        <button class="btn primary" data-act="save-notes" type="button">${icon('pen')}Save changes</button>
        ${status === 'applying'
          ? `<button class="btn decline" data-act="decline" type="button">${icon('x')}Move to Declined</button>`
          : `<button class="btn apply" data-act="apply" type="button">${icon('check')}Move to Applying</button>`}
        <button class="btn ghost" data-act="reopen" type="button">Back to Opportunities</button>
      </div>`;
  }

  el.innerHTML = `
    <div class="detail-head">
      <button class="btn ghost back" data-act="close" type="button">← Back to list</button>
      <div class="funder">${esc(g.funder)}</div>
      <h2>${esc(g.title)}</h2>
      <div class="badges">${deadlineBadge(g)} ${fitBadge(g)}
        ${g.category ? `<span class="badge">${esc(g.category)}</span>` : ''}
        ${isNew(g) ? '<span class="badge new">New</span>' : ''}</div>
    </div>
    <div class="detail-body">
      <div class="facts">
        <div class="fact"><div class="k">Amount</div><div class="v">${esc(g.amount || 'Not stated')}</div></div>
        <div class="fact"><div class="k">Deadline</div><div class="v">${g.deadline ? esc(fmtDate(g.deadline)) : 'None listed'}</div>
          <div class="s">${n === null ? '' : n < 0 ? 'Closed' : n === 0 ? 'Due today' : `${n} days from today`}${g.deadline_note ? (n === null ? '' : ' · ') + esc(g.deadline_note) : ''}</div></div>
        <div class="fact"><div class="k">Grade levels</div><div class="v">${esc(g.grade_levels || 'Not stated')}</div>
          <div class="s">Found ${esc(fmtDate(g.first_seen))} via ${esc(g.source || 'scan')}</div></div>
      </div>
      <div class="links">
        ${url ? `<a class="btn primary" href="${esc(url)}" target="_blank" rel="noopener noreferrer">Open funder page ↗</a>` : ''}
        ${page && page !== url ? `<a class="btn" href="${esc(page)}" target="_blank" rel="noopener noreferrer">Source page ↗</a>` : ''}
        ${g.deadline && n >= 0 ? `<button class="btn" data-act="ics" type="button">${icon('cal')}Add to calendar</button>` : ''}
      </div>
      ${section('What it funds', g.description)}
      ${section('Who can apply', g.eligibility)}
      ${proconHtml(g, d)}
      <p class="disclaimer">Details and suggestions are gathered automatically. Always confirm eligibility and dates on the funder’s website before applying.</p>
      <div class="decision">${actions}</div>
    </div>`;
}

function renderSources() {
  const src = S.data.sources || [];
  const mark = { ok: '✓', changed: '★', error: '⚠', off: '–' };
  $('#sources-body').innerHTML = `<p class="muted" style="margin:8px 0 0">Last search ${esc(fmtDateTime(S.data.generated_at))}.
    Every other Monday we check Grants.gov, the watched funder pages${S.data.ai ? ', and run AI web searches' : ''}.
    ★ means a funder page changed since the last check.</p>
    <table>${src.map((s) => `<tr><td>${mark[s.status] || ''} ${esc(s.name)}</td>
      <td>${esc(s.detail || '')}${safeUrl(s.url) ? ` · <a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">page</a>` : ''}</td></tr>`).join('')}</table>`;
}

/* ------------------------------------------------------------------ activity */
const DAY = 86400000;
const ACTION_TEXT = { apply: 'moved to Applying', decline: 'declined', reopen: 'moved back to Opportunities', notes: 'updated notes on' };
function describe(ev) {
  if (ev.type === 'visit') return `opened the tracker${ev.device ? ` <span class="muted">(${esc(ev.device)})</span>` : ''}`;
  const what = ev.type.startsWith('stage:') ? `set stage to <b>${esc(ev.type.slice(6))}</b> for` : (ACTION_TEXT[ev.type] || esc(ev.type));
  return `${what} <a href="index.html#item=${encodeURIComponent(ev.id || '')}">${esc(ev.title || 'an opportunity')}</a>`;
}
function weekStart(d) { const x = new Date(d); x.setHours(0, 0, 0, 0); x.setDate(x.getDate() - ((x.getDay() + 6) % 7)); return x; }

function renderActivity() {
  const ev = S.activity || [];
  const now = Date.now();
  const visits = ev.filter((e) => e.type === 'visit');
  const v30 = visits.filter((e) => now - new Date(e.at) <= 30 * DAY);
  const people30 = new Set(v30.map((e) => e.by.trim().toLowerCase()));
  const actions = ev.filter((e) => e.type !== 'visit');
  const last = visits.length ? visits[visits.length - 1] : null;
  const stat = (n, l, ic, cls = '') => `<div class="stat ${cls}"><div class="ic">${icon(ic)}</div><div><div class="n">${n}</div><div class="l">${l}</div></div></div>`;

  // visits per week, last 12 weeks
  const weeks = [];
  const thisWeek = weekStart(new Date());
  for (let i = 11; i >= 0; i--) { const s = new Date(thisWeek); s.setDate(s.getDate() - 7 * i); weeks.push({ start: s, n: 0, people: new Set() }); }
  for (const e of visits) {
    const ws = weekStart(new Date(e.at)).getTime();
    const w = weeks.find((x) => x.start.getTime() === ws);
    if (w) { w.n++; w.people.add(e.by.trim()); }
  }
  const max = Math.max(1, ...weeks.map((w) => w.n));
  const W = 720, H = 180, padL = 28, padB = 26, padT = 12;
  const bw = (W - padL) / weeks.length;
  const ticks = [0, Math.ceil(max / 2), max].filter((v, i, a) => a.indexOf(v) === i);
  const y = (v) => H - padB - (v / max) * (H - padB - padT);
  const bars = weeks.map((w, i) => {
    const x = padL + i * bw + 2, h = Math.max(0, H - padB - y(w.n)), barW = bw - 4;
    const label = `Week of ${w.start.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}: ${w.n} visit${w.n === 1 ? '' : 's'}${w.people.size ? ' · ' + [...w.people].join(', ') : ''}`;
    const r = Math.min(4, h / 2, barW / 2);
    const path = h > 0 ? `M${x},${H - padB} v${-(h - r)} q0,${-r} ${r},${-r} h${barW - 2 * r} q${r},0 ${r},${r} v${h - r} z` : '';
    return `<g class="bar" tabindex="0" data-tip="${esc(label)}"><rect x="${x - 2}" y="${padT}" width="${bw}" height="${H - padB - padT}" fill="transparent"/>
      ${path ? `<path d="${path}"/>` : ''}
      ${i % 2 === 1 || weeks.length <= 6 ? `<text x="${x + barW / 2}" y="${H - 8}" text-anchor="middle">${w.start.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</text>` : ''}</g>`;
  }).join('');
  const grid = ticks.map((t) => `<line x1="${padL}" x2="${W}" y1="${y(t)}" y2="${y(t)}"/><text x="${padL - 6}" y="${y(t) + 4}" text-anchor="end">${t}</text>`).join('');

  // per-person table
  const people = new Map();
  for (const e of ev) {
    const k = e.by.trim().toLowerCase();
    const p = people.get(k) || { name: e.by.trim(), visits: 0, v30: 0, actions: 0, last: '', first: e.at, devices: new Set() };
    if (e.type === 'visit') { p.visits++; if (now - new Date(e.at) <= 30 * DAY) p.v30++; if (e.device) p.devices.add(e.device); } else p.actions++;
    if (e.at > p.last) p.last = e.at;
    people.set(k, p);
  }
  const rows = [...people.values()].sort((a, b) => b.last.localeCompare(a.last));
  const recent = ev.slice(-30).reverse();

  $('#activity-body').innerHTML = `
    <div class="stats stats-flat">
      ${stat(v30.length, 'Visits in the last 30 days', 'list')}
      ${stat(people30.size, 'People in the last 30 days', 'spark')}
      ${stat(actions.length, 'Decisions & notes saved', 'pen', 'good')}
      ${stat(last ? esc(fmtDate(last.at)) : '—', last ? `Last visit · ${esc(last.by)}` : 'No visits yet', 'cal', 'datestat')}
    </div>
    <div class="panel">
      <h3>Visits per week</h3>
      <p class="muted small">One visit is counted per person, per device, per day. Hover a bar for names.</p>
      <div class="chart-wrap"><svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Visits per week for the last 12 weeks">${grid}${bars}</svg>
        <div class="chart-tip" id="chart-tip" hidden></div></div>
    </div>
    <div class="act-grid">
      <div class="panel">
        <h3>Who’s using it</h3>
        ${rows.length ? `<table class="people"><thead><tr><th>Name</th><th>Visits (30 days)</th><th>All visits</th><th>Actions</th><th>Last seen</th></tr></thead>
          <tbody>${rows.map((p) => `<tr><td><b>${esc(p.name)}</b><div class="muted small">${esc([...p.devices].join(', '))}</div></td><td>${p.v30}</td><td>${p.visits}</td><td>${p.actions}</td><td>${esc(fmtDateTime(p.last))}</td></tr>`).join('')}</tbody></table>`
          : '<p class="muted">No activity recorded yet.</p>'}
      </div>
      <div class="panel">
        <h3>Recent activity</h3>
        ${recent.length ? `<ul class="feed">${recent.map((e) => `<li><span class="dot ${e.type === 'visit' ? '' : 'act'}"></span><div><b>${esc(e.by)}</b> ${describe(e)}<div class="muted small">${esc(fmtDateTime(e.at))}</div></div></li>`).join('')}</ul>`
          : '<p class="muted">Nothing yet.</p>'}
      </div>
    </div>
    <p class="muted small">Names are whatever each person types when unlocking. With one shared password, the tracker can’t verify who someone is.</p>`;
}

function render() {
  if (!S.data) return;
  if (PAGE === 'activity') { renderActivity(); return; }
  // keep half-typed notes if the same item is re-rendered (e.g. background refresh)
  const ids = ['note', 'pros-note', 'cons-note'];
  const keep = { id: S.selected, status: statusOf(S.selected), focused: document.activeElement?.id };
  for (const i of ids) keep[i] = document.getElementById(i)?.value;
  renderStats();
  renderList();
  renderDetail();
  if (keep.id === S.selected && keep.status === statusOf(S.selected)) {
    for (const i of ids) { const el = document.getElementById(i); if (el && keep[i] !== undefined) el.value = keep[i]; }
    if (ids.includes(keep.focused)) document.getElementById(keep.focused)?.focus();
  }
}

/* ------------------------------------------------------------------ actions */
function select(id) {
  S.selected = id;
  const st = statusOf(id);
  if (st !== S.tab) S.tab = st;
  render();
  document.body.classList.toggle('show-detail', !!id);
  if (window.matchMedia('(min-width: 861px)').matches) $('#browse').scrollIntoView({ block: 'start' });
  document.querySelector(`.card[data-id="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'nearest' });
}

function downloadIcs(g) {
  const d = g.deadline.replace(/-/g, '');
  const [y, m, day] = g.deadline.split('-').map(Number);
  const next = new Date(y, m - 1, day + 1).toLocaleDateString('en-CA').replace(/-/g, '');
  const clean = (s) => String(s || '').replace(/[\\;,]/g, (c) => '\\' + c).replace(/\r?\n/g, '\\n');
  const ics = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//St Cecilia Grant Tracker//EN', 'BEGIN:VEVENT',
    `UID:${g.id}-${d}@grant-tracker`, `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`,
    `DTSTART;VALUE=DATE:${d}`, `DTEND;VALUE=DATE:${next}`,
    `SUMMARY:${clean('Grant deadline: ' + g.title)}`, `DESCRIPTION:${clean(g.funder + '\n' + (g.url || ''))}`,
    'BEGIN:VALARM', 'TRIGGER:-P7D', 'ACTION:DISPLAY', 'DESCRIPTION:Grant deadline in 1 week', 'END:VALARM',
    'END:VEVENT', 'END:VCALENDAR'].join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([ics], { type: 'text/calendar' }));
  a.download = 'grant-deadline.ics';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function onDetailClick(e) {
  const act = e.target.closest('[data-act]')?.dataset.act;
  if (!act) return;
  const g = S.grants.find((x) => x.id === S.selected);
  if (act === 'close') { document.body.classList.remove('show-detail'); return; }
  if (!g) return;
  if (act === 'ics') { downloadIcs(g); return; }
  const prev = S.decisions[g.id] || {};
  const now = new Date().toISOString();
  const by = S.who || 'Someone';
  const notes = {
    note: $('#note')?.value.trim() || '',
    pros_note: $('#pros-note')?.value.trim() || '',
    cons_note: $('#cons-note')?.value.trim() || '',
  };
  const base = { ...prev, ...notes };
  if (act === 'apply') saveRecord(g.id, { ...base, status: 'applying', stage: prev.stage || 'Preparing', by, at: now }, 'Moved to Applying', 'apply');
  else if (act === 'decline') saveRecord(g.id, { ...base, status: 'declined', stage: undefined, by, at: now }, 'Moved to Declined', 'decline');
  else if (act === 'reopen') saveRecord(g.id, { ...base, status: 'open', stage: undefined, by, at: now }, 'Moved back to Opportunities', 'reopen');
  else if (act === 'save-notes') {
    const stage = $('#stage')?.value;
    const stageChanged = stage && stage !== prev.stage;
    saveRecord(g.id, { ...base, status: prev.status || 'open', ...(stage ? { stage } : {}),
      by: prev.by || by, at: prev.at || now, edited_by: by, edited_at: now }, 'Notes saved', stageChanged ? `stage:${stage}` : 'notes');
  }
}

/* ------------------------------------------------------------------ unlock */
async function unlock(password, quiet = false) {
  const res = await fetch(`${DATA_URL}?t=${Date.now()}`, { cache: 'no-store' });
  if (res.status === 404) throw new Error('No data yet. Run the “Grant scan” workflow once on GitHub (see README).');
  if (!res.ok) throw new Error(`Could not load data (${res.status}).`);
  const env = await res.json();
  try { S.data = await decryptEnvelope(env, password); } catch { throw new Error('That password didn’t work. Please try again.'); }
  S.password = password;
  S.grants = S.data.grants || [];
  $('#who-label').textContent = S.who ? `Signed in as ${S.who}` : '';
  if (PAGE === 'activity') {
    $('#lock').hidden = true; $('#app').hidden = false;
    await refreshDecisions();
    render();
    if (!canSave()) $('#activity-body').innerHTML = '<p class="muted">Activity tracking needs the GH_DATA_TOKEN secret (see README).</p>';
    return;
  }
  const cats = [...new Set(S.grants.map((g) => g.category).filter(Boolean))].sort();
  $('#category').innerHTML = '<option value="">All categories</option>' + cats.map((c) => `<option>${esc(c)}</option>`).join('');
  $('#scan-info').textContent = `${S.grants.length} opportunities tracked · last updated ${fmtDateTime(S.data.generated_at)}`;
  renderSources();
  $('#lock').hidden = true;
  $('#app').hidden = false;
  render();
  await refreshDecisions();
  if (!canSave() && !quiet) toast('Viewing only: saving is not set up yet (see README).', true);
  openFromHash();
  logVisit();
}

/** index.html#item=<id> (links from the Activity page) opens that opportunity. */
function openFromHash() {
  const m = location.hash.match(/^#item=(.+)$/);
  if (!m) return;
  const id = decodeURIComponent(m[1]);
  history.replaceState(null, '', location.pathname);
  if (S.grants.some((g) => g.id === id)) select(id); else toast('That opportunity is no longer in the list.');
}

function lock() {
  store.clear('stc-pw');
  S.password = ''; S.data = null; S.decisions = {}; S.activity = []; S.decisionsSha = null; keyCache.clear(); writeSalt = null;
  $('#app').hidden = true; $('#lock').hidden = false; $('#pw').value = ''; $('#pw').focus();
}

/* ------------------------------------------------------------------ wire up */
document.addEventListener('DOMContentLoaded', async () => {
  const art = document.getElementById('hero-art');
  document.querySelectorAll('[data-art]').forEach((el) => el.appendChild(art.content.cloneNode(true)));

  S.who = store.get('stc-who') || '';
  $('#who').value = S.who;

  $('#lock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#unlock-btn'); const label = btn.querySelector('span'); const err = $('#lock-error');
    btn.disabled = true; label.textContent = 'Unlocking…'; err.hidden = true;
    const pw = $('#pw').value;
    const remember = $('#remember').checked;
    S.who = $('#who').value.trim();
    if (!S.who) { err.textContent = 'Please enter your name.'; err.hidden = false; btn.disabled = false; label.textContent = 'Unlock'; return; }
    store.set('stc-who', S.who, true);
    try {
      await unlock(pw);
      store.set('stc-pw', pw, remember);
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    btn.disabled = false; label.textContent = 'Unlock';
  });

  $('#lock-btn').addEventListener('click', lock);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && S.data) refreshDecisions(); });
  setInterval(() => { if (S.data && !document.hidden) refreshDecisions(); }, 120000);
  if (PAGE === 'activity') wireActivity(); else wireTracker();

  const saved = store.get('stc-pw');
  if (saved) {
    try { await unlock(saved, true); } catch { store.clear('stc-pw'); }
  }
});

function wireActivity() {
  // chart tooltips
  const act = $('#activity');
  const showTip = (g) => {
    const tip = $('#chart-tip'); if (!tip || !g) return;
    tip.textContent = g.dataset.tip; tip.hidden = false;
    const box = g.getBoundingClientRect(), wrap = tip.parentElement.getBoundingClientRect();
    tip.style.left = `${Math.min(Math.max(box.left - wrap.left + box.width / 2, 90), wrap.width - 90)}px`;
    tip.style.top = `${box.top - wrap.top - 8}px`;
  };
  act.addEventListener('mouseover', (e) => showTip(e.target.closest('.bar')));
  act.addEventListener('focusin', (e) => showTip(e.target.closest('.bar')));
  act.addEventListener('mouseout', (e) => { if (e.target.closest('.bar')) { const t = $('#chart-tip'); if (t) t.hidden = true; } });
}

function wireTracker() {
  window.addEventListener('hashchange', () => { if (S.data) openFromHash(); });
  document.querySelectorAll('.tab').forEach((b) => b.addEventListener('click', () => {
    S.tab = b.dataset.tab; S.selected = null; render();
    $('#browse').scrollIntoView({ block: 'start' });
  }));
  $('#search').addEventListener('input', (e) => { S.query = e.target.value; renderList(); });
  $('#category').addEventListener('change', (e) => { S.category = e.target.value; renderList(); });
  $('#sort').addEventListener('change', (e) => { S.sort = e.target.value; renderList(); });
  $('#show-closed').addEventListener('change', (e) => { S.showClosed = e.target.checked; renderList(); });
  $('#list').addEventListener('click', (e) => { const c = e.target.closest('.card'); if (c) select(c.dataset.id); });
  $('#upcoming').addEventListener('click', (e) => { const b = e.target.closest('[data-jump]'); if (b) select(b.dataset.jump); });
  $('#detail').addEventListener('click', onDetailClick);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') document.body.classList.remove('show-detail'); });
}
