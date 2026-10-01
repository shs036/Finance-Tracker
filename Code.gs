/**
 * Sharma Finance: private web app for "Shubham Finance Tracker 2.0".
 *
 * Security
 *  - Only the Google accounts in ALLOWED can use the app (checked on every call).
 *  - Each person sets a PIN (stored as a salted SHA-256 hash in their own User Properties).
 *  - After unlocking, a session token lives 15 minutes from the last action; 5 wrong PINs lock the PIN for 15 minutes.
 *
 * Deploy (see the setup guide): Deploy > New deployment > Web app
 *   Execute as: User accessing the web app
 *   Who has access: Anyone with Google account   (the ALLOWED list below blocks everyone else)
 * Share the spreadsheet with Priya as Editor so the app can read and write it for her.
 */

const SHEET_ID = '1uYbrE4wljHRHYAwjmpxFL9cTt0YIgxg437IPbVKYD24';
const ALLOWED = {
  'shubham.sharma036@gmail.com': 'Shubham',
  'priyagoel059@gmail.com': 'Priya'
};
const REPORT_SHEET = 'Monthly Report';
const REPORT_FOLDER = 'Finance Reports';
const TX_FIRST_ROW = 5, TX_LAST_ROW = 1004, TX_FIRST_COL = 2;  // column A is a margin; B = Date
const TX_ADDED_BY_COL = 15;                                      // column O
const SESSION_SECONDS = 900, MAX_TRIES = 5, LOCKOUT_SECONDS = 900;

function doGet() {
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('Sharma Finance')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, viewport-fit=cover')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT);
}

/* ---------------- security ---------------- */

function who_() {
  const email = String(Session.getActiveUser().getEmail() || '').toLowerCase();
  const allowed = {};
  Object.keys(ALLOWED).forEach(k => allowed[k.toLowerCase()] = ALLOWED[k]);
  if (!email || !allowed[email]) throw new Error('ACCESS_DENIED: this account is not allowed to use Sharma Finance.');
  return { email, name: allowed[email] };
}

function hash_(salt, pin) {
  const bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + '|' + pin, Utilities.Charset.UTF_8);
  return Utilities.base64Encode(bytes);
}

function validPin_(pin) {
  if (!/^\d{4,6}$/.test(String(pin || ''))) throw new Error('PIN must be 4 to 6 digits.');
}

function newSession_() {
  const token = Utilities.getUuid();
  CacheService.getUserCache().put('session', token, SESSION_SECONDS);
  return token;
}

/** Checks the account and the session token; extends the session on each call. */
function guard_(token) {
  const user = who_();
  const cache = CacheService.getUserCache();
  const current = cache.get('session');
  if (!token || !current || current !== token) throw new Error('LOCKED');
  cache.put('session', token, SESSION_SECONDS);
  return user;
}

/** First call from the app: who is this, and do they have a PIN yet? */
function getAuthState() {
  const user = who_();
  const hasPin = !!PropertiesService.getUserProperties().getProperty('pinHash');
  return { name: user.name, hasPin };
}

/* sign-in activity: last 15 events per person, kept in their own User Properties */
function log_(ok, device, note) {
  const props = PropertiesService.getUserProperties();
  let log = [];
  try { log = JSON.parse(props.getProperty('log') || '[]'); } catch (e) {}
  log.unshift({ t: Date.now(), ok: !!ok, d: String(device || 'Unknown device').slice(0, 40), n: note || '' });
  props.setProperty('log', JSON.stringify(log.slice(0, 15)));
  return log;
}
function readLog_() {
  try { return JSON.parse(PropertiesService.getUserProperties().getProperty('log') || '[]'); } catch (e) { return []; }
}
/** What the welcome screen shows: the previous good sign-in and wrong PINs since then. */
function welcome_(user) {
  const log = readLog_();
  const prev = log.slice(1).find(x => x.ok) || null;
  let failed = 0;
  for (let i = 1; i < log.length && !log[i].ok; i++) failed++;
  return { token: newSession_(), name: user.name, last: prev, failed };
}

function setPin(pin, device) {
  const user = who_();
  validPin_(pin);
  const props = PropertiesService.getUserProperties();
  if (props.getProperty('pinHash')) throw new Error('A PIN is already set. Use Change PIN instead.');
  const salt = Utilities.getUuid();
  props.setProperties({ pinSalt: salt, pinHash: hash_(salt, pin) });
  log_(true, device, 'PIN created');
  return welcome_(user);
}

function unlock(pin, device) {
  const user = who_();
  const cache = CacheService.getUserCache();
  if (cache.get('lockout')) throw new Error('Too many wrong PINs. Try again in 15 minutes.');
  const props = PropertiesService.getUserProperties();
  const salt = props.getProperty('pinSalt'), stored = props.getProperty('pinHash');
  if (!stored) throw new Error('No PIN set yet.');
  if (hash_(salt, String(pin || '')) !== stored) {
    const tries = Number(cache.get('tries') || 0) + 1;
    log_(false, device, 'Wrong PIN');
    if (tries >= MAX_TRIES) { cache.put('lockout', '1', LOCKOUT_SECONDS); cache.remove('tries'); throw new Error('Too many wrong PINs. Locked for 15 minutes.'); }
    cache.put('tries', String(tries), LOCKOUT_SECONDS);
    throw new Error('Wrong PIN. ' + (MAX_TRIES - tries) + ' tries left.');
  }
  cache.remove('tries');
  log_(true, device, 'Unlocked');
  return welcome_(user);
}

/** Sign-in activity for the Settings > Security panel. */
function getActivity(token) {
  guard_(token);
  return readLog_();
}

function changePin(token, oldPin, newPin) {
  guard_(token);
  validPin_(newPin);
  const props = PropertiesService.getUserProperties();
  if (hash_(props.getProperty('pinSalt'), String(oldPin || '')) !== props.getProperty('pinHash')) throw new Error('Current PIN is wrong.');
  const salt = Utilities.getUuid();
  props.setProperties({ pinSalt: salt, pinHash: hash_(salt, newPin) });
  log_(true, '', 'PIN changed');
  return true;
}

function lock(token) {
  const cache = CacheService.getUserCache();
  if (cache.get('session') === token) cache.remove('session');
  return true;
}

/** Forgot your PIN? Open Extensions > Apps Script, pick resetMyPin and press Run. Then set a new PIN in the app. */
function resetMyPin() {
  PropertiesService.getUserProperties().deleteAllProperties();
  CacheService.getUserCache().removeAll(['session', 'tries', 'lockout']);
}

/* ---------------- data ---------------- */

function ss_() { return SpreadsheetApp.openById(SHEET_ID); }
function iso_(d, tz) { return d instanceof Date ? Utilities.formatDate(d, tz, 'yyyy-MM-dd') : ''; }
function num_(v) { const n = Number(v); return isNaN(n) ? 0 : n; }

function lists_() {
  const ss = ss_(), tz = ss.getSpreadsheetTimeZone(), setup = ss.getSheetByName('Setup');
  const currencies = setup.getRange('A4:B8').getValues().filter(r => r[0]).map(r => ({ code: String(r[0]), rate: num_(r[1]) || 1 }));
  const types = setup.getRange('D4:D8').getValues().map(r => String(r[0])).filter(String);
  const subcategories = setup.getRange('G4:H80').getValues().filter(r => r[0]).map(r => ({ name: String(r[0]), cat: String(r[1]) }));
  const months = setup.getRange('L4:L15').getValues().map(r => r[0]).filter(v => v instanceof Date).map(d => iso_(d, tz));
  const accounts = ss.getSheetByName('Accounts').getRange('A5:D18').getValues().filter(r => r[0])
    .map(r => ({ name: String(r[0]), currency: String(r[2] || 'AED'), kind: 'account', bucket: String(r[3]) }));
  const cards = ss.getSheetByName('Cards & Loans').getRange('A5:A12').getValues().filter(r => r[0])
    .map(r => ({ name: String(r[0]), currency: 'AED', kind: 'card', bucket: 'Card' }));
  return {
    currencies, types, subcategories, months,
    accounts: accounts.concat(cards).concat([{ name: 'Other', currency: 'AED', kind: 'other', bucket: '' }]),
    today: Utilities.formatDate(new Date(), tz, 'yyyy-MM-dd')
  };
}

function getLists(token) {
  const user = guard_(token);
  const l = lists_();
  l.user = user.name;
  return l;
}

function readTx_(ss) {
  const tz = ss.getSpreadsheetTimeZone();
  const vals = ss.getSheetByName('Transactions').getRange(TX_FIRST_ROW, TX_FIRST_COL, TX_LAST_ROW - TX_FIRST_ROW + 1, 14).getValues();
  const out = [];
  vals.forEach((r, i) => {
    if (!r[0]) return;
    out.push({
      row: TX_FIRST_ROW + i, date: iso_(r[0], tz), type: String(r[1]), sub: String(r[2]),
      from: String(r[3]), to: String(r[4]), amount: num_(r[5]), currency: String(r[6]),
      received: r[7] === '' ? '' : num_(r[7]), notes: String(r[8]), cat: String(r[9]),
      month: iso_(r[10], tz), aed: num_(r[12]), by: String(r[13] || '')
    });
  });
  return out;
}

function summary_(monthIso) {
  const ss = ss_(), tz = ss.getSpreadsheetTimeZone(), dash = ss.getSheetByName('Dashboard');
  if (monthIso) {
    const p = monthIso.split('-').map(Number), target = new Date(p[0], p[1] - 1, 1);
    const current = dash.getRange('C2').getValue();
    if (!(current instanceof Date) || iso_(current, tz) !== iso_(target, tz)) { dash.getRange('C2').setValue(target); SpreadsheetApp.flush(); }
  }
  const k = dash.getRange('B5:M10').getValues();
  const kpi = {
    spendableIncome: num_(k[0][0]), budgetUsed: num_(k[0][2]), budgetLeft: num_(k[0][4]),
    saved: num_(k[0][6]), extraIncome: num_(k[0][8]), cardDues: num_(k[0][10]),
    cashNow: num_(k[4][0]), cashLeft: num_(k[4][2]), oneOff: num_(k[4][4]),
    plannedSurplus: num_(k[4][6]), netWorth: num_(k[4][8])
  };
  const budget = ss.getSheetByName('Budget');
  kpi.incomePlan = num_(budget.getRange('S9').getValue());
  kpi.spendPlan = num_(budget.getRange('S50').getValue());
  // cash forecast steps, same formulas as the Monthly Report tab
  const rep = ss.getSheetByName(REPORT_SHEET).getRange('C74:C77').getValues();
  kpi.forecast = { cashNow: num_(rep[0][0]), budgetLeft: num_(rep[1][0]), cardDues: num_(rep[2][0]), cashLeft: num_(rep[3][0]) };

  const categories = dash.getRange('B14:F19').getValues().filter(r => r[0])
    .map(r => ({ name: String(r[0]), budget: num_(r[1]), actual: num_(r[2]), left: num_(r[3]), pct: num_(r[4]) }));
  const cards = dash.getRange('I14:M21').getValues().filter(r => r[0])
    .map(r => ({ name: String(r[0]), available: num_(r[1]), due: num_(r[2]), emi: num_(r[3]), status: String(r[4]) }));
  const lines = budget.getRange('A12:V49').getValues().filter(r => r[1])
    .map(r => ({ group: String(r[0]), name: String(r[1]), budget: num_(r[18]), actual: num_(r[19]), left: num_(r[20]), pct: num_(r[21]) }));
  const accounts = ss.getSheetByName('Accounts').getRange('A5:J18').getValues().filter(r => r[0])
    .map(r => ({ name: String(r[0]), currency: String(r[2]), bucket: String(r[3]), balance: num_(r[7]), aed: num_(r[9]) }));

  const monthKey = iso_(dash.getRange('C2').getValue(), tz);
  const all = readTx_(ss);
  kpi.extraSaved = all.filter(r => r.month === monthKey && r.sub === 'Extra Savings').reduce((s, r) => s + r.aed, 0);
  return {
    month: monthKey, kpi, categories, cards, lines, accounts,
    monthTx: all.filter(r => r.month === monthKey),
    recent: all.sort((a, b) => (b.date > a.date ? 1 : b.date < a.date ? -1 : b.row - a.row)).slice(0, 40)
  };
}

function getSummary(token, monthIso) { guard_(token); return summary_(monthIso); }

function validate_(e) {
  const L = lists_();
  const subs = L.subcategories.map(x => x.name), accts = L.accounts.map(x => x.name), curs = L.currencies.map(x => x.code);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.date || '')) throw new Error('Pick a date.');
  if (L.types.indexOf(e.type) < 0) throw new Error('Pick a type.');
  if (subs.indexOf(e.sub) < 0) throw new Error('Pick a subcategory.');
  if (accts.indexOf(e.from) < 0) throw new Error('Pick where the money came from.');
  if (accts.indexOf(e.to) < 0) throw new Error('Pick where the money went.');
  if (e.from === e.to && e.from !== 'Other') throw new Error('Paid from and Paid to are the same.');
  const amount = Number(e.amount);
  if (!(amount > 0) || amount > 10000000) throw new Error('Enter an amount above zero.');
  if (curs.indexOf(e.currency) < 0) throw new Error('Pick a currency.');
  const received = e.received === '' || e.received == null ? '' : Number(e.received);
  if (received !== '' && !(received > 0)) throw new Error('Received amount must be above zero.');
  const p = e.date.split('-').map(Number);
  return [new Date(p[0], p[1] - 1, p[2]), e.type, e.sub, e.from, e.to, amount, e.currency, received, String(e.notes || '').slice(0, 200)];
}

function addEntry(token, e, monthIso) {
  const user = guard_(token);
  const values = validate_(e);
  const lockSvc = LockService.getScriptLock();
  lockSvc.waitLock(20000);
  try {
    const sh = ss_().getSheetByName('Transactions');
    const colB = sh.getRange(TX_FIRST_ROW, TX_FIRST_COL, TX_LAST_ROW - TX_FIRST_ROW + 1, 1).getValues();
    const idx = colB.findIndex(r => r[0] === '' || r[0] === null);
    if (idx < 0) throw new Error('Transactions is full. Add more rows to the sheet.');
    const row = TX_FIRST_ROW + idx;
    sh.getRange(row, TX_FIRST_COL, 1, 9).setValues([values]);
    sh.getRange(row, TX_ADDED_BY_COL).setValue(user.name);
    SpreadsheetApp.flush();
  } finally { lockSvc.releaseLock(); }
  return summary_(monthIso);
}

/** Edit an existing entry. `expect` must still match the row, so a changed sheet is never overwritten. */
function updateEntry(token, row, expect, e, monthIso) {
  const user = guard_(token);
  row = Number(row);
  if (!(row >= TX_FIRST_ROW && row <= TX_LAST_ROW)) throw new Error('Invalid row.');
  const values = validate_(e);
  const lockSvc = LockService.getScriptLock();
  lockSvc.waitLock(20000);
  try {
    const sh = ss_().getSheetByName('Transactions');
    const r = sh.getRange(row, TX_FIRST_COL, 1, 9).getValues()[0];
    if ([String(r[1]), String(r[2]), num_(r[5])].join('|') !== expect) throw new Error('This entry changed in the sheet. Refresh and try again.');
    sh.getRange(row, TX_FIRST_COL, 1, 9).setValues([values]);
    const by = String(sh.getRange(row, TX_ADDED_BY_COL).getValue() || '');
    if (by.indexOf(user.name) < 0) sh.getRange(row, TX_ADDED_BY_COL).setValue(by ? by + ' · edited by ' + user.name : user.name);
    SpreadsheetApp.flush();
  } finally { lockSvc.releaseLock(); }
  return summary_(monthIso);
}

function deleteEntry(token, row, expect, monthIso) {
  guard_(token);
  row = Number(row);
  if (!(row >= TX_FIRST_ROW && row <= TX_LAST_ROW)) throw new Error('Invalid row.');
  const lockSvc = LockService.getScriptLock();
  lockSvc.waitLock(20000);
  try {
    const sh = ss_().getSheetByName('Transactions');
    const r = sh.getRange(row, TX_FIRST_COL, 1, 9).getValues()[0];
    if ([String(r[1]), String(r[2]), num_(r[5])].join('|') !== expect) throw new Error('This entry changed in the sheet. Refresh and try again.');
    sh.getRange(row, TX_FIRST_COL, 1, 9).clearContent();
    sh.getRange(row, TX_ADDED_BY_COL).clearContent();
    SpreadsheetApp.flush();
  } finally { lockSvc.releaseLock(); }
  return summary_(monthIso);
}

/* ---------------- reports, planning sheet, monthly email ---------------- */

function monthLabel_(iso) { const p = iso.split('-').map(Number); return Utilities.formatDate(new Date(p[0], p[1] - 1, 1), ss_().getSpreadsheetTimeZone(), 'MMMM yyyy'); }
function shiftMonth_(iso, n) { const p = iso.split('-').map(Number), d = new Date(p[0], p[1] - 1 + n, 1); return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-01'; }
function isSpend_(r) { return (r.type === 'Expense' || r.type === 'Transfer') && ['Income', 'Extra Income', 'Transfers'].indexOf(r.cat) < 0; }

/** Month vs last month figures, plus a 6-month spending trend. */
function compare_(all, monthKey) {
  const prevKey = shiftMonth_(monthKey, -1);
  const pick = k => {
    const tx = all.filter(r => r.month === k), cats = {}, subs = {};
    let spent = 0, income = 0, extra = 0, oneOff = 0, saved = 0;
    tx.forEach(r => {
      if (isSpend_(r)) { spent += r.aed; cats[r.cat] = (cats[r.cat] || 0) + r.aed; subs[r.sub] = (subs[r.sub] || 0) + r.aed; if (r.cat === 'Savings & Investments') saved += r.aed; }
      if (r.type === 'Income') income += r.aed;
      if (r.type === 'One-Off Income') extra += r.aed;
      if (r.type === 'One-Off Expense') oneOff += r.aed;
    });
    return { key: k, count: tx.length, spent, income, extra, oneOff, saved, cats, subs };
  };
  const trend = [];
  for (let i = 5; i >= 0; i--) { const t = pick(shiftMonth_(monthKey, -i)); trend.push({ key: t.key, label: monthLabel_(t.key).slice(0, 3), spent: t.spent, income: t.income, has: t.count > 0 }); }
  return { cur: pick(monthKey), prev: pick(prevKey), prevLabel: monthLabel_(prevKey), trend };
}

function saveToDrive_(blob, name) {
  const folders = DriveApp.getFoldersByName(REPORT_FOLDER);
  const folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(REPORT_FOLDER);
  const file = folder.createFile(blob.setName(name));
  const id = file.getId();
  return { url: file.getUrl(), name: file.getName(), id: id, download: 'https://drive.google.com/uc?export=download&id=' + id };
}
function pdfFromHtml_(html) { return HtmlService.createHtmlOutput(html).getBlob().getAs('application/pdf'); }
function stamp_() { return Utilities.formatDate(new Date(), ss_().getSpreadsheetTimeZone(), 'd MMM yyyy, HH:mm'); }
function fileStamp_() { return Utilities.formatDate(new Date(), ss_().getSpreadsheetTimeZone(), 'd MMM HH-mm'); }

function buildReport_(monthIso, byName) {
  const ss = ss_();
  const S = summary_(monthIso);             // sets the month and recalculates
  S.compare = compare_(readTx_(ss), S.month);
  const label = monthLabel_(S.month);
  let blob;
  try {
    blob = pdfFromHtml_(reportHtml_(S, { label, stamp: stamp_(), by: byName }));
  } catch (e) {
    // fallback: export the Monthly Report tab as it looks in the sheet
    const gid = ss.getSheetByName(REPORT_SHEET).getSheetId();
    const url = 'https://docs.google.com/spreadsheets/d/' + SHEET_ID + '/export?format=pdf&gid=' + gid +
      '&size=A4&portrait=true&fitw=true&gridlines=false&printtitle=false&sheetnames=false&pagenum=CENTER' +
      '&top_margin=0.5&bottom_margin=0.5&left_margin=0.5&right_margin=0.5&horizontal_alignment=CENTER';
    const res = UrlFetchApp.fetch(url, { headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() }, muteHttpExceptions: true });
    if (res.getResponseCode() !== 200) throw new Error('Could not create the PDF (code ' + res.getResponseCode() + ').');
    blob = res.getBlob();
  }
  return { blob, label, S };
}

/** Saves an A4 report for the chosen month in Drive > Finance Reports and returns download links. */
function makeReport(token, monthIso) {
  const user = guard_(token);
  const r = buildReport_(monthIso, user.name);
  return saveToDrive_(r.blob, 'Finance Report - ' + r.label + ' (' + fileStamp_() + ').pdf');
}

/** Figures for the printable planning sheet. */
function planData_(monthIso) {
  const ss = ss_();
  const S = summary_(monthIso);
  const budget = ss.getSheetByName('Budget');
  const income = budget.getRange('A6:S8').getValues().filter(r => r[1]).map(r => ({ name: String(r[1]), plan: num_(r[18]) }));
  const cmp = compare_(readTx_(ss), S.month);
  const groups = [];
  budget.getRange('A12:S49').getValues().filter(r => r[1]).forEach(r => {
    let g = groups.find(x => x.name === String(r[0]));
    if (!g) { g = { name: String(r[0]), lines: [] }; groups.push(g); }
    g.lines.push({ name: String(r[1]), cur: String(r[2] || 'AED'), native: num_(r[17]), plan: num_(r[18]), last: cmp.prev.subs[String(r[1])] || 0 });
  });
  return { month: S.month, label: monthLabel_(S.month), prevLabel: cmp.prevLabel, hasPrev: cmp.prev.count > 0, income, groups,
    cashNow: S.kpi.cashNow, cardDues: S.kpi.cardDues, incomePlan: S.kpi.incomePlan, spendPlan: S.kpi.spendPlan };
}
function buildPlan_(monthIso) {
  const P = planData_(monthIso);
  return { blob: pdfFromHtml_(planHtml_(P, { stamp: stamp_() })), label: P.label };
}
/** Printable planning sheet for the chosen month (to fill in together on the 1st). */
function makePlan(token, monthIso) {
  guard_(token);
  const r = buildPlan_(monthIso);
  return saveToDrive_(r.blob, 'Monthly Plan - ' + r.label + ' (' + fileStamp_() + ').pdf');
}

/* ---- email on the 1st ---- */
function recipients_() { return Object.keys(ALLOWED).filter(e => /@/.test(e) && !/PRIYA_GMAIL_HERE/i.test(e)); }

/** Runs on the 1st of every month (installed from Settings > Email on the 1st). */
function sendMonthlyEmail() {
  const ss = ss_(), tz = ss.getSpreadsheetTimeZone();
  const today = Utilities.formatDate(new Date(), tz, 'yyyy-MM') + '-01', prev = shiftMonth_(today, -1);
  const months = lists_().months;
  const files = [], attachments = [];
  let summaryHtml = '';
  if (months.indexOf(prev) >= 0) {
    const r = buildReport_(prev, 'monthly email');
    attachments.push(r.blob.copyBlob().setName('Finance Report - ' + r.label + '.pdf'));
    files.push(saveToDrive_(r.blob, 'Finance Report - ' + r.label + ' (' + fileStamp_() + ').pdf'));
    const k = r.S.kpi, f = k.forecast;
    const row = (a, b, c) => `<tr><td style="padding:6px 0;color:#5F6678">${a}</td><td style="padding:6px 0;text-align:right;font-weight:bold;color:${c || '#14213D'}">AED ${b}</td></tr>`;
    summaryHtml = `<h3 style="margin:22px 0 6px;color:#14213D">${r.label} at a glance</h3><table style="width:100%;max-width:420px;border-collapse:collapse;font-size:14px">
      ${row('Salary received', rf_(k.spendableIncome))}${row('Spent of plan', rf_(k.budgetUsed) + ' / ' + rf_(k.spendPlan))}
      ${row('Saved', rf_(k.saved), '#1E8A63')}${row('Extra income', rf_(k.extraIncome))}${row('Card dues now', rf_(k.cardDues, 2), '#C2412F')}</table>`;
  }
  if (months.indexOf(today) >= 0) {
    const pl = buildPlan_(today);
    attachments.push(pl.blob.copyBlob().setName('Monthly Plan - ' + pl.label + '.pdf'));
    files.push(saveToDrive_(pl.blob, 'Monthly Plan - ' + pl.label + ' (' + fileStamp_() + ').pdf'));
    summary_(today);                         // leave the Dashboard on the new month
  }
  if (!attachments.length) return;
  const appUrl = ScriptApp.getService().getUrl() || '';
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;color:#14213D;max-width:560px">
    <div style="background:#14213D;color:#ffffff;padding:18px 20px"><div style="font-size:11px;letter-spacing:3px;color:#D4B06A">SHARMA FINANCE</div>
    <div style="font-size:22px;margin-top:4px">New month, new plan</div><div style="color:#C9CEDA;font-size:13px">${monthLabel_(today)}</div></div>
    <div style="padding:16px 20px;border:1px solid #E4E0D6;border-top:0">
    <p>Good morning! It's the 1st, time to sit together for ten minutes.</p>
    <ol style="padding-left:18px;line-height:1.7"><li>Look at last month's report (attached).</li><li>Print the planning sheet (attached) and write your estimates.</li><li>Update the plan in the sheet, then start logging in the app.</li></ol>
    ${summaryHtml}
    ${appUrl ? `<p style="margin-top:22px"><a href="${appUrl}" style="background:#A8823F;color:#ffffff;padding:11px 18px;text-decoration:none;border-radius:8px">Open Sharma Finance</a></p>` : ''}
    <p style="font-size:11px;color:#9AA0AE;margin-top:24px">Private family email, sent automatically on the 1st. Copies are in Drive › ${REPORT_FOLDER}.</p></div></div>`;
  MailApp.sendEmail({ to: recipients_().join(','), subject: 'Sharma Finance · ' + monthLabel_(today) + ' plan and last month\'s report', htmlBody: html, attachments: attachments, name: 'Sharma Finance' });
}

function getEmailState(token) {
  const user = guard_(token);
  const by = PropertiesService.getScriptProperties().getProperty('monthlyEmailBy') || '';
  const mine = ScriptApp.getProjectTriggers().some(t => t.getHandlerFunction() === 'sendMonthlyEmail');
  return { on: !!by, by: by, mine: mine || by === user.name, to: recipients_().map(e => ALLOWED[e] || e) };
}
function setMonthlyEmail(token, on) {
  const user = guard_(token);
  const props = PropertiesService.getScriptProperties(), by = props.getProperty('monthlyEmailBy');
  if (by && by !== user.name) throw new Error('Monthly email is managed by ' + by + '.');
  ScriptApp.getProjectTriggers().filter(t => t.getHandlerFunction() === 'sendMonthlyEmail').forEach(t => ScriptApp.deleteTrigger(t));
  if (on) {
    ScriptApp.newTrigger('sendMonthlyEmail').timeBased().onMonthDay(1).atHour(8).inTimezone(ss_().getSpreadsheetTimeZone()).create();
    props.setProperty('monthlyEmailBy', user.name);
  } else props.deleteProperty('monthlyEmailBy');
  return getEmailState(token);
}
function sendTestEmail(token) { guard_(token); sendMonthlyEmail(); return recipients_().map(e => ALLOWED[e] || e); }

/* ---------------- PDF report (HTML → PDF) ----------------
   Built with tables and coloured cells only, which Google's PDF converter prints reliably. */
const RPT = { ink: '#14213D', muted: '#5F6678', faint: '#9AA0AE', line: '#E4E0D6', gold: '#A8823F', goldSoft: '#F4ECDC', blue: '#1F4FBF', blueSoft: '#E6ECFA',
  good: '#1E8A63', bad: '#C2412F', badSoft: '#FBE9E6', paper: '#FFFFFF', band: '#14213D', track: '#EEEBE4',
  cat: { 'Home Expenses': '#B8892E', 'Daily Expenses': '#3987E5', 'Loans & EMI': '#D95926', 'Savings & Investments': '#199E70', 'India Remittance': '#9085E9', 'Other': '#D55181' } };
function rf_(n, d) { n = Number(n) || 0; const s = Math.abs(n).toFixed(d || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ','); return (n < 0 ? '−' : '') + s; }
function re_(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function rbar_(parts, h) {   // parts: [[pct, colour], ...] ; remainder is track
  h = h || 10; let used = 0, cells = '';
  parts.forEach(p => { const w = Math.max(0, Math.min(100 - used, p[0])); if (w > 0.3) { cells += `<td style="width:${w.toFixed(2)}%;background:${p[1]};height:${h}px;padding:0"></td>`; used += w; } });
  if (100 - used > 0.3) cells += `<td style="width:${(100 - used).toFixed(2)}%;background:${RPT.track};height:${h}px;padding:0"></td>`;
  return `<table style="width:100%;border-collapse:collapse;table-layout:fixed"><tr>${cells}</tr></table>`;
}
function rsec_(no, title, right) {
  return `<table style="width:100%;margin:22px 0 8px;border-collapse:collapse"><tr><td style="font-size:9px;letter-spacing:2px;color:${RPT.gold};font-weight:bold;width:24px;vertical-align:bottom">${no}</td>
    <td style="font-size:14px;font-weight:bold;color:${RPT.ink};vertical-align:bottom">${title}</td><td style="text-align:right;font-size:10px;color:${RPT.muted};vertical-align:bottom">${right || ''}</td></tr></table>
    <div style="height:2px;background:${RPT.gold};width:40px;margin:0 0 10px 24px"></div>`;
}
function rkpi_(label, value, sub, colour) {
  return `<td style="width:25%;padding:0 4px"><div style="border:1px solid ${RPT.line};border-top:3px solid ${colour || RPT.gold};padding:10px 12px;background:#FFFFFF">
    <div style="font-size:8px;letter-spacing:1.5px;color:${RPT.muted};text-transform:uppercase">${label}</div>
    <div style="font-size:17px;color:${RPT.ink};margin-top:5px"><span style="font-size:8px;color:${RPT.gold};font-weight:bold">AED </span>${value}</div>
    <div style="font-size:8.5px;color:${RPT.faint};margin-top:3px">${sub}</div></div></td>`;
}

function reportHtml_(S, meta) {
  const k = S.kpi, f = k.forecast || { cashNow: k.cashNow, budgetLeft: 0, cardDues: -k.cardDues, cashLeft: k.cashLeft };
  const spend = Math.max(-f.budgetLeft, 0), dues = Math.max(-f.cardDues, 0), need = spend + dues, have = Math.max(f.cashNow, 0);
  const tot = Math.max(need, have) || 1, short = f.cashLeft < 0, pc = v => v / tot * 100;
  const th = s => `<th style="text-align:${s[1] || 'left'};font-size:8px;letter-spacing:1.2px;color:${RPT.muted};font-weight:normal;text-transform:uppercase;padding:6px 6px;border-bottom:1px solid ${RPT.ink}">${s[0]}</th>`;
  const td = (v, al, extra) => `<td style="text-align:${al || 'left'};padding:6px 6px;border-bottom:1px solid ${RPT.line};font-size:10px;color:${RPT.ink};${extra || ''}">${v}</td>`;
  const pctUsed = k.spendPlan ? k.budgetUsed / k.spendPlan : 0;

  // 1. header band + KPIs
  let h = `<div style="background:${RPT.band};color:#FFFFFF;padding:18px 22px">
    <table style="width:100%;border-collapse:collapse"><tr>
      <td><div style="font-size:9px;letter-spacing:3px;color:#D4B06A">SHARMA FAMILY · PRIVATE</div>
        <div style="font-size:24px;margin-top:4px;color:#FFFFFF">Monthly Finance Report</div>
        <div style="font-size:12px;color:#C9CEDA;margin-top:2px">${re_(meta.label)}</div></td>
      <td style="text-align:right;vertical-align:top;font-size:9px;color:#C9CEDA">Prepared ${re_(meta.stamp)}<br>by ${re_(meta.by)}<br><span style="color:#D4B06A">All amounts in AED</span></td>
    </tr></table></div>
  <table style="width:100%;border-collapse:collapse;margin-top:14px"><tr>
    ${rkpi_('Spendable income', rf_(k.spendableIncome), 'Plan ' + rf_(k.incomePlan), RPT.blue)}
    ${rkpi_('Budget used', rf_(k.budgetUsed), Math.round(pctUsed * 100) + '% of ' + rf_(k.spendPlan) + ' plan', RPT.gold)}
    ${rkpi_('Card dues', rf_(k.cardDues, 2), S.cards.filter(c => c.due > 0).length + ' cards to pay', '#D95926')}
    ${rkpi_(short ? 'Short at month end' : 'Cash left at month end', `<span style="color:${short ? RPT.bad : RPT.good}">${rf_(Math.abs(f.cashLeft))}</span>`, 'Cash now − still to spend − card dues', short ? RPT.bad : RPT.good)}
  </tr></table>`;

  // 2. cash forecast (have vs need)
  h += rsec_('01', 'Cash forecast', 'Have vs need for the rest of the month');
  h += `<table style="width:100%;border-collapse:collapse">
    <tr><td style="width:60px;font-size:10px;color:${RPT.muted};padding:5px 0">Have</td><td style="padding:5px 8px">${rbar_([[pc(have), RPT.blue]].concat(short ? [[pc(-f.cashLeft), RPT.bad]] : []), 16)}</td><td style="width:80px;text-align:right;font-size:11px">${rf_(have)}</td></tr>
    <tr><td style="font-size:10px;color:${RPT.muted};padding:5px 0">Need</td><td style="padding:5px 8px">${rbar_([[pc(spend), RPT.gold], [pc(dues), '#D95926']].concat(!short && f.cashLeft > 0 ? [[pc(f.cashLeft), RPT.good]] : []), 16)}</td><td style="text-align:right;font-size:11px">${rf_(need)}</td></tr></table>
  <table style="width:100%;border-collapse:collapse;margin-top:8px;font-size:9.5px;color:${RPT.muted}"><tr>
    <td><span style="background:${RPT.blue}">&nbsp;&nbsp;&nbsp;</span> Cash now ${rf_(have)}</td><td><span style="background:${RPT.gold}">&nbsp;&nbsp;&nbsp;</span> Still to spend ${rf_(spend)}</td>
    <td><span style="background:#D95926">&nbsp;&nbsp;&nbsp;</span> Card dues ${rf_(dues)}</td><td style="text-align:right"><span style="background:${short ? RPT.bad : RPT.good}">&nbsp;&nbsp;&nbsp;</span> <b style="color:${short ? RPT.bad : RPT.good}">${short ? 'Short by ' : 'Spare '}${rf_(Math.abs(f.cashLeft))}</b></td></tr></table>
  <div style="margin-top:8px;padding:8px 10px;background:${short ? RPT.badSoft : '#E7F4EE'};font-size:10px;color:${RPT.ink}">${short ? `<b>Action:</b> move AED ${rf_(-f.cashLeft)} from savings, or push a payment to next month.` : 'Cash covers everything planned this month.'}</div>`;

  // 3. budget by category with bars
  const cats = S.categories.filter(c => c.budget || c.actual), cmax = Math.max.apply(null, cats.map(c => Math.max(c.budget, c.actual)).concat([1]));
  h += rsec_('02', 'Budget: plan vs spent', `Used ${rf_(k.budgetUsed)} of ${rf_(k.spendPlan)} · planned surplus ${rf_(k.plannedSurplus)}`);
  h += `<table style="width:100%;border-collapse:collapse"><tr>${[['Category'], ['Plan vs spent'], ['Plan', 'right'], ['Spent', 'right'], ['Left', 'right'], ['Used', 'right']].map(th).join('')}</tr>` +
    cats.map(c => { const col = RPT.cat[c.name] || RPT.gold, over = c.actual > c.budget;
      return `<tr>${td(`<span style="background:${col}">&nbsp;&nbsp;</span>&nbsp; ${re_(c.name)}`)}<td style="padding:6px;border-bottom:1px solid ${RPT.line};width:34%">${rbar_([[c.budget / cmax * 100, '#D9D4C8']], 5)}<div style="height:2px"></div>${rbar_([[c.actual / cmax * 100, over ? RPT.bad : col]], 7)}</td>
        ${td(rf_(c.budget), 'right')}${td(rf_(c.actual), 'right')}${td(rf_(c.left), 'right', c.left < 0 ? 'color:' + RPT.bad : '')}${td(Math.round(c.budget ? c.actual / c.budget * 100 : 0) + '%', 'right', over ? 'color:' + RPT.bad + ';font-weight:bold' : '')}</tr>`; }).join('') +
    `<tr>${td('<b>Total</b>')}${td('')}${td('<b>' + rf_(k.spendPlan) + '</b>', 'right')}${td('<b>' + rf_(k.budgetUsed) + '</b>', 'right')}${td('<b>' + rf_(k.budgetLeft) + '</b>', 'right')}${td('<b>' + Math.round(pctUsed * 100) + '%</b>', 'right')}</tr></table>
    <div style="font-size:8.5px;color:${RPT.faint};margin-top:4px">Light bar = plan, coloured bar = spent (red when over plan).</div>`;

  // 3. month vs last month
  const C = S.compare;
  if (C) {
    h += rsec_('03', 'Month vs last month', re_(meta.label) + ' compared with ' + re_(C.prevLabel));
    const kp = [['Salary in', 'income', false], ['Spent (budget)', 'spent', true], ['Saved', 'saved', false], ['One-off spend', 'oneOff', true]];
    const chg = (cur, prev, badUp) => { if (!prev) return `<span style="color:${RPT.faint}">new</span>`; const d = (cur - prev) / prev * 100, up = d >= 0, bad = badUp ? up : !up;
      return `<span style="color:${Math.abs(d) < 0.5 ? RPT.muted : bad ? RPT.bad : RPT.good}">${up ? '▲' : '▼'} ${Math.abs(d).toFixed(0)}%</span>`; };
    if (!C.prev.count) {
      h += `<div style="padding:9px 11px;background:${RPT.goldSoft};font-size:10px;color:${RPT.ink}">This is the first month of tracking, so there is nothing to compare yet. From next month this section shows what went up or down, category by category.</div>`;
    } else {
      h += `<table style="width:100%;border-collapse:collapse"><tr>${kp.map(x => `<td style="width:25%;padding:0 4px"><div style="border:1px solid ${RPT.line};padding:8px 10px">
        <div style="font-size:8px;letter-spacing:1.4px;color:${RPT.muted};text-transform:uppercase">${x[0]}</div>
        <div style="font-size:14px;margin-top:4px">${rf_(C.cur[x[1]])} <span style="font-size:9px">${chg(C.cur[x[1]], C.prev[x[1]], x[2])}</span></div>
        <div style="font-size:8.5px;color:${RPT.faint}">last month ${rf_(C.prev[x[1]])}</div></div></td>`).join('')}</tr></table>`;
      const names = Object.keys(RPT.cat).filter(n => C.cur.cats[n] || C.prev.cats[n]);
      const mx = Math.max.apply(null, names.map(n => Math.max(C.cur.cats[n] || 0, C.prev.cats[n] || 0)).concat([1]));
      h += `<table style="width:100%;border-collapse:collapse;margin-top:10px"><tr>${[['Category'], ['Last month vs this month'], [re_(C.prevLabel.slice(0, 3)), 'right'], [re_(meta.label.slice(0, 3)), 'right'], ['Change', 'right']].map(th).join('')}</tr>` +
        names.map(n => { const a = C.prev.cats[n] || 0, b = C.cur.cats[n] || 0, col = RPT.cat[n];
          return `<tr>${td(`<span style="background:${col}">&nbsp;&nbsp;</span>&nbsp; ${re_(n)}`)}<td style="padding:6px;border-bottom:1px solid ${RPT.line};width:34%">${rbar_([[a / mx * 100, '#CFC9BC']], 5)}<div style="height:2px"></div>${rbar_([[b / mx * 100, col]], 7)}</td>${td(rf_(a), 'right')}${td(rf_(b), 'right')}${td(chg(b, a, true), 'right')}</tr>`; }).join('') + `</table>`;
      const moves = Object.keys(Object.assign({}, C.cur.subs, C.prev.subs)).map(n => ({ n, d: (C.cur.subs[n] || 0) - (C.prev.subs[n] || 0), a: C.prev.subs[n] || 0 }))
        .filter(m => Math.abs(m.d) >= 50).sort((x, y) => Math.abs(y.d) - Math.abs(x.d)).slice(0, 4);
      if (moves.length) h += `<div style="margin-top:8px;padding:8px 11px;background:${RPT.blueSoft};font-size:10px;line-height:1.6"><b>Biggest changes:</b> ` +
        moves.map(m => `${re_(m.n)} ${m.d > 0 ? 'up' : 'down'} AED ${rf_(Math.abs(m.d))}${m.a ? ' (' + (m.d > 0 ? '+' : '−') + Math.abs(m.d / m.a * 100).toFixed(0) + '%)' : ''}`).join(' · ') + `</div>`;
    }
    // 6-month trend (vertical bars)
    const tmax = Math.max.apply(null, C.trend.map(t => Math.max(t.spent, t.income)).concat([1]));
    h += `<div style="font-size:8px;letter-spacing:1.4px;color:${RPT.muted};text-transform:uppercase;margin:12px 0 4px">Last 6 months · salary in vs budget spending</div>
      <table style="width:100%;border-collapse:collapse;table-layout:fixed"><tr>${C.trend.map(t => `<td style="vertical-align:bottom;height:80px;padding:0 6px;border-bottom:1px solid ${RPT.ink}">
        <table style="width:100%;border-collapse:collapse"><tr><td style="vertical-align:bottom;padding:0 1px"><div style="height:${Math.round(t.income / tmax * 72)}px;background:${RPT.blue}"></div></td>
        <td style="vertical-align:bottom;padding:0 1px"><div style="height:${Math.round(t.spent / tmax * 72)}px;background:${RPT.gold}"></div></td></tr></table></td>`).join('')}</tr>
      <tr>${C.trend.map(t => `<td style="text-align:center;font-size:8.5px;color:${t.has ? RPT.ink : RPT.faint};padding-top:3px">${t.label}${t.has ? '<br><span style="color:' + RPT.muted + '">' + rf_(t.spent) + '</span>' : ''}</td>`).join('')}</tr></table>
      <div style="font-size:8.5px;color:${RPT.faint};margin-top:3px"><span style="background:${RPT.blue}">&nbsp;&nbsp;&nbsp;</span> salary in &nbsp; <span style="background:${RPT.gold}">&nbsp;&nbsp;&nbsp;</span> budget spending</div>`;
  }

  // 4. still to pay this month (budget lines with money left)
  const left = S.lines.filter(l => l.left > 0 && l.name !== 'Credit Card EMI').sort((a, b) => b.left - a.left);
  if (left.length) {
    h += rsec_('04', 'Still to pay this month', 'Budget lines with money not yet used');
    const half = Math.ceil(left.length / 2), col = arr => `<table style="width:100%;border-collapse:collapse">${arr.map(l => `<tr>${td(re_(l.name))}${td(rf_(l.left), 'right')}</tr>`).join('')}</table>`;
    h += `<table style="width:100%;border-collapse:collapse"><tr><td style="width:48%;vertical-align:top;padding:0">${col(left.slice(0, half))}</td><td style="width:4%"></td><td style="width:48%;vertical-align:top;padding:0">${col(left.slice(half))}</td></tr></table>
      <div style="font-size:8.5px;color:${RPT.faint};margin-top:4px">Credit Card EMI is left out because the card dues below already include it.</div>`;
  }

  // 5. credit cards
  const due = S.cards.filter(c => c.due > 0).sort((a, b) => b.due - a.due), clear = S.cards.filter(c => c.due <= 0);
  h += `<div style="page-break-before:always"></div>` + rsec_('05', 'Credit cards to pay', 'Total ' + rf_(k.cardDues, 2));
  h += `<table style="width:100%;border-collapse:collapse"><tr>${[['Card'], ['Share of dues'], ['Due', 'right'], ['EMI', 'right'], ['Available', 'right'], ['Paid', 'center']].map(th).join('')}</tr>` +
    due.map(c => `<tr>${td(re_(c.name))}<td style="padding:6px;border-bottom:1px solid ${RPT.line};width:28%">${rbar_([[c.due / (k.cardDues || 1) * 100, '#D95926']], 7)}</td>${td('<b>' + rf_(c.due, 2) + '</b>', 'right')}${td(c.emi ? rf_(c.emi) : '–', 'right')}${td(rf_(c.available), 'right')}${td('<span style="display:inline-block;width:11px;height:11px;border:1px solid ' + RPT.muted + '"></span>', 'center')}</tr>`).join('') +
    `</table><div style="font-size:9px;color:${RPT.muted};margin-top:5px">Clear: ${clear.map(c => re_(c.name.replace(' Credit Card', ''))).join(', ') || 'none'}</div>`;

  // 6. accounts
  const order = [['Spendable', 'Spendable', RPT.blue], ['Savings', 'Savings', RPT.good], ['Reserved', 'India & reserved', '#9085E9']];
  const accTot = S.accounts.reduce((s, a) => s + a.aed, 0) || 1;
  h += rsec_('06', 'Account balances', 'Total ' + rf_(accTot));
  h += rbar_(order.map(o => [S.accounts.filter(a => a.bucket === o[0]).reduce((s, a) => s + a.aed, 0) / accTot * 100, o[2]]), 12);
  h += `<table style="width:100%;border-collapse:collapse;margin-top:6px"><tr>${[['Account'], ['Currency'], ['Balance', 'right'], ['AED', 'right']].map(th).join('')}</tr>` +
    order.map(o => { const list = S.accounts.filter(a => a.bucket === o[0]).sort((a, b) => b.aed - a.aed); if (!list.length) return '';
      const sub = list.reduce((s, a) => s + a.aed, 0);
      return `<tr><td colspan="3" style="padding:9px 6px 4px;font-size:8.5px;letter-spacing:1.5px;color:${o[2]};font-weight:bold;text-transform:uppercase">${o[1]}</td><td style="padding:9px 6px 4px;text-align:right;font-size:10px;font-weight:bold">${rf_(sub)}</td></tr>` +
        list.map(a => `<tr>${td('&nbsp;&nbsp;' + re_(a.name))}${td(re_(a.currency))}${td(rf_(a.balance, 2), 'right')}${td(rf_(a.aed), 'right')}</tr>`).join(''); }).join('') + `</table>`;

  // 7. net position
  h += rsec_('07', 'Net position', '');
  h += `<table style="width:100%;border-collapse:collapse"><tr>
    ${rkpi_('Spendable cash now', rf_(k.cashNow), 'Current accounts', RPT.blue)}${rkpi_('Extra income', rf_(k.extraIncome), 'Not spendable · ' + rf_(k.extraSaved) + ' to savings', RPT.gold)}
    ${rkpi_('Saved this month', rf_(k.saved), 'Regular saving lines', RPT.good)}${rkpi_('Net worth', rf_(k.netWorth), 'Excludes gold', RPT.ink)}</tr></table>`;

  // 8. transactions
  const tx = (S.monthTx || []).slice().sort((a, b) => a.date < b.date ? -1 : a.date > b.date ? 1 : a.row - b.row);
  h += rsec_('08', 'Transactions this month', tx.length + ' entries');
  h += tx.length ? `<table style="width:100%;border-collapse:collapse"><tr>${[['Date'], ['Type'], ['Subcategory'], ['From → To'], ['Amount', 'right'], ['By']].map(th).join('')}</tr>` +
    tx.map(r => { const inc = /Income/.test(r.type); return `<tr>${td(re_(r.date.slice(8, 10) + '/' + r.date.slice(5, 7)), 'left', 'font-size:9px')}${td(re_(r.type), 'left', 'font-size:9px;color:' + RPT.muted)}${td(re_(r.sub) + (r.notes ? `<div style="font-size:8px;color:${RPT.faint}">${re_(r.notes)}</div>` : ''))}${td(re_(r.from) + ' → ' + re_(r.to), 'left', 'font-size:8.5px;color:' + RPT.muted)}${td((inc ? '+' : '') + rf_(r.amount, 2) + ' <span style="font-size:7.5px;color:' + RPT.gold + '">' + re_(r.currency) + '</span>', 'right', inc ? 'color:' + RPT.good : '')}${td(re_(r.by || ''), 'left', 'font-size:9px;color:' + RPT.muted)}</tr>`; }).join('') + `</table>`
    : `<div style="font-size:10px;color:${RPT.muted}">No entries this month.</div>`;

  // 9. review & sign-off
  h += rsec_('09', 'Monthly review', 'Fill in together at the start of the month');
  const box = t => `<td style="width:50%;padding:0 4px;vertical-align:top"><div style="border:1px solid ${RPT.line};padding:8px 10px;height:62px"><div style="font-size:8px;letter-spacing:1.4px;color:${RPT.muted};text-transform:uppercase">${t}</div></div></td>`;
  h += `<table style="width:100%;border-collapse:collapse"><tr>${box('What went well')}${box('What to change next month')}</tr></table>
    <table style="width:100%;border-collapse:collapse;margin-top:8px"><tr>${box('Top-up / transfers decided')}${box('Big payments coming up')}</tr></table>
    <table style="width:100%;border-collapse:collapse;margin-top:18px;font-size:10px;color:${RPT.muted}"><tr>
      <td style="width:45%;border-top:1px solid ${RPT.ink};padding-top:4px">Shubham</td><td style="width:10%"></td><td style="width:45%;border-top:1px solid ${RPT.ink};padding-top:4px">Priya</td></tr></table>
    <div style="margin-top:18px;font-size:8px;color:${RPT.faint};text-align:center">Sharma Finance · generated from Shubham Finance Tracker 2.0 · private family document</div>`;

  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>@page{size:A4;margin:14mm 12mm}body{font-family:Roboto,Arial,Helvetica,sans-serif;color:${RPT.ink};margin:0}table{page-break-inside:auto}tr{page-break-inside:avoid}</style></head><body>${h}</body></html>`;
}

/* ---------------- printable planning sheet ---------------- */
function planHtml_(P, meta) {
  const rsec_ = (no, t, r) => rsecP_(no, t, r);
  const W = (w, t, al) => `<th style="width:${w};text-align:${al || 'left'};font-size:8px;letter-spacing:1.2px;color:${RPT.muted};font-weight:normal;text-transform:uppercase;padding:5px 6px;border-bottom:1.5px solid ${RPT.ink}">${t}</th>`;
  const cell = (v, al, ex) => `<td style="text-align:${al || 'left'};padding:0 6px;height:17px;border-bottom:1px solid ${RPT.line};font-size:9.5px;color:${RPT.ink};${ex || ''}">${v}</td>`;
  const write = `<div style="border-bottom:1px solid ${RPT.faint};height:11px"></div>`;
  const box = `<div style="border:1px solid ${RPT.faint};height:13px;background:#FFFFFF"></div>`;
  const lastHead = P.hasPrev ? 'Spent ' + re_(P.prevLabel.slice(0, 3)) : 'Last month';
  let h = `<div style="background:${RPT.band};color:#FFFFFF;padding:16px 22px"><table style="width:100%;border-collapse:collapse"><tr>
    <td><div style="font-size:9px;letter-spacing:3px;color:#D4B06A">SHARMA FAMILY · PLANNING SHEET</div><div style="font-size:22px;margin-top:4px;color:#FFFFFF">Monthly Plan · ${re_(P.label)}</div>
    <div style="font-size:10.5px;color:#C9CEDA;margin-top:3px">Sit together on the 1st. Write your estimates in pen, then update the Budget tab.</div></td>
    <td style="text-align:right;vertical-align:top;font-size:9px;color:#C9CEDA">Printed ${re_(meta.stamp)}<br><span style="color:#D4B06A">All amounts in AED</span></td></tr></table></div>`;

  // income
  h += rsec_('01', 'Expected salary & income', 'Plan now ' + rf_(P.incomePlan));
  h += `<table style="width:100%;border-collapse:collapse"><tr>${W('34%', 'Income')}${W('14%', 'Plan now', 'right')}${W('18%', 'Our estimate', 'center')}${W('34%', 'Notes')}</tr>` +
    P.income.map(i => `<tr>${cell(re_(i.name))}${cell(rf_(i.plan), 'right', 'color:' + RPT.muted)}<td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${box}</td><td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${write}</td></tr>`).join('') +
    `<tr>${cell('Other / expected bonus')}${cell('', 'right')}<td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${box}</td><td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${write}</td></tr>
    <tr>${cell('<b>Total income</b>')}${cell('<b>' + rf_(P.incomePlan) + '</b>', 'right')}<td style="padding:3px 6px">${box}</td><td></td></tr></table>`;

  // spending
  h += rsec_('02', 'Spending plan', 'Plan now ' + rf_(P.spendPlan));
  h += `<table style="width:100%;border-collapse:collapse"><tr>${W('34%', 'Line')}${W('12%', 'Plan now', 'right')}${W('12%', lastHead, 'right')}${W('18%', 'Our estimate', 'center')}${W('24%', 'Notes')}</tr>` +
    P.groups.map(g => { const col = RPT.cat[g.name] || RPT.gold, lines = g.lines.filter(l => l.plan || l.last), sub = g.lines.reduce((a, l) => a + l.plan, 0);
      return `<tr><td colspan="5" style="padding:9px 6px 3px;font-size:8.5px;letter-spacing:1.5px;font-weight:bold;color:${col};text-transform:uppercase;border-bottom:1px solid ${col}">${re_(g.name)}</td></tr>` +
        lines.map(l => `<tr>${cell(re_(l.name) + (l.cur !== 'AED' && l.native ? ` <span style="font-size:8.5px;color:${RPT.faint}">(${re_(l.cur)} ${rf_(l.native)})</span>` : ''))}${cell(l.plan ? rf_(l.plan) : '–', 'right', 'color:' + RPT.muted)}${cell(P.hasPrev ? rf_(l.last) : '', 'right', 'color:' + RPT.faint)}<td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${box}</td><td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${write}</td></tr>`).join('') +
        `<tr>${cell('<span style="color:' + RPT.faint + '">+ new line</span>')}${cell('')}${cell('')}<td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${box}</td><td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${write}</td></tr>
        <tr>${cell('<i>' + re_(g.name) + ' total</i>', 'left', 'color:' + RPT.muted)}${cell(rf_(sub), 'right', 'font-weight:bold')}${cell('')}<td style="padding:2px 6px;border-bottom:1px solid ${RPT.line}">${box}</td>${cell('')}</tr>`; }).join('') +
    `<tr>${cell('<b>Total spending plan</b>')}${cell('<b>' + rf_(P.spendPlan) + '</b>', 'right')}${cell('')}<td style="padding:3px 6px">${box}</td>${cell('')}</tr></table>`;

  // one-off + reimbursements
  const blankRows = (n, cols) => Array.from({ length: n }, () => `<tr>${cols.map(() => `<td style="padding:2px 6px;border-bottom:1px solid ${RPT.line};height:19px"></td>`).join('')}</tr>`).join('');
  h += rsec_('03', 'One-off expenses expected', 'Outside the budget: travel, gifts, repairs, fees');
  h += `<table style="width:100%;border-collapse:collapse"><tr>${W('36%', 'What')}${W('16%', 'Amount', 'right')}${W('16%', 'When')}${W('22%', 'Paid from')}${W('10%', 'Done', 'center')}</tr>${blankRows(4, [1, 2, 3, 4, 5])}</table>`;
  h += rsec_('04', 'Reimbursements expected', 'Office expenses and claims to get back');
  h += `<table style="width:100%;border-collapse:collapse"><tr>${W('32%', 'Claim / what')}${W('14%', 'Amount', 'right')}${W('16%', 'Paid on')}${W('16%', 'Submitted')}${W('12%', 'Claim no.')}${W('10%', 'Received', 'center')}</tr>${blankRows(4, [1, 2, 3, 4, 5, 6])}</table>`;

  // cash check
  const ck = (lbl, pre, strong) => `<tr><td style="padding:4px 6px;font-size:10px;${strong ? 'font-weight:bold;' : ''}border-bottom:1px solid ${RPT.line}">${lbl}</td><td style="padding:4px 6px;font-size:9.5px;color:${RPT.muted};text-align:right;border-bottom:1px solid ${RPT.line}">${pre}</td><td style="width:26%;padding:2px 6px;border-bottom:1px solid ${RPT.line}">${box}</td></tr>`;
  h += rsec_('05', 'Cash check', 'Will our current accounts last the month?');
  h += `<table style="width:100%;border-collapse:collapse"><tr>${W('50%', 'Step')}${W('24%', 'From the app today', 'right')}${W('26%', 'Our figure', 'center')}</tr>
    ${ck('Cash in current accounts now', rf_(P.cashNow))}${ck('+ Salary still to come this month', '')}${ck('− Spending plan (section 02)', rf_(P.spendPlan))}${ck('− Card dues to pay', rf_(P.cardDues, 2))}
    ${ck('− One-off expenses (section 03)', '')}${ck('+ Reimbursements expected (section 04)', '')}${ck('= Left at month end (or top-up needed)', '', true)}${ck('Savings target this month', '')}</table>`;

  // decisions + signatures
  h += rsec_('06', 'Decisions for this month', '');
  h += `<div style="border:1px solid ${RPT.line};padding:6px 10px">${Array.from({ length: 3 }, () => `<div style="border-bottom:1px solid ${RPT.line};height:20px"></div>`).join('')}</div>
    <table style="width:100%;border-collapse:collapse;margin-top:22px;font-size:10px;color:${RPT.muted}"><tr><td style="width:45%;border-top:1px solid ${RPT.ink};padding-top:4px">Shubham</td><td style="width:10%"></td><td style="width:45%;border-top:1px solid ${RPT.ink};padding-top:4px">Priya</td></tr></table>
    <div style="margin-top:16px;font-size:8px;color:${RPT.faint};text-align:center">Sharma Finance · planning sheet · private family document</div>`;
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>@page{size:A4;margin:13mm 12mm}body{font-family:Roboto,Arial,Helvetica,sans-serif;color:${RPT.ink};margin:0}tr{page-break-inside:avoid}</style></head><body>${h}</body></html>`;
}

function rsecP_(no, title, right) {
  return `<table style="width:100%;margin:14px 0 5px;border-collapse:collapse"><tr><td style="font-size:9px;letter-spacing:2px;color:${RPT.gold};font-weight:bold;width:24px">${no}</td>
    <td style="font-size:13px;font-weight:bold;color:${RPT.ink}">${title}</td><td style="text-align:right;font-size:9.5px;color:${RPT.muted}">${right || ''}</td></tr></table>`;
}
