// Tripwire extractor, step 1. Memo text in, promise objects out. Deterministic, offline, no defaults.
// Every promise carries its exact quoted sentence. Parameters come from the memo or the promise is untestable.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const VERSION = "0.1.0-deterministic";
export const CATEGORIES = ["TRANSFER_RESTRICTION", "LOCKUP", "HOLDER_CAP", "JURISDICTION_BLOCK", "FORCED_TRANSFER_OR_FREEZE", "SUPPLY_CAP", "PAUSABILITY"];

// ---------- numbers ----------
const ONES = { zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19 };
const TENS = { twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70, eighty: 80, ninety: 90 };
const W = [...Object.keys(ONES), ...Object.keys(TENS), "hundred", "thousand", "million"].join("|");
export const NUM = `(?:\\d[\\d,]*(?:\\.\\d+)?(?:\\s*(?:million|thousand))?|(?:${W})(?:[-\\s]+(?:and[-\\s]+)?(?:${W}))*)`;
const PAREN = "(?:\\s*\\(\\s*\\d[\\d,]*\\s*\\))?";
export function parseNumber(str) {
  const s = String(str).toLowerCase().trim().replace(/\s+/g, " ");
  if (/^\d[\d,]*(\.\d+)?$/.test(s)) return Number(s.replace(/,/g, ""));
  const mm = s.match(/^(\d[\d,]*(?:\.\d+)?)\s*(million|thousand)$/);
  if (mm) return Number(mm[1].replace(/,/g, "")) * (mm[2] === "million" ? 1e6 : 1e3);
  let total = 0, cur = 0, seen = false;
  for (const w of s.split(/[\s-]+/)) {
    if (w === "and") continue;
    if (w in ONES) { cur += ONES[w]; seen = true; }
    else if (w in TENS) { cur += TENS[w]; seen = true; }
    else if (w === "hundred") { cur = (cur || 1) * 100; seen = true; }
    else if (w === "thousand") { total += (cur || 1) * 1000; cur = 0; seen = true; }
    else if (w === "million") { total += (cur || 1) * 1e6; cur = 0; seen = true; }
    else return null;
  }
  return seen ? total + cur : null;
}

// ---------- dates ----------
const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
const MON = MONTHS.join("|");
export function findDates(s) {
  const out = []; let m;
  const mk = (y, mo, d, index, text) => { const dt = new Date(Date.UTC(y, mo, d)); if (dt.getUTCFullYear() === y && dt.getUTCMonth() === mo && dt.getUTCDate() === d) out.push({ iso: dt.toISOString().slice(0, 10), index, text }); };
  const re1 = new RegExp(`\\b(${MON})\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})\\b`, "gi");
  const re2 = new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(${MON}),?\\s+(\\d{4})\\b`, "gi");
  const re3 = /\b(\d{4})-(\d{2})-(\d{2})\b/g;
  while ((m = re1.exec(s))) mk(+m[3], MONTHS.indexOf(m[1].toLowerCase()), +m[2], m.index, m[0]);
  while ((m = re2.exec(s))) mk(+m[3], MONTHS.indexOf(m[2].toLowerCase()), +m[1], m.index, m[0]);
  while ((m = re3.exec(s))) mk(+m[1], +m[2] - 1, +m[3], m.index, m[0]);
  return out.sort((a, b) => a.index - b.index);
}
export function addMonths(iso, n) {
  const d = new Date(iso + "T00:00:00Z"), y = d.getUTCFullYear(), m = d.getUTCMonth() + n, day = d.getUTCDate();
  const last = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  return new Date(Date.UTC(y, m, Math.min(day, last))).toISOString().slice(0, 10);
}
export function addDays(iso, n) { const d = new Date(iso + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
export function endDate(anchorIso, duration) {
  const { value, unit } = duration;
  return unit === "month" ? addMonths(anchorIso, value) : unit === "year" ? addMonths(anchorIso, value * 12) : unit === "week" ? addDays(anchorIso, value * 7) : addDays(anchorIso, value);
}

// ---------- sentences with offsets ----------
function mask(t) {
  return t
    .replace(/\b(?:U\.S|U\.K|E\.U|Inc|Corp|Ltd|vs|e\.g|i\.e|approx|etc)\./gi, (m) => m.replace(/\./g, "\u0001"))
    .replace(/(\d)\.(\d)/g, "$1\u0001$2")
    .replace(/(^|\n)([ \t]*\(?(?:\d{1,2}|[a-zA-Z]|[ivxIVX]{1,4})[.)])(?=[ \t])/g, (m, a, b) => a + b.replace(/\./g, "\u0001"));
}
export function sentences(text) {
  const m = mask(text), out = [];
  const push = (a, z) => {
    let seg = text.slice(a, z);
    a += seg.length - seg.trimStart().length;
    seg = text.slice(a, z).trimEnd(); z = a + seg.length;
    const mk = /^\(?(?:\d{1,2}|[a-zA-Z]|[ivxIVX]{1,4})[.)]\s+/.exec(seg);
    if (mk) a += mk[0].length;
    if (z - a >= 15) out.push({ start: a, end: z, text: text.slice(a, z) });
  };
  const lineRe = /[^\n]+/g; let lm;
  while ((lm = lineRe.exec(m))) {
    const line = lm[0], base = lm.index; let s = 0, b;
    const re = /[.!?]+["”')\]]*(?=\s+[A-Z“"(0-9]|\s*$)/g;
    while ((b = re.exec(line))) { push(base + s, base + b.index + b[0].length); s = b.index + b[0].length; }
    push(base + s, base + line.length);
  }
  return out;
}

// ---------- helpers ----------
const COUNTRIES = { iran: "IR", "north korea": "KP", "democratic people's republic of korea": "KP", syria: "SY", cuba: "CU", russia: "RU", "russian federation": "RU", belarus: "BY", myanmar: "MM", venezuela: "VE", sudan: "SD", "south sudan": "SS", afghanistan: "AF", iraq: "IQ", libya: "LY", yemen: "YE", somalia: "SO", "united states": "US", "united states of america": "US", usa: "US", china: "CN", "united kingdom": "GB", canada: "CA", singapore: "SG", nigeria: "NG" };
const normActor = (s) => { const m = s.match(/\b(?:the )?(issuer|transfer agent|company|administrator|trustee)\b/i); return m ? m[1].toLowerCase() : /\b(?:we|us|our)\b/i.test(s) ? "issuer (first person)" : null; };
const conditionOf = (s) => { const m = s.match(/(?:in the event of|upon|if|following|pursuant to|in case of)\s+([^.;]+)/i); return m ? m[1].trim().replace(/[.,]+$/, "") : null; };
const hasRight = /\b(?:right|may|can|authority|reserves|retains|able|power|entitled)\b/i;

function promise(category, sent, parameters, testable, reason) {
  const id = "P" + createHash("sha256").update(category + "|" + sent.text).digest("hex").slice(0, 8);
  const p = { id, quote: sent.text, span: { start: sent.start, end: sent.end }, category, parameters, testable };
  if (!testable) p.reason = reason;
  return p;
}

// ---------- detectors ----------
function anchorFor(kind, sents) {
  const KEY = { CLOSING: /closing|closed/i, ISSUANCE: /issue date|issuance date|date of (?:initial )?issuance|issued on|(?:were|are|will be) issued/i, EFFECTIVE_DATE: /effective date/i, EVENT: /token (?:integration|generation|launch) event|\bTGE\b|listing|launch/i }[kind];
  if (!KEY) return null;
  for (const s of sents) { if (!KEY.test(s.text)) continue; const d = findDates(s.text)[0]; if (d) return { kind, date: d.iso, quote: s.text, span: { start: s.start, end: s.end } }; }
  return null;
}
const START = [
  ["PER_HOLDER_ACQUISITION", /(?:each|such|that|every|any|the|its|their)\s+(?:holder|investor|purchaser|subscriber)['’]?s?\s+(?:own\s+)?(?:purchase|acquisition|subscription|investment)|date of (?:purchase|acquisition)|purchase date|from (?:their|its|his|her) (?:purchase|acquisition)/i],
  ["CLOSING", /closing/i],
  ["ISSUANCE", /\bissu(?:e|ance|ed)\b/i],
  ["EFFECTIVE_DATE", /effective date/i],
  ["EVENT", /token (?:integration|generation|launch) event|\bTGE\b|listing|launch/i],
];
const DUR = new RegExp(`(${NUM})${PAREN}[\\s-]+(day|week|month|year)s?\\b`, "i");
function detectLockup(sent, ctx) {
  const s = sent.text;
  const kw = /lock[-\s]?up|locked[-\s]?up|holding period|restricted period|non-?transferable|(?:may|must|shall|will) not (?:sell|transfer|resell)|not be (?:sold|transferred|resold)/i;
  const explicit = /lock[-\s]?up|locked[-\s]?up|holding period|restricted period/i.test(s);
  if (!kw.test(s)) return null;
  const sched = s.match(/between the (\d+)(?:st|nd|rd|th) and (\d+)(?:st|nd|rd|th) day/i);
  const ann = s.match(/\b(first|second|third)\s+anniversary/i);
  const dm = s.match(DUR);
  const dates = findDates(s);
  if (sched) {
    const frac = s.match(/\b(one[-\s]third|one[-\s]half|one[-\s]quarter|\d{1,3}\s?%)/i);
    return promise("LOCKUP", sent, { schedule: [{ fromDay: +sched[1], toDay: +sched[2], maxShare: frac ? frac[1] : null }] }, false, "Tiered release schedule. v1 tests only a single lock-up end date.");
  }
  let duration = null, derivedFrom = null;
  if (ann) { duration = { value: { first: 1, second: 2, third: 3 }[ann[1].toLowerCase()] * 12, unit: "month" }; derivedFrom = "anniversary"; }
  else if (dm) { const v = parseNumber(dm[1]); if (v !== null) duration = { value: v, unit: dm[2].toLowerCase() }; }
  if (!duration) {
    if (dates.length && /(?:until|through|before|prior to|ending)/i.test(s)) {
      return promise("LOCKUP", sent, { duration: null, startRule: "ABSOLUTE_DATE", anchor: null, endsAt: dates[0].iso }, true);
    }
    if (explicit) return promise("LOCKUP", sent, { duration: null, startRule: null, anchor: null, endsAt: null }, false, "The memo mentions a lock-up but states no duration or end date.");
    return null;
  }
  let startRule = "UNSPECIFIED";
  for (const [k, re] of START) if (re.test(s)) { startRule = k; break; }
  const params = { duration, startRule, anchor: null, endsAt: null };
  if (derivedFrom) params.derivedFrom = derivedFrom;
  if (startRule === "PER_HOLDER_ACQUISITION") return promise("LOCKUP", sent, params, false, "The lock-up runs from each holder's own purchase date, so there is no single end date. Testing it needs on-chain acquisition times (decision pending).");
  if (startRule === "UNSPECIFIED") return promise("LOCKUP", sent, params, false, "The memo does not say when the lock-up starts.");
  let anchor = anchorFor(startRule, ctx.sents);
  const own = findDates(s)[0];
  if (!anchor && own) anchor = { kind: startRule, date: own.iso, quote: s, span: { start: sent.start, end: sent.end } };
  if (!anchor) return promise("LOCKUP", sent, params, false, `The lock-up runs from the ${startRule.toLowerCase().replace(/_/g, " ")}, and the memo states no date for it.`);
  params.anchor = anchor; params.endsAt = endDate(anchor.date, duration);
  return promise("LOCKUP", sent, params, true);
}

const CLASSES = [
  [/accredited investors?/i, "accredited investors"], [/qualified institutional buyers?|\bQIBs?\b/i, "qualified institutional buyers"],
  [/qualified purchasers?/i, "qualified purchasers"], [/non-?U\.?S\.? (?:persons?|investors?)/i, "non-U.S. persons"],
  [/professional investors?/i, "professional investors"], [/eligible investors?/i, "eligible investors"],
  [/(?:whitelisted|KYC[-\s]?verified|verified)\s+(?:wallets?|addresses|investors?|holders?)/i, "whitelisted wallets"],
];
function detectTransfer(sent, already) {
  const s = sent.text;
  const verb = /\b(?:transfer(?:red|s)?|resold?|resale|sold|sell|assign(?:ed)?|offered|trade[sd]?|trading|transferability)\b/i;
  const restrictor = /\b(?:only|solely|exclusively|limited to|restricted to|except (?:to|for|as)|requires?\s+(?:the\s+)?(?:prior\s+)?(?:written\s+)?(?:consent|approval)|subject to (?:the )?(?:prior )?(?:written )?(?:consent|approval))\b/i;
  const classes = CLASSES.filter(([re]) => re.test(s)).map(([, l]) => l);
  const am = s.match(/(?:consent|approval) of (?:the )?(issuer|company|transfer agent|board)|approved (?:in writing )?by (?:the )?(issuer|company|transfer agent)/i);
  const approval = am ? { by: (am[1] || am[2]).toLowerCase() } : null;
  if (verb.test(s) && restrictor.test(s) && (classes.length || approval)) {
    const ex = s.match(/Rule 506\((?:b|c)\)|Regulation S|Reg\.? S\b|Regulation D|Reg\.? D\b|Rule 144A?/i);
    return promise("TRANSFER_RESTRICTION", sent, { recipientClasses: classes, approval, exemption: ex ? ex[0] : null }, true);
  }
  if (!already && /(?:restrictions?|limitations?) on (?:the )?(?:transfer|resale|transferability)|transfer restrictions?|restricted securities/i.test(s))
    return promise("TRANSFER_RESTRICTION", sent, { recipientClasses: [], approval: null, exemption: null }, false, "The memo says transfers are restricted but names no recipient class or approval requirement.");
  return null;
}

const HOLD = "(?:record\\s+holders|holders\\s+of\\s+record|holders|investors|beneficial\\s+owners|purchasers|stockholders|shareholders|wallets|addresses)";
function detectCap(sent) {
  const s = sent.text; let m, n = null, strict = false, kind = null;
  if ((m = s.match(new RegExp(`(?:no more than|not more than|maximum of|at most|up to|not exceed(?:ing)?|cap(?:ped)? at|limited to|limit of|cap of)\\s+(${NUM})${PAREN}\\s+(?:[a-z-]+\\s+){0,2}?(${HOLD})`, "i")))) { n = parseNumber(m[1]); kind = m[2]; }
  else if ((m = s.match(new RegExp(`(?:fewer|less) than\\s+(${NUM})${PAREN}\\s+(?:[a-z-]+\\s+){0,2}?(${HOLD})`, "i")))) { n = parseNumber(m[1]); strict = true; kind = m[2]; }
  else if ((m = s.match(new RegExp(`number of (?:record )?(?:holders|investors|owners)[^.]{0,80}?(not exceed|exceed(?:ing)?|capped at|limited to|at most|below|under|fewer than|less than)\\s+(${NUM})`, "i")))) { n = parseNumber(m[2]); strict = /below|under|fewer|less/i.test(m[1]); kind = "holders"; }
  if (n !== null && n > 0) return promise("HOLDER_CAP", sent, { maxHolders: strict ? n - 1 : n, statedNumber: n, comparator: strict ? "FEWER_THAN" : "AT_MOST", holderType: kind.toLowerCase().replace(/\s+/g, " ") }, true);
  if (/holder (?:limit|cap)|limit(?:ed)? (?:on|to) the number of (?:holders|investors)/i.test(s)) return promise("HOLDER_CAP", sent, {}, false, "The memo mentions a holder limit but states no number.");
  return null;
}

function detectJurisdiction(sent) {
  const s = sent.text;
  if (!/\b(?:not|never|prohibited|prohibits|barred|banned|restricted|excluded|forbidden|void)\b/i.test(s)) return null;
  let names = [], qualifier = null;
  if (/\bU\.?S\.? persons?\b|\bUnited States persons?\b/i.test(s)) { names.push("United States"); qualifier = "U.S. persons"; }
  const trig = /(?:residents?|citizens?|nationals?|persons?|investors?|entities|holders?|purchasers?)\s+(?:of|in|located in|resident in|residing in|domiciled in|organi[sz]ed in)\s+|(?:to|in)\s+(?:the following (?:countries|jurisdictions)|any of the following)\s*[:,]?\s*/i;
  const m = trig.exec(s);
  if (m) {
    let list = s.slice(m.index + m[0].length).replace(/[.]+$/, "").split(/\s+(?:unless|except|provided|subject to)\b/i)[0];
    for (let it of list.split(/,|;|\band\b|\bor\b/i)) {
      it = it.trim().replace(/^the\s+/i, "");
      if (!it || /^any other\b/i.test(it) || it.split(/\s+/).length > 5) continue;
      if (!names.map((x) => x.toLowerCase()).includes(it.toLowerCase())) names.push(it);
    }
  }
  if (!names.length) return null;
  const codes = names.map((n) => COUNTRIES[n.toLowerCase().replace(/\s+region$/, "")] ?? null);
  const unmappedNames = names.filter((n, i) => codes[i] === null);
  return promise("JURISDICTION_BLOCK", sent, { blocked: names, codes, unmappedNames, qualifier }, true);
}

function detectForced(sent) {
  const s = sent.text, powers = [];
  if (/\b(?:freeze|frozen|freezing)\b/i.test(s)) powers.push("FREEZE");
  if (/\b(?:force[d]?\s+(?:the\s+)?transfer|forced[-\s]transfer|claw[-\s]?back|seiz(?:e|ure)|reassign|recover(?:y)?\s+(?:of\s+)?(?:the\s+)?tokens)/i.test(s)) powers.push("FORCED_TRANSFER");
  if (/\b(?:burn|cancel(?:lation)?|revoke)\b/i.test(s) && /\btokens?\b/i.test(s)) powers.push("BURN_OR_REVOKE");
  if (!powers.length || !hasRight.test(s)) return null;
  const actor = normActor(s);
  if (!actor) return promise("FORCED_TRANSFER_OR_FREEZE", sent, { powers, actor: null, condition: conditionOf(s) }, false, "The memo describes the power but does not say who holds it.");
  return promise("FORCED_TRANSFER_OR_FREEZE", sent, { powers, actor, condition: conditionOf(s) }, true);
}

function detectSupply(sent) {
  const s = sent.text; let m;
  const T = `${PAREN}\\s*(?:tokens?|units)`;
  const pats = [
    new RegExp(`(?:total|maximum|max|aggregate|fixed|authori[sz]ed|hard[-\\s]?cap(?:ped)?)\\s+(?:token\\s+)?(?:supply|issuance|amount|number of tokens)[^.]{0,60}?(${NUM})${T}`, "i"),
    new RegExp(`(?:supply|issuance)[^.]{0,50}?(?:fixed|capped|limited|set|equal)\\s+(?:at|to|of)?\\s*(${NUM})${T}`, "i"),
    new RegExp(`(?:not|never)\\s+(?:issue|mint|create)\\s+(?:more than|in excess of|over)\\s+(${NUM})${T}`, "i"),
    new RegExp(`(?:no more than|not more than|a maximum of|up to|only)\\s+(${NUM})${T}\\s+(?:will|shall|may|can)?\\s*(?:be\\s+)?(?:issued|minted|created|authori[sz]ed)`, "i"),
  ];
  for (const re of pats) if ((m = s.match(re))) { const n = parseNumber(m[1]); if (n) return promise("SUPPLY_CAP", sent, { maxSupply: n, statedNumber: n, unit: "tokens", fixed: /\bfixed\b/i.test(s) }, true); }
  return null;
}

function detectPause(sent) {
  const s = sent.text;
  if (!/\b(?:pause[sd]?|pausable|suspend(?:s|ed)?|suspension|halt(?:s|ed)?)\b/i.test(s) || !/\b(?:transfers?|trading|transferability|tokens?)\b/i.test(s)) return null;
  const cannot = /\b(?:cannot|can not|may not|shall not|will not|not be|never)\b[^.]{0,40}?(?:pause[sd]?|suspend(?:ed)?|halt(?:ed)?)/i.test(s);
  const actor = normActor(s);
  if (cannot) return promise("PAUSABILITY", sent, { direction: "CANNOT_PAUSE", actor, condition: null }, true);
  if (actor && hasRight.test(s)) return promise("PAUSABILITY", sent, { direction: "CAN_PAUSE", actor, condition: conditionOf(s) }, true);
  return promise("PAUSABILITY", sent, { direction: null, actor, condition: conditionOf(s) }, false, "The memo mentions pausing or suspending but does not say who can do it.");
}

// ---------- main ----------
export function extractPromises(memo) {
  const sents = sentences(memo), ctx = { sents }, promises = [], unclassified = [];
  const KEYWORDS = /\b(?:transfer|restrict|lock[-\s]?up|holder|freeze|frozen|pause|suspend|supply|mint|jurisdiction|resident|accredited|smart contract|on-?chain)/i;
  for (const sent of sents) {
    const found = [];
    for (const f of [() => detectLockup(sent, ctx), () => detectCap(sent), () => detectJurisdiction(sent), () => detectForced(sent), () => detectSupply(sent), () => detectPause(sent)]) { const p = f(); if (p) found.push(p); }
    const tr = detectTransfer(sent, found.length > 0); if (tr) found.push(tr);
    if (/(?:enforced|enforce|implemented)\s+(?:by|through|via|on)\s+(?:the\s+)?(?:smart contract|on-?chain|blockchain)|smart contracts?\s+(?:will\s+)?enforce/i.test(sent.text) && found.every((x) => !x.testable)) found.length = 0;
    promises.push(...found);
    if (!found.length && KEYWORDS.test(sent.text)) unclassified.push({ quote: sent.text, span: { start: sent.start, end: sent.end }, note: /smart contract|on-?chain/i.test(sent.text) ? "Claims on-chain enforcement but states no testable parameter." : "Mentions enforcement-relevant terms but matches no category." });
  }
  return { extractorVersion: VERSION, memoSha256: createHash("sha256").update(memo).digest("hex"), promises, unclassified };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const file = process.argv[2];
  if (!file) { console.log("usage: node extractor/extract.mjs memo.txt [--summary]"); process.exit(2); }
  const out = extractPromises(readFileSync(file, "utf8"));
  if (process.argv.includes("--summary")) {
    for (const p of out.promises) console.log(`${p.id}  ${p.category.padEnd(26)} ${p.testable ? "testable  " : "UNTESTABLE"}  ${p.quote.slice(0, 70)}${p.reason ? "\n          -> " + p.reason : ""}`);
    for (const u of out.unclassified) console.log(`(unclassified) ${u.quote.slice(0, 70)}  [${u.note}]`);
  } else console.log(JSON.stringify(out, null, 2));
}
