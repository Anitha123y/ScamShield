// ScamShield page logic.
// Flow: user clicks "Check" -> POST /api/check (1 s) -> show result
//       -> if AI is on: POST /api/explain (10-40 s) -> replace the explanation.
// SECURITY: message text is always inserted with textContent (never innerHTML),
// so a message containing HTML/JavaScript is shown as plain text and cannot run.

const $ = (id) => document.getElementById(id);
const ICON = { SCAM: "🚨", SUSPICIOUS: "⚠️", SAFE: "✅" };
let lastResult = null;

// Small helper: create an element with a class and text.
function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

// Call the API and turn errors into friendly messages.
async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "Please check the message and try again.";
    throw new Error(detail);
  }
  return data;
}

// ---------- startup: load settings and demo messages ----------
async function init() {
  const cfg = await api("/api/config");
  for (const lang of cfg.languages) $("language").append(new Option(lang, lang));
  for (const [label, text] of Object.entries(cfg.demos)) {
    const b = el("button", "pill", label);
    b.type = "button";
    b.onclick = () => { $("message").value = text; updateCount(); check(); };
    $("demos").append(b);
  }
  $("aiExplain").checked = cfg.ai_available;
  $("aiExplain").disabled = $("aiSecond").disabled = !cfg.ai_available;
  $("aiNote").hidden = cfg.ai_available;
}

function updateCount() { $("count").textContent = $("message").value.length; }

function showError(msg) { $("error").textContent = msg; $("error").hidden = !msg; }

// ---------- main action ----------
async function check() {
  const message = $("message").value.trim();
  showError("");
  if (!message) return showError("Please paste a message first.");
  $("checkBtn").disabled = true;
  $("checkBtn").textContent = "Checking…";
  try {
    const result = await api("/api/check", { message });
    lastResult = result;
    renderResult(result);
    const wantExplain = $("aiExplain").checked, wantSecond = $("aiSecond").checked;
    if (wantExplain || wantSecond) loadAI(message, wantSecond);   // runs in the background
  } catch (err) {
    showError(err.message);
  } finally {
    $("checkBtn").disabled = false;
    $("checkBtn").textContent = "🔍 Check message";
  }
}

async function loadAI(message, wantSecond) {
  const box = $("explanation");
  box.replaceChildren(el("h4", "", "🤖 AI explanation"));
  const loading = el("div", "loading");
  loading.append(el("span", "spinner"), el("span", "", "Writing the AI explanation (10–40 seconds)… the result above is ready."));
  box.append(loading);
  try {
    const ai = await api("/api/explain", { message, language: $("language").value, second_opinion: wantSecond });
    if (ai.verdict !== lastResult.verdict) {               // AI second opinion raised the risk
      renderCard({ ...lastResult, verdict: ai.verdict, title: ai.title }, ai.merge_note);
    } else if (ai.merge_note) {
      $("mergeNote").textContent = "🤖 " + ai.merge_note; $("mergeNote").hidden = false;
    }
    renderExplanation(ai.explanation, $("language").value);
  } catch (err) {
    renderExplanation(lastResult.explanation, null, err.message);   // fall back to rule-based text
  }
}

// ---------- drawing the result ----------
function renderResult(r) {
  $("empty").hidden = true;
  $("result").hidden = false;
  renderCard(r);
  renderExplanation(r.explanation);
  renderFindings(r);
  renderMessage(r.segments);
  $("report").hidden = r.verdict === "SAFE";
  $("copyText").textContent = reportText(r);
  $("breakdown").replaceChildren(...r.breakdown.map((line) => el("li", "", line)));
}

function renderCard(r, mergeNote) {
  $("card").className = "card " + r.verdict;
  $("icon").textContent = ICON[r.verdict];
  $("title").textContent = r.title;
  $("meaning").textContent = r.meaning;
  const pct = Math.round(r.score * 100);
  $("pin").style.left = Math.min(99, Math.max(1, pct)) + "%";
  $("meter").setAttribute("aria-label", `Risk score ${pct}%`);
  const n = r.red.length;
  $("meta").replaceChildren(
    el("span", "", `${r.risk_level} risk`), el("span", "", `Score ${pct}%`),
    el("span", "", `🌐 ${r.language}`), el("span", "", `🚩 ${n} red flag${n === 1 ? "" : "s"}`));
  $("mergeNote").textContent = mergeNote ? "🤖 " + mergeNote : "";
  $("mergeNote").hidden = !mergeNote;
}

function renderExplanation(ex, language, errorText) {
  const box = $("explanation");
  const title = ex.source === "ai" ? `🤖 AI explanation (${language})` : "💡 Explanation";
  box.replaceChildren(el("h4", "", title));
  if (errorText) box.append(el("p", "quote", `⚠️ ${errorText} Showing the rule-based explanation.`));
  box.append(el("p", "", ex.summary));
  if (ex.reasons.length) {
    const ul = el("ul");
    for (const r of ex.reasons) {
      const li = el("li", "", r.point);
      li.append(el("br"), el("span", "quote", `“${r.quote}”`));
      ul.append(li);
    }
    box.append(ul);
  }
  if (ex.what_to_do.length) {
    box.append(el("p", "", "What to do:"));
    box.lastChild.style.fontWeight = "700";
    box.append(el("ul", "", ""));
    for (const t of ex.what_to_do) box.lastChild.append(el("li", "", t));
  }
}

function renderFindings(r) {
  const out = $("findings");
  out.replaceChildren();
  const groups = [["🚩 Red flags", r.red, "red"], ["🔍 Things to verify", r.verify, "verify"], ["✅ Good signs", r.good, "good"]];
  for (const [heading, items, kind] of groups) {
    if (!items.length) continue;
    out.append(el("h3", "sec", heading));
    for (const f of items) {
      const card = el("div", "finding " + kind);
      const name = el("div", "name", f.name);
      if (f.critical) name.append(el("span", "crit", "CRITICAL"));
      card.append(name);
      if (kind !== "good") card.append(el("div", "why", f.why));
      card.append(el("div", "evidence", `Found: “${f.evidence}”`));
      out.append(card);
    }
    if (kind === "red") for (const c of r.context) out.append(el("span", "ctx", "⚡ " + c));
  }
  if (!out.children.length) out.append(el("p", "quote", "No red flags, things to verify or good signs were found."));
}

function renderMessage(segments) {
  const box = $("highlighted");
  box.replaceChildren();
  for (const s of segments) {
    if (!s.kind) { box.append(document.createTextNode(s.text)); continue; }
    const m = el("mark", s.kind, s.text);
    m.title = s.label;
    box.append(m);
  }
}

function reportText(r) {
  const lines = [`ScamShield result: ${r.verdict} (${r.risk_level} risk, score ${Math.round(r.score * 100)}%)`,
                 `Language: ${r.language}`];
  for (const [title, items] of [["Red flags", r.red], ["Things to verify", r.verify], ["Good signs", r.good]]) {
    if (!items.length) continue;
    lines.push(title + ":");
    for (const f of items) lines.push(`  - ${f.name}: "${f.evidence}"`);
  }
  lines.push("Report scams: cybercrime.gov.in or call 1930");
  return lines.join("\n");
}

// ---------- buttons ----------
$("checkBtn").onclick = check;
$("clearBtn").onclick = () => {
  $("message").value = ""; updateCount(); showError("");
  $("result").hidden = true; $("empty").hidden = false; lastResult = null;
};
$("copyBtn").onclick = async () => {
  await navigator.clipboard.writeText($("copyText").textContent);
  $("copyBtn").textContent = "Copied ✓";
  setTimeout(() => ($("copyBtn").textContent = "Copy to clipboard"), 1500);
};
$("message").addEventListener("input", updateCount);
$("message").addEventListener("keydown", (e) => { if (e.key === "Enter" && e.ctrlKey) check(); });

init().catch(() => showError("Could not reach the ScamShield server. Is it running?"));
