/* ==========================================================================
   SET-CDP static/script.js


/* ==========================================================================
   1) SAFE HELPERS
   ========================================================================== */

function fileEscapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* Alias متعمد حتى لا تنكسر الصفحات القديمة */
function escapeHtml(value) {
  return fileEscapeHtml(value);
}

function safeText(value, fallback = "-") {
  const v = value ?? fallback;
  return v === "" ? fallback : v;
}

function normalizeUrl(raw) {
  const value = String(raw || "").trim();
  if (!value) return "";
  return /^https?:\/\//i.test(value) ? value : "https://" + value;
}

function normalizeDomain(raw) {
  return String(raw || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0]
    .trim();
}

function riskClass(level) {
  const clean = String(level || "").toLowerCase();

  if (/critical|high|danger|insecure|error|weak|expired|malicious|unsafe|failed/.test(clean)) {
    return "danger";
  }

  if (/medium|moderate|warning|suspicious|soon|unknown|info/.test(clean)) {
    return "warning";
  }

  return "success";
}

/* Compatibility مع الملف القديم */
function badge(level) {
  const type = riskClass(level);
  if (type === "danger") return "danger";
  if (type === "warning") return "warning";
  return "success";
}

function getRiskIcon(level) {
  const type = riskClass(level);

  if (type === "danger") {
    return '<i class="fas fa-exclamation-triangle text-danger fs-4"></i>';
  }

  if (type === "warning") {
    return '<i class="fas fa-exclamation-circle text-warning fs-4"></i>';
  }

  return '<i class="fas fa-check-circle text-success fs-4"></i>';
}

function riskBadge(level) {
  const type = riskClass(level);
  const cls =
    type === "danger" ? "bg-danger" :
    type === "warning" ? "bg-warning text-dark" :
    "bg-success";

  return `<span class="badge ${cls} rounded-pill px-3 py-2">${fileEscapeHtml(level || "Info")}</span>`;
}

function scoreBadge(level) {
  return riskBadge(level);
}

function safeScoreValue(score, fallback = 0) {
  const n = Number(score);
  if (Number.isFinite(n)) return Math.max(0, Math.min(100, n));
  return fallback;
}

function normalizeScoreMaybe10(score) {
  const n = Number(score || 0);
  if (!Number.isFinite(n)) return 0;
  if (n <= 10) return Math.max(0, Math.min(100, n * 10));
  return Math.max(0, Math.min(100, n));
}

function createProgressBar(score, level, label = "Security Score") {
  const safeScore = safeScoreValue(score, 0);
  const type = riskClass(level);
  const cls =
    type === "danger" ? "bg-danger" :
    type === "warning" ? "bg-warning" :
    "bg-success";

  return `
    <div class="mt-3 mb-3">
      <div class="d-flex justify-content-between mb-1">
        <small class="fw-bold" style="color: var(--set-muted, #94a3b8);">${fileEscapeHtml(label)}</small>
        <small class="fw-bold text-info">${safeScore}%</small>
      </div>
      <div class="progress" style="height: 9px; background-color: var(--set-border, #334155);">
        <div class="progress-bar ${cls} progress-bar-striped progress-bar-animated" style="width:${safeScore}%"></div>
      </div>
    </div>
  `;
}

function fileProgress(score, level, label = "Security Score") {
  return createProgressBar(score, level, label);
}

function renderList(items, emptyText = "لا توجد ملاحظات.") {
  const list = Array.isArray(items) ? items : [];

  if (!list.length) {
    return `<div class="small text-muted">${fileEscapeHtml(emptyText)}</div>`;
  }

  return `
    <ul class="mb-0 ps-3">
      ${list.map(item => `<li>${fileEscapeHtml(item)}</li>`).join("")}
    </ul>
  `;
}

function renderKeyValue(label, value, dir = "auto") {
  return `
    <div class="d-flex gap-2 flex-wrap align-items-start mb-1">
      <strong class="text-info">${fileEscapeHtml(label)}:</strong>
      <span dir="${dir}" style="color: var(--set-text, inherit);">${fileEscapeHtml(value ?? "-")}</span>
    </div>
  `;
}

function renderObjectTable(obj, title, icon = "fa-list") {
  if (!obj || typeof obj !== "object" || !Object.keys(obj).length) return "";

  const rows = Object.entries(obj).map(([key, value]) => {
    const shown = typeof value === "object" && value !== null
      ? JSON.stringify(value, null, 2)
      : value;

    return `
      <tr>
        <td class="fw-bold text-info" style="width: 220px;">${fileEscapeHtml(key)}</td>
        <td class="text-break" dir="auto">${fileEscapeHtml(shown)}</td>
      </tr>
    `;
  }).join("");

  return `
    <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
      <h6 class="fw-bold mb-2">
        <i class="fas ${icon} text-info"></i>
        ${fileEscapeHtml(title)}
      </h6>
      <div class="table-responsive">
        <table class="table table-sm align-middle mb-0" style="color: var(--set-text, inherit);">
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

function renderArrayList(items, title, icon = "fa-folder-tree", maxItems = 80) {
  if (!Array.isArray(items) || !items.length) return "";

  const shown = items.slice(0, maxItems);
  const rest = items.length - shown.length;

  return `
    <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
      <h6 class="fw-bold mb-2">
        <i class="fas ${icon} text-info"></i>
        ${fileEscapeHtml(title)}
      </h6>
      <ol class="mb-0 ps-3 font-monospace" dir="ltr" style="font-size: 12px; color: var(--set-text, inherit);">
        ${shown.map(item => `
          <li class="text-break">
            ${fileEscapeHtml(typeof item === "object" ? JSON.stringify(item) : String(item))}
          </li>
        `).join("")}
      </ol>
      ${rest > 0 ? `<div class="small text-muted mt-2">+ ${rest} عناصر أخرى غير معروضة.</div>` : ""}
    </div>
  `;
}

function renderHashInput(label, value, id) {
  return `
    <div class="mb-2">
      <small class="text-info fw-bold">${fileEscapeHtml(label)}</small>
      <div class="d-flex gap-2 mt-1">
        <input
          id="${id}"
          type="text"
          class="form-control form-control-sm font-monospace text-success"
          value="${fileEscapeHtml(value || "-")}"
          readonly
          style="background: var(--set-input, #111827); border-color: var(--set-border, #334155);"
        >
        <button class="btn btn-sm btn-outline-info" type="button" onclick="copyTextValue('${id}')">
          <i class="fas fa-copy"></i>
        </button>
      </div>
    </div>
  `;
}

function toolError(message) {
  return `
    <div class="alert alert-danger mb-0">
      <i class="fas fa-times-circle"></i>
      ${fileEscapeHtml(message || "حدث خطأ غير متوقع.")}
    </div>
  `;
}

function showError(box, msg) {
  if (!box) return;
  box.innerHTML = toolError(msg);
}

function setResult(id, html, type = "info") {
  const box = document.getElementById(id);
  if (!box) return;

  const border =
    type === "danger" ? "rgba(239, 68, 68, 0.45)" :
    type === "warning" ? "rgba(245, 158, 11, 0.45)" :
    type === "success" ? "rgba(34, 197, 94, 0.42)" :
    "rgba(56, 189, 248, 0.42)";

  box.style.background = "var(--set-card, rgba(15,23,42,.72))";
  box.style.border = `1px solid ${border}`;
  box.style.color = "var(--set-text, inherit)";
  box.classList.add("show", "p-3", "rounded", "mt-3");
  box.innerHTML = html;
}

function setFileResult(html, type = "info") {
  setResult("fileResult", html, type);
}

function setLoading(id, text = "جاري الفحص") {
  setResult(id, `
    <div class="text-center py-4">
      <i class="fas fa-circle-notch fa-spin text-info fs-2 mb-3"></i>
      <h6 style="color: var(--set-text, inherit);">${fileEscapeHtml(text)}...</h6>
      <small class="text-muted">يرجى الانتظار لحظات</small>
    </div>
  `);
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify(payload || {})
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.error || data.message || `HTTP ${res.status}`);
  }

  return data;
}

function copyTextValue(id) {
  const el = document.getElementById(id);
  if (!el) return;

  const text = el.value || el.textContent || "";

  navigator.clipboard.writeText(text).then(() => {
    if (typeof window.setcdpToast === "function") {
      window.setcdpToast("تم النسخ");
    }
  }).catch(() => {});
}

function copyGeneratedPassword() {
  copyTextValue("generatedPasswordText");
  copyTextValue("genPwdInput");
}


/* ==========================================================================
   2) STATS + HISTORY FROM DATABASE
   ========================================================================== */

function animateCounter(elementId, newValue, suffix = "") {
  const el = document.getElementById(elementId);
  if (!el) return;

  const cleanCurrent = String(el.textContent || "0").replace(/[^\d]/g, "");
  const start = Number(cleanCurrent || 0);
  const end = Number(newValue || 0);
  const duration = 650;
  const startTime = performance.now();

  function update(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const value = Math.round(start + (end - start) * eased);

    el.textContent = `${value}${suffix}`;
    el.setAttribute("dir", "ltr");
    el.style.direction = "ltr";
    el.style.unicodeBidi = "isolate";

    if (progress < 1) requestAnimationFrame(update);
  }

  requestAnimationFrame(update);
}

function normalizeStatsPayload(data) {
  return {
    captures: Number(data.captures ?? data.training ?? data.total_captures ?? 0),
    clones: Number(data.clones ?? data.total_clones ?? 0),
    scans: Number(data.scans ?? data.total_scans ?? 0),
    tools: Number(data.tools ?? data.total_tools ?? 10)
  };
}

async function refreshStats() {
  try {
    const res = await fetch(`/api/get-stats?ts=${Date.now()}`, {
      method: "GET",
      cache: "no-store",
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      console.warn("Stats API error:", data.error || res.status);
      return;
    }

    const stats = normalizeStatsPayload(data);

    animateCounter("statCaptures", stats.captures);
    animateCounter("statClones", stats.clones);
    animateCounter("statScans", stats.scans);

    const toolsEl = document.getElementById("statTools");
    if (toolsEl) {
      toolsEl.textContent = `${stats.tools || 10}+`;
      toolsEl.setAttribute("dir", "ltr");
      toolsEl.style.direction = "ltr";
      toolsEl.style.unicodeBidi = "isolate";
    }
  } catch (e) {
    console.warn("Stats refresh failed:", e.message);
  }
}

/* Compatibility مع الكود القديم */
async function loadStats() {
  return refreshStats();
}

async function refreshHistory() {
  const body = document.getElementById("historyBody");

  try {
    const res = await fetch(`/api/scans/recent?ts=${Date.now()}`, {
      cache: "no-store",
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    });

    const data = await res.json().catch(() => ({}));

    if (body && res.ok && Array.isArray(data.scans)) {
      const scans = data.scans;
      const isAdmin = Boolean(data.is_admin);
      const colCount = isAdmin ? 7 : 6;

      if (!scans.length) {
        body.innerHTML = `
          <tr>
            <td colspan="${colCount}" class="text-center text-secondary py-5">
              لا توجد عمليات فحص حديثة في سجلك.
            </td>
          </tr>
        `;
      } else {
        body.innerHTML = scans.map(s => {
          const level = String(s.risk_level || "Info");
          const cls =
            riskClass(level) === "danger" ? "bg-danger" :
            riskClass(level) === "warning" ? "bg-warning text-dark" :
            "bg-success";

          return `
            <tr>
              <td>${fileEscapeHtml(s.id)}</td>
              <td><span class="badge bg-secondary text-uppercase"><i class="fas fa-terminal me-1"></i>${fileEscapeHtml(s.scan_type || "-")}</span></td>
              <td class="text-break" style="max-width: 250px; color: var(--page-accent, #38bdf8);" dir="ltr">${fileEscapeHtml(s.target || "-")}</td>
              <td>${fileEscapeHtml(s.result_summary || "-")}</td>
              <td><span class="badge ${cls}">${fileEscapeHtml(level)}</span></td>
              <td><small class="text-secondary" dir="ltr">${fileEscapeHtml(s.timestamp || "-")}</small></td>
              ${isAdmin ? `<td><small class="fw-bold text-info"><i class="fas fa-user-ninja me-1"></i>${fileEscapeHtml(s.owner_username || "زائر")}</small></td>` : ""}
            </tr>
          `;
        }).join("");
      }
    }
  } catch (e) {
    console.warn("History refresh failed:", e.message);
  } finally {
    await refreshStats();
  }
}

/* للصفحات القديمة التي فيها div id="historyResult" */
async function loadHistory() {
  const box = document.getElementById("historyResult");
  if (!box) {
    return refreshHistory();
  }

  box.innerHTML = "Loading...";

  try {
    const r = await fetch(`/api/history?ts=${Date.now()}`, {
      credentials: "same-origin",
      cache: "no-store",
      headers: {"Accept": "application/json"}
    });

    const d = await r.json().catch(() => []);

    if (!r.ok) {
      throw new Error(d.error || `HTTP ${r.status}`);
    }

    if (!Array.isArray(d) || !d.length) {
      box.innerHTML = '<div class="alert alert-info">لا يوجد سجل حتى الآن</div>';
      await refreshStats();
      return;
    }

    box.innerHTML = `
      <div class="table-responsive">
        <table class="table table-sm table-bordered history-table">
          <thead>
            <tr>
              <th>النوع</th>
              <th>الهدف</th>
              <th>النتيجة</th>
              <th>المستوى</th>
              <th>الوقت</th>
            </tr>
          </thead>
          <tbody>
            ${d.map(x => `
              <tr>
                <td>${fileEscapeHtml(x.scan_type)}</td>
                <td dir="ltr">${fileEscapeHtml(x.target)}</td>
                <td>${fileEscapeHtml(x.result_summary || "-")}</td>
                <td>${fileEscapeHtml(x.risk_level || "-")}</td>
                <td dir="ltr">${fileEscapeHtml(x.timestamp)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  } catch (e) {
    box.innerHTML = toolError(e.message);
  } finally {
    await refreshStats();
  }
}

async function clearHistory() {
  if (!confirm("هل تريد مسح السجل؟")) return;

  try {
    await fetch("/api/history/clear", {
      method: "DELETE",
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    });

    await loadHistory();
    await refreshHistory();
    await refreshStats();
  } catch (e) {
    alert(e.message || "تعذر مسح السجل.");
  }
}


/* ==========================================================================
   3) DELETE BUTTONS FOR DASHBOARD
   ========================================================================== */

async function setcdpDeleteRequest(url) {
  const res = await fetch(url, {
    method: "DELETE",
    credentials: "same-origin",
    headers: {"Accept": "application/json"}
  });

  const contentType = res.headers.get("content-type") || "";
  let data = {};

  if (contentType.includes("application/json")) {
    data = await res.json().catch(() => ({}));
  } else {
    const text = await res.text().catch(() => "");
    data = {error: text || `HTTP ${res.status}`};
  }

  if (!res.ok) {
    if (res.status === 401 || res.status === 302) {
      throw new Error("يجب تسجيل الدخول أولاً.");
    }
    if (res.status === 403) {
      throw new Error(data.error || "غير مصرح لك بحذف هذا العنصر.");
    }
    if (res.status === 404) {
      throw new Error(data.error || "العنصر غير موجود أو تم حذفه مسبقاً.");
    }
    throw new Error(data.error || data.message || `فشل الحذف - HTTP ${res.status}`);
  }

  return data;
}

async function deleteCapture(itemId) {
  const id = Number(itemId);

  if (!id) {
    alert("ID غير صالح.");
    return;
  }

  if (!confirm(`هل تريد حذف السجل رقم ${id}؟`)) return;

  try {
    await setcdpDeleteRequest(`/api/delete-captured/${encodeURIComponent(id)}`);
    await refreshStats();

    /* جداول لوحة التحكم غالباً مبنية من Jinja لذلك reload أفضل */
    window.location.reload();
  } catch (e) {
    alert(e.message || "حدث خطأ أثناء الحذف.");
    console.error("deleteCapture failed:", e);
  }
}

async function deleteClone(cloneName) {
  const name = String(cloneName || "").trim();

  if (!name) {
    alert("اسم النسخة غير صالح.");
    return;
  }

  if (!confirm(`هل تريد حذف النسخة: ${name}؟`)) return;

  try {
    await setcdpDeleteRequest(`/api/delete-clone/${encodeURIComponent(name)}`);
    await refreshStats();

    window.location.reload();
  } catch (e) {
    alert(e.message || "حدث خطأ أثناء حذف النسخة.");
    console.error("deleteClone failed:", e);
  }
}


/* ==========================================================================
   4) OPTIONAL LOG SCAN
   ========================================================================== */

async function logScan(scanType, target, resultSummary, riskLevel) {
  try {
    await postJson("/api/log-scan", {
      scan_type: scanType,
      target: target || "-",
      result_summary: resultSummary || "Completed",
      risk_level: riskLevel || "Info"
    });

    await refreshStats();
  } catch (e) {
    console.warn("Log skipped:", e.message);
  }
}


/* ==========================================================================
   5) COMPATIBILITY RENDERERS FROM OLD FILE
   ========================================================================== */

function normalizeHeaderList(headers) {
  if (Array.isArray(headers)) return headers;

  if (headers && typeof headers === "object") {
    return Object.entries(headers).map(([name, h]) => ({
      header: name,
      present: Boolean(h && h.present),
      status: h && h.present ? "Secure" : "Missing",
      value: h && h.value ? h.value : "Not Set",
      recommendation: h && h.recommendation ? h.recommendation : ""
    }));
  }

  return [];
}

function renderWebsiteResult(d) {
  if (d.error) return `<div class="alert alert-danger">${fileEscapeHtml(d.error)}</div>`;

  const level = d.level || d.risk || "Checked";
  const score = safeScoreValue(d.score, 0);
  const headers = normalizeHeaderList(d.headers);

  return `
    <div class="result-card">
      <div class="d-flex justify-content-between">
        <h5>نتيجة فحص الموقع</h5>
        ${riskBadge(level)}
      </div>
      ${createProgressBar(score, level)}
      <p><b>HTTPS:</b> ${d.https ? "✅ مفعل" : "❌ غير مفعل"}</p>
      <p><b>Status:</b> ${fileEscapeHtml(d.status_code || "-")}</p>
      <h6>Security Headers</h6>
      <ul class="clean-list">
        ${headers.map(h => `
          <li>
            ${h.present || h.status === "Secure" ? "✅" : "❌"}
            <b>${fileEscapeHtml(h.header)}</b>
            <small>${fileEscapeHtml(h.value || "Not Set")}</small>
          </li>
        `).join("")}
      </ul>
      ${(d.missing || d.issues || []).length
        ? `<div class="alert alert-warning mt-2"><b>ملاحظات:</b> ${(d.missing || d.issues).map(fileEscapeHtml).join(", ")}</div>`
        : ""}
    </div>
  `;
}

function renderSSLResult(d) {
  if (d.error) return `<div class="alert alert-danger">${fileEscapeHtml(d.error)}</div>`;

  return `
    <div class="result-card">
      <div class="d-flex justify-content-between">
        <h5>نتيجة SSL</h5>
        ${riskBadge(d.status)}
      </div>
      <p><b>Domain:</b> ${fileEscapeHtml(d.domain || "-")}</p>
      <p><b>Issuer:</b> ${fileEscapeHtml(d.issuer || "-")}</p>
      <p><b>Expires:</b> ${fileEscapeHtml(d.expires || "-")}</p>
      <p><b>Days left:</b> ${fileEscapeHtml(d.days_left ?? "-")} يوم</p>
    </div>
  `;
}

function renderPasswordResult(d) {
  const level = d.strength || "Info";
  return `
    <div class="result-card">
      <div class="d-flex justify-content-between">
        <h5>تحليل كلمة المرور</h5>
        ${riskBadge(level)}
      </div>
      ${createProgressBar(d.score, level)}
      <p><b>Score:</b> ${fileEscapeHtml(d.score ?? 0)}%</p>
      <ul class="clean-list">
        ${(d.feedback || []).map(x => {
          const text = typeof x === "string" ? x : (x.msg || "");
          return `<li>${fileEscapeHtml(text)}</li>`;
        }).join("")}
      </ul>
    </div>
  `;
}

function renderEmailResult(d) {
  const level = d.risk || "Info";
  return `
    <div class="result-card">
      <div class="d-flex justify-content-between">
        <h5>تحليل التصيد</h5>
        ${riskBadge(level)}
      </div>
      ${createProgressBar(normalizeScoreMaybe10(d.score), level)}
      <p><b>Score:</b> ${fileEscapeHtml(d.score ?? 0)}</p>
      <h6>المؤشرات</h6>
      <ul class="clean-list">${(d.findings || []).map(x => `<li>${fileEscapeHtml(x)}</li>`).join("")}</ul>
    </div>
  `;
}

function renderFileResult(d) {
  if (d.error) return `<div class="alert alert-danger">${fileEscapeHtml(d.error)}</div>`;

  return `
    <div class="result-card">
      <h5>تحليل الملف</h5>
      <p><b>Filename:</b> ${fileEscapeHtml(d.filename || d.basic?.filename || "-")}</p>
      <p><b>Type:</b> ${fileEscapeHtml(d.file_type || d.type_detection?.description || "-")}</p>
      <p><b>Size:</b> ${fileEscapeHtml(d.size || d.basic?.size_bytes || "-")} bytes</p>
      <h6>Hashes</h6>
      <div class="hash-box">MD5: ${fileEscapeHtml(d.hashes?.md5 || "-")}</div>
      <div class="hash-box">SHA1: ${fileEscapeHtml(d.hashes?.sha1 || "-")}</div>
      <div class="hash-box">SHA256: ${fileEscapeHtml(d.hashes?.sha256 || "-")}</div>
      ${Object.keys(d.metadata || {}).length
        ? `<h6 class="mt-2">Metadata</h6>
           <ul class="clean-list">
             ${Object.entries(d.metadata).map(([k, v]) => `<li><b>${fileEscapeHtml(k)}:</b> ${fileEscapeHtml(v)}</li>`).join("")}
           </ul>`
        : ""}
      ${(d.warnings || d.security?.warnings || []).length
        ? `<div class="alert alert-warning mt-2">${(d.warnings || d.security?.warnings).map(fileEscapeHtml).join("<br>")}</div>`
        : ""}
    </div>
  `;
}

function renderUrlResult(d) {
  const level = d.level || d.risk || "Info";
  return `
    <div class="result-card">
      <div class="d-flex justify-content-between">
        <h5>فحص الرابط</h5>
        ${riskBadge(level)}
      </div>
      ${createProgressBar(d.score, level)}
      <ul class="clean-list">${(d.issues || []).map(x => `<li>${fileEscapeHtml(x)}</li>`).join("")}</ul>
    </div>
  `;
}


/* ==========================================================================
   6) TOOL FUNCTIONS
   ========================================================================== */

async function scanWebsite() {
  const url = normalizeUrl(document.getElementById("scanUrl")?.value);

  if (!url) {
    return setResult("scanResult", `<div class="alert alert-warning mb-0">أدخل الرابط.</div>`, "warning");
  }

  setLoading("scanResult", "جاري فحص الموقع");

  try {
    const d = await postJson("/api/scan-website", {url});
    const level = d.level || d.risk || "Checked";
    const headers = normalizeHeaderList(d.headers);

    const headersBlock = headers.length ? `
      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-info mb-2">
          <i class="fas fa-server"></i>
          Security Headers
        </h6>
        <div class="table-responsive">
          <table class="table table-sm align-middle mb-0" style="color: var(--set-text, inherit); font-size: 13px;">
            <tbody>
              ${headers.map(h => `
                <tr>
                  <td class="fw-bold font-monospace">${fileEscapeHtml(h.header)}</td>
                  <td>${h.present || h.status === "Secure" ? '<span class="badge bg-success">موجود</span>' : '<span class="badge bg-danger">مفقود</span>'}</td>
                  <td class="text-break text-secondary" dir="ltr">${fileEscapeHtml(h.value || "-")}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    ` : `
      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        ${renderKeyValue("Headers Found", `${d.headers_found ?? "-"} / ${d.total_headers ?? "-"}`)}
      </div>
    `;

    const html = `
      <div class="d-flex align-items-center justify-content-between mb-3 border-bottom pb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <div class="d-flex align-items-center gap-2">
          ${getRiskIcon(level)}
          <h6 class="mb-0 fw-bold">تقرير فحص الموقع</h6>
        </div>
        ${scoreBadge(level)}
      </div>

      <div class="p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        ${renderKeyValue("الرابط", d.final_url || d.url || url, "ltr")}
        ${renderKeyValue("HTTPS", d.https ? "مفعل" : "غير مفعل")}
        ${renderKeyValue("Status Code", d.status_code || "-")}
        ${renderKeyValue("الخادم", d.server || "Unknown", "ltr")}
      </div>

      ${createProgressBar(d.score, level)}

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-warning mb-2">
          <i class="fas fa-flag"></i>
          الملاحظات الأمنية
        </h6>
        ${renderList(d.issues || d.missing, "لا توجد ملاحظات واضحة.")}
      </div>

      ${headersBlock}
    `;

    setResult("scanResult", html, riskClass(level));
    await refreshHistory();
  } catch (e) {
    setResult("scanResult", toolError(e.message), "danger");
  }
}

async function checkSSL() {
  const domain = normalizeDomain(document.getElementById("sslDomain")?.value);

  if (!domain) {
    return setResult("sslResult", `<div class="alert alert-warning mb-0">أدخل اسم النطاق.</div>`, "warning");
  }

  setLoading("sslResult", "جاري فحص شهادة SSL/TLS");

  try {
    const d = await postJson("/api/ssl-check", {domain});
    const level = d.status || "Checked";

    const html = `
      <div class="d-flex align-items-center justify-content-between mb-3 border-bottom pb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <div class="d-flex align-items-center gap-2">
          ${getRiskIcon(level)}
          <h6 class="mb-0 fw-bold">تفاصيل شهادة التشفير</h6>
        </div>
        ${scoreBadge(level)}
      </div>

      <div class="p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        ${renderKeyValue("Domain", d.domain || domain, "ltr")}
        ${renderKeyValue("TLS Version", d.tls_version || "-", "ltr")}
        ${renderKeyValue("Cipher", d.cipher || "-", "ltr")}
        ${renderKeyValue("Issuer", d.issuer || "Unknown", "ltr")}
        ${renderKeyValue("Expires", d.expires || "-", "ltr")}
        ${renderKeyValue("Days Left", d.days_left ?? "-")}
        ${renderKeyValue("SAN Count", d.san_count ?? "-")}
      </div>

      ${createProgressBar(d.score, level)}

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-info mb-2">نتيجة التحليل</h6>
        ${renderList(d.issues, "الشهادة صالحة.")}
      </div>
    `;

    setResult("sslResult", html, riskClass(level));
    await refreshHistory();
  } catch (e) {
    setResult("sslResult", toolError(e.message), "danger");
  }
}

async function checkPassword() {
  const password = document.getElementById("passwordInput")?.value || "";

  if (!password) {
    const box = document.getElementById("passwordResult");
    if (box) box.classList.remove("show");
    return;
  }

  try {
    const d = await postJson("/api/check-password", {password});
    const level = d.strength || "Info";

    const feedbackHtml = (d.feedback || []).map(f => {
      if (typeof f === "string") {
        return `<span class="badge bg-secondary py-2 px-3">${fileEscapeHtml(f)}</span>`;
      }

      const cls =
        f.type === "success" ? "bg-success" :
        f.type === "warning" ? "bg-warning text-dark" :
        "bg-danger";

      return `<span class="badge ${cls} py-2 px-3">${fileEscapeHtml(f.msg || "")}</span>`;
    }).join("");

    const html = `
      <div class="d-flex justify-content-between align-items-center border-bottom pb-2 mb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <h6 class="mb-0 fw-bold text-warning">
          <i class="fas fa-key"></i>
          قوة الكلمة
        </h6>
        ${scoreBadge(level)}
      </div>

      ${createProgressBar(d.score, level, "Password Score")}

      <div class="mt-3 d-flex flex-wrap gap-2">
        ${feedbackHtml || '<span class="badge bg-secondary">لا توجد ملاحظات</span>'}
      </div>
    `;

    setResult("passwordResult", html, riskClass(level));
  } catch (e) {
    setResult("passwordResult", toolError(e.message), "danger");
  }
}

async function checkEmail() {
  const email = document.getElementById("emailInput")?.value || "";

  if (!email.trim()) {
    return setResult("emailResult", `<div class="alert alert-warning mb-0">الصق نص الرسالة.</div>`, "warning");
  }

  setLoading("emailResult", "جاري تحليل مؤشرات التصيد");

  try {
    const d = await postJson("/api/check-email", {email});
    const level = d.risk || "Info";
    const score = normalizeScoreMaybe10(d.score);

    const urlsBlock = Array.isArray(d.urls) && d.urls.length ? `
      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-info mb-2">
          <i class="fas fa-link"></i>
          الروابط المستخرجة
        </h6>
        <ol class="mb-0 ps-3 font-monospace text-secondary" dir="ltr" style="font-size: 13px;">
          ${d.urls.map(u => `<li>${fileEscapeHtml(u)}</li>`).join("")}
        </ol>
      </div>
    ` : "";

    const html = `
      <div class="d-flex align-items-center justify-content-between mb-2 border-bottom pb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <h6 class="mb-0 fw-bold text-danger">
          <i class="fas fa-envelope-open-text"></i>
          تقييم التصيد
        </h6>
        ${scoreBadge(level)}
      </div>

      ${createProgressBar(score, level)}

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-warning mb-2">
          <i class="fas fa-flag"></i>
          المؤشرات المستخرجة
        </h6>
        ${renderList(d.findings, "لا توجد مؤشرات واضحة.")}
      </div>

      ${urlsBlock}
    `;

    setResult("emailResult", html, riskClass(level));
    await refreshHistory();
  } catch (e) {
    setResult("emailResult", toolError(e.message), "danger");
  }
}

async function analyzeFile() {
  const input = document.getElementById("fileInput");
  const file = input?.files?.[0];

  if (!file) {
    return setFileResult(`<div class="alert alert-warning mb-0">اختر ملفاً أولاً.</div>`, "warning");
  }

  if (file.size > 25 * 1024 * 1024) {
    return setFileResult(`<div class="alert alert-danger mb-0">حجم الملف كبير. الحد الأقصى 25MB.</div>`, "danger");
  }

  setFileResult(`
    <div class="text-center py-4">
      <i class="fas fa-file-shield fa-beat text-info fs-1 mb-3"></i>
      <h6 class="fw-bold">جاري استخراج بيانات الملف والـ Metadata...</h6>
      <small class="text-muted">يتم التحليل على الخادم بدون تخزين محتوى الملف.</small>
    </div>
  `);

  try {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("client_last_modified", String(file.lastModified || ""));

    const res = await fetch("/api/analyze-file", {
      method: "POST",
      credentials: "same-origin",
      body: fd
    });

    const d = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw new Error(d.error || `HTTP ${res.status}`);
    }

    window.lastFileAnalysisReport = d;

    const level = d.security?.risk || d.risk || "Info";
    const score = d.security?.score ?? (
      riskClass(level) === "success" ? 92 :
      riskClass(level) === "warning" ? 65 :
      35
    );

    const deep = d.deep_metadata || {};
    const image = deep.image || {};
    const pdf = deep.pdf || {};
    const office = deep.office || {};
    const zip = deep.zip || {};
    const typeDetection = d.type_detection || {};

    const html = `
      <div class="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <div>
          <h5 class="mb-1 fw-bold text-info">
            <i class="fas fa-microchip"></i>
            تقرير تحليل الملف المتقدم
          </h5>
          <small class="text-muted">Static Metadata & Risk Analysis</small>
        </div>
        ${riskBadge(level)}
      </div>

      ${fileProgress(score, level)}

      <div class="row g-3">
        <div class="col-md-6">
          <div class="p-3 rounded h-100" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
            <h6 class="fw-bold text-info">
              <i class="fas fa-circle-info"></i>
              معلومات أساسية
            </h6>
            ${renderKeyValue("الاسم", d.basic?.filename || d.filename || file.name)}
            ${renderKeyValue("الحجم", d.basic?.size_human || d.size_human || ((d.size || file.size) + " bytes"))}
            ${renderKeyValue("الامتداد", d.basic?.extension || typeDetection.extension || "-")}
            ${renderKeyValue("آخر تعديل من المتصفح", d.basic?.browser_last_modified || "-", "ltr")}
            ${renderKeyValue("وقت التحليل", d.basic?.server_analysis_time || "-", "ltr")}
          </div>
        </div>

        <div class="col-md-6">
          <div class="p-3 rounded h-100" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
            <h6 class="fw-bold text-warning">
              <i class="fas fa-fingerprint"></i>
              النوع الحقيقي
            </h6>
            ${renderKeyValue("Magic Type", typeDetection.description || d.file_type || "Unknown")}
            ${renderKeyValue("MIME", typeDetection.mime || "-", "ltr")}
            ${renderKeyValue("Magic Hex", typeDetection.magic_hex || "-", "ltr")}
            ${renderKeyValue("Entropy", `${d.entropy ?? "-"} / 8`)}
          </div>
        </div>
      </div>

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-danger mb-2">
          <i class="fas fa-triangle-exclamation"></i>
          التحذيرات والتحليل الأمني
        </h6>
        ${renderList(d.security?.warnings || d.warnings, "لم يتم اكتشاف مؤشرات خطورة واضحة.")}
        ${d.security?.note ? `<div class="small text-muted mt-2">${fileEscapeHtml(d.security.note)}</div>` : ""}
      </div>

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-success mb-2">
          <i class="fas fa-hashtag"></i>
          البصمات الرقمية Hashes
        </h6>
        ${renderHashInput("MD5", d.hashes?.md5, "hashMd5")}
        ${renderHashInput("SHA-1", d.hashes?.sha1, "hashSha1")}
        ${renderHashInput("SHA-256", d.hashes?.sha256, "hashSha256")}
        ${d.hashes?.sha512 ? renderHashInput("SHA-512", d.hashes.sha512, "hashSha512") : ""}
        <button class="btn btn-sm btn-outline-info mt-2" type="button" onclick="downloadFileAnalysisReport()">
          <i class="fas fa-download"></i>
          تحميل تقرير JSON
        </button>
      </div>

      ${renderObjectTable(d.metadata, "Metadata المختصرة", "fa-tags")}

      ${renderObjectTable(image.summary, "Image Summary", "fa-image")}
      ${renderObjectTable(image.software_device, "Camera / Device / Software", "fa-camera")}
      ${renderObjectTable(image.dates, "Image Dates", "fa-calendar-days")}
      ${renderObjectTable(image.exif, "Full EXIF Metadata", "fa-list")}
      ${renderObjectTable(image.gps, "GPS Metadata إن وجدت", "fa-location-dot")}

      ${renderObjectTable(pdf.summary, "PDF Summary", "fa-file-pdf")}
      ${renderObjectTable(pdf.document_info, "PDF Document Info", "fa-tags")}
      ${renderObjectTable(pdf.dates, "PDF Dates", "fa-calendar-days")}
      ${renderObjectTable(pdf.security_indicators, "PDF Security Indicators", "fa-shield-halved")}

      ${renderObjectTable(office.core_properties, "Office Core Properties", "fa-file-word")}
      ${renderObjectTable(office.app_properties, "Office App Properties", "fa-building")}
      ${renderObjectTable(office.package_summary, "Office Package Summary", "fa-box-archive")}
      ${renderObjectTable(office.security_indicators, "Office Security Indicators", "fa-shield-halved")}
      ${renderArrayList(office.sample_entries, "Office Internal Package Entries", "fa-folder-tree")}

      ${renderObjectTable(zip.summary, "ZIP / Package Summary", "fa-file-zipper")}
      ${renderObjectTable(zip.security_indicators, "ZIP Security Indicators", "fa-shield-halved")}
      ${renderArrayList(zip.sample_entries, "ZIP Entries Sample", "fa-folder-tree")}
    `;

    setFileResult(html, riskClass(level));
    await refreshHistory();
  } catch (e) {
    setFileResult(toolError(e.message), "danger");
  }
}

function downloadFileAnalysisReport() {
  if (!window.lastFileAnalysisReport) {
    alert("لا يوجد تقرير لتحميله");
    return;
  }

  const blob = new Blob(
    [JSON.stringify(window.lastFileAnalysisReport, null, 2)],
    {type: "application/json"}
  );

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download = "setcdp-file-analysis-report.json";

  document.body.appendChild(a);
  a.click();
  a.remove();

  URL.revokeObjectURL(url);
}

async function checkURL() {
  const url = document.getElementById("urlCheckInput")?.value || "";

  if (!url.trim()) {
    return setResult("urlResult", `<div class="alert alert-warning mb-0">أدخل الرابط.</div>`, "warning");
  }

  setLoading("urlResult", "جاري تقييم الرابط");

  try {
    const d = await postJson("/api/check-url", {url});
    const level = d.level || d.risk || "Info";

    const html = `
      <div class="d-flex justify-content-between align-items-center mb-2 border-bottom pb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <h6 class="mb-0 fw-bold">
          <i class="fas fa-shield-alt text-info"></i>
          تقييم الرابط
        </h6>
        ${scoreBadge(level)}
      </div>

      <div class="p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        ${renderKeyValue("URL", d.url || normalizeUrl(url), "ltr")}
        ${renderKeyValue("Domain", d.domain || "-", "ltr")}
      </div>

      ${createProgressBar(d.score, level)}

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-warning mb-2">
          <i class="fas fa-search"></i>
          المؤشرات المكتشفة
        </h6>
        ${renderList(d.issues, "الرابط يبدو آمناً.")}
      </div>
    `;

    setResult("urlResult", html, riskClass(level));
    await refreshHistory();
  } catch (e) {
    setResult("urlResult", toolError(e.message), "danger");
  }
}

async function generatePassword() {
  const length = Math.max(8, Math.min(64, Number(document.getElementById("genLength")?.value || 16)));

  setLoading("generatedPasswordResult", "جاري التوليد");

  try {
    let password = "";

    try {
      const d = await postJson("/api/generate-password", {
        length,
        upper: true,
        lower: true,
        digits: true,
        symbols: true
      });
      password = d.password;
    } catch (_) {
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}";
      const arr = new Uint32Array(length);
      crypto.getRandomValues(arr);

      for (let i = 0; i < length; i++) {
        password += chars[arr[i] % chars.length];
      }
    }

    const html = `
      <h6 class="fw-bold text-success mb-2">
        <i class="fas fa-check-circle"></i>
        كلمة المرور المولدة
      </h6>
      <div class="d-flex gap-2">
        <input
          type="text"
          id="genPwdInput"
          class="form-control text-success fw-bold font-monospace"
          style="background: var(--set-input, #111827);"
          value="${fileEscapeHtml(password)}"
          readonly
        >
        <button class="btn btn-outline-success" onclick="copyTextValue('genPwdInput')" type="button">
          <i class="fas fa-copy"></i>
        </button>
      </div>
      <div id="generatedPasswordText" class="visually-hidden">${fileEscapeHtml(password)}</div>
    `;

    setResult("generatedPasswordResult", html, "success");
    await refreshHistory();
  } catch (e) {
    setResult("generatedPasswordResult", toolError(e.message), "danger");
  }
}

async function expandUrl() {
  const url = normalizeUrl(document.getElementById("expandUrlInput")?.value);

  if (!url) {
    return setResult("expandUrlResult", `<div class="alert alert-warning mb-0">أدخل الرابط المختصر.</div>`, "warning");
  }

  setLoading("expandUrlResult", "جاري تتبع مسار الرابط");

  try {
    const d = await postJson("/api/expand-url", {url});
    const level = d.risk || "Info";
    const chain = Array.isArray(d.chain) ? d.chain : [];

    const html = `
      <div class="d-flex justify-content-between align-items-center mb-3 border-bottom pb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <div class="d-flex align-items-center gap-2">
          ${getRiskIcon(level)}
          <h6 class="mb-0 fw-bold">نتيجة تتبع الرابط</h6>
        </div>
        ${scoreBadge(level)}
      </div>

      <div class="p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        ${renderKeyValue("الرابط الأصلي", d.original_url || url, "ltr")}
        ${renderKeyValue("الوجهة النهائية", d.final_url || "-", "ltr")}
        ${renderKeyValue("عدد التحويلات", d.redirect_count ?? chain.length)}
        ${renderKeyValue("Status Code", d.status_code ?? "-")}
      </div>

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-warning mb-2">
          <i class="fas fa-route"></i>
          مسار التحويل
        </h6>
        <ol class="mb-0 ps-3 font-monospace text-secondary" dir="ltr" style="font-size: 13px;">
          ${chain.map(c => `<li class="text-break">${fileEscapeHtml(c)}</li>`).join("")}
        </ol>
      </div>

      <div class="mt-3 p-3 rounded" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        <h6 class="fw-bold text-info mb-2">
          <i class="fas fa-note-sticky"></i>
          الملاحظات
        </h6>
        ${renderList(d.notes, "لا توجد ملاحظات.")}
      </div>
    `;

    setResult("expandUrlResult", html, riskClass(level));
    await refreshHistory();
  } catch (e) {
    setResult("expandUrlResult", toolError(e.message), "danger");
  }
}

async function analyzeHeaders() {
  const url = normalizeUrl(document.getElementById("headerUrlInput")?.value);

  if (!url) {
    return setResult("headerAnalyzerResult", `<div class="alert alert-warning mb-0">أدخل الرابط.</div>`, "warning");
  }

  setLoading("headerAnalyzerResult", "جاري تحليل Security Headers");

  try {
    const d = await postJson("/api/header-analyzer", {url});
    const level = d.level || "Info";
    const headers = normalizeHeaderList(d.headers);

    const headersRows = headers.length ? headers.map(h => `
      <tr style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <td class="fw-bold font-monospace">${fileEscapeHtml(h.header)}</td>
        <td>
          ${h.present || h.status === "Secure"
            ? '<span class="badge bg-success">موجود</span>'
            : '<span class="badge bg-danger">مفقود</span>'}
        </td>
        <td class="text-break text-secondary" dir="ltr">${fileEscapeHtml(h.value || "Not Set")}</td>
      </tr>
    `).join("") : `
      <tr>
        <td colspan="3" class="text-center text-muted py-3">لم يتم إرجاع قائمة Headers من الخادم.</td>
      </tr>
    `;

    const html = `
      <div class="d-flex justify-content-between align-items-center mb-2 border-bottom pb-2" style="border-color: var(--set-border, rgba(148,163,184,.18)) !important;">
        <div>
          <h6 class="mb-1 fw-bold text-primary">
            <i class="fas fa-server"></i>
            Server Security Headers
          </h6>
          <small class="text-muted" dir="ltr">${fileEscapeHtml(d.final_url || d.url || url)}</small>
        </div>
        ${scoreBadge(level)}
      </div>

      <div class="p-3 rounded mt-3" style="background: var(--set-bg-soft, rgba(148,163,184,.08)); border: 1px solid var(--set-border, rgba(148,163,184,.18));">
        ${renderKeyValue("Score", `${d.score ?? 0}%`)}
        ${renderKeyValue("Status Code", d.status_code ?? "-")}
        ${renderKeyValue("Server", d.server || "Unknown", "ltr")}
        ${renderKeyValue("X-Powered-By", d.x_powered_by || "Not Disclosed", "ltr")}
      </div>

      ${createProgressBar(d.score, level)}

      <div class="table-responsive mt-3">
        <table class="table table-sm align-middle" style="color: var(--set-text, inherit); font-size: 13px;">
          <thead>
            <tr>
              <th>Header</th>
              <th>Status</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>${headersRows}</tbody>
        </table>
      </div>
    `;

    setResult("headerAnalyzerResult", html, riskClass(level));
    await refreshHistory();
  } catch (e) {
    setResult("headerAnalyzerResult", toolError(e.message), "danger");
  }
}


/* ==========================================================================
   7) TRAINING SCENARIOS / LEGACY CLONE PAGE
   ========================================================================== */

async function cloneSite() {
  const box = document.getElementById("cloneResult");
  const urlInput = document.getElementById("cloneUrl");
  const nameInput = document.getElementById("cloneName");

  if (!box) return;

  const url = urlInput ? urlInput.value.trim() : "";
  const name = nameInput ? nameInput.value.trim() : "";

  if (!url || !name) {
    box.innerHTML = `<div class="alert alert-warning">أدخل الرابط واسم السيناريو.</div>`;
    return;
  }

  box.innerHTML = "جاري إنشاء السيناريو التدريبي...";

  try {
    const d = await postJson("/api/clone-site", {url, name});

    if (d.success) {
      box.innerHTML = `
        <div class="alert alert-success">
          تم الإنشاء:
          <a target="_blank" href="${fileEscapeHtml(d.url || "#")}">${fileEscapeHtml(d.clone_name || name)}</a>
        </div>
      `;
    } else {
      box.innerHTML = `<div class="alert alert-danger">${fileEscapeHtml(d.error || "فشل الإنشاء")}</div>`;
    }

    await refreshStats();
  } catch (e) {
    box.innerHTML = toolError(e.message);
  }
}


/* ==========================================================================
   8) INIT
   ========================================================================== */

document.addEventListener("DOMContentLoaded", function () {
  refreshStats();

  const toolsEl = document.getElementById("statTools");
  if (toolsEl) {
    toolsEl.textContent = "10+";
    toolsEl.setAttribute("dir", "ltr");
    toolsEl.style.direction = "ltr";
    toolsEl.style.unicodeBidi = "isolate";
  }
});

/* تحميل أولي مع fallback للصفحات القديمة */
refreshStats();
