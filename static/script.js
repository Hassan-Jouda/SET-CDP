function badge(level){const map={Secure:'success',Valid:'success',Safe:'success',Strong:'success',Medium:'warning',Moderate:'warning',Suspicious:'warning','Expiring Soon':'warning',Insecure:'danger',Weak:'danger',Error:'danger','High Risk':'danger'};return map[level]||'secondary'}
function showError(box,msg){box.innerHTML=`<div class="alert alert-danger">${msg}</div>`}
function renderWebsiteResult(d){if(d.error)return `<div class="alert alert-danger">${d.error}</div>`;let headers=d.headers||{};return `<div class="result-card"><div class="d-flex justify-content-between"><h5>نتيجة فحص الموقع</h5><span class="badge bg-${badge(d.level)}">${d.level}</span></div><div class="score-number">${d.score}%</div><div class="progress mb-3"><div class="progress-bar bg-${badge(d.level)}" style="width:${d.score}%"></div></div><p><b>HTTPS:</b> ${d.https?'✅ مفعل':'❌ غير مفعل'}</p><p><b>Status:</b> ${d.status_code||'-'}</p><h6>Security Headers</h6><ul class="clean-list">${Object.entries(headers).map(([n,h])=>`<li>${h.present?'✅':'❌'} <b>${n}</b><small>${h.value||'Not Set'}</small></li>`).join('')}</ul>${(d.missing||[]).length?`<div class="alert alert-warning mt-2"><b>Headers مفقودة:</b> ${d.missing.join(', ')}</div>`:''}</div>`}
function renderSSLResult(d){if(d.error)return `<div class="alert alert-danger">${d.error}</div>`;return `<div class="result-card"><div class="d-flex justify-content-between"><h5>نتيجة SSL</h5><span class="badge bg-${badge(d.status)}">${d.status}</span></div><p><b>Domain:</b> ${d.domain}</p><p><b>Issuer:</b> ${d.issuer||'-'}</p><p><b>Expires:</b> ${d.expires}</p><p><b>Days left:</b> ${d.days_left} يوم</p></div>`}
function renderPasswordResult(d){return `<div class="result-card"><div class="d-flex justify-content-between"><h5>تحليل كلمة المرور</h5><span class="badge bg-${badge(d.strength)}">${d.strength}</span></div><div class="progress mb-3"><div class="progress-bar bg-${badge(d.strength)}" style="width:${d.score}%"></div></div><p><b>Score:</b> ${d.score}%</p><ul class="clean-list">${(d.feedback||[]).map(x=>`<li>${x}</li>`).join('')}</ul></div>`}
function renderEmailResult(d){return `<div class="result-card"><div class="d-flex justify-content-between"><h5>تحليل التصيد</h5><span class="badge bg-${badge(d.risk)}">${d.risk}</span></div><p><b>Score:</b> ${d.score}/10</p><h6>المؤشرات</h6><ul class="clean-list">${(d.findings||[]).map(x=>`<li>${x}</li>`).join('')}</ul></div>`}
function renderFileResult(d){if(d.error)return `<div class="alert alert-danger">${d.error}</div>`;return `<div class="result-card"><h5>تحليل الملف</h5><p><b>Filename:</b> ${d.filename}</p><p><b>Type:</b> ${d.file_type}</p><p><b>Size:</b> ${d.size} bytes</p><h6>Hashes</h6><div class="hash-box">MD5: ${d.hashes?.md5||'-'}</div><div class="hash-box">SHA1: ${d.hashes?.sha1||'-'}</div><div class="hash-box">SHA256: ${d.hashes?.sha256||'-'}</div>${Object.keys(d.metadata||{}).length?`<h6 class="mt-2">Metadata</h6><ul class="clean-list">${Object.entries(d.metadata).map(([k,v])=>`<li><b>${k}:</b> ${v}</li>`).join('')}</ul>`:''}${(d.warnings||[]).length?`<div class="alert alert-warning mt-2">${d.warnings.join('<br>')}</div>`:''}</div>`}
function renderUrlResult(d){return `<div class="result-card"><div class="d-flex justify-content-between"><h5>فحص الرابط</h5><span class="badge bg-${badge(d.level)}">${d.level}</span></div><div class="score-number">${d.score}%</div><div class="progress mb-3"><div class="progress-bar bg-${badge(d.level)}" style="width:${d.score}%"></div></div><ul class="clean-list">${(d.issues||[]).map(x=>`<li>${x}</li>`).join('')}</ul></div>`}
async function loadStats(){let r=await fetch('/api/get-stats');let d=await r.json();document.getElementById('statCaptures')&&(statCaptures.textContent=d.total_captures);document.getElementById('statClones')&&(statClones.textContent=d.total_clones);document.getElementById('statScans')&&(statScans.textContent=d.total_scans)}
async function scanWebsite(){let box=scanResult;box.innerHTML='جاري الفحص...';let r=await fetch('/api/scan-website',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:scanUrl.value})});let d=await r.json();box.innerHTML=renderWebsiteResult(d);loadStats()}
async function checkSSL(){let box=sslResult;box.innerHTML='جاري فحص SSL...';let r=await fetch('/api/ssl-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:sslDomain.value})});let d=await r.json();box.innerHTML=renderSSLResult(d);loadStats()}
async function checkPassword(){let r=await fetch('/api/check-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:passwordInput.value})});passwordResult.innerHTML=renderPasswordResult(await r.json())}
async function checkEmail(){let r=await fetch('/api/check-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:emailInput.value})});emailResult.innerHTML=renderEmailResult(await r.json());loadStats()}
async function analyzeFile(){if(!fileInput.files[0]){fileResult.innerHTML='<div class="alert alert-warning">اختر ملف أولاً</div>';return}let fd=new FormData();fd.append('file',fileInput.files[0]);let r=await fetch('/api/analyze-file',{method:'POST',body:fd});fileResult.innerHTML=renderFileResult(await r.json());loadStats()}
async function checkURL(){let r=await fetch('/api/check-url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:urlCheckInput.value})});urlResult.innerHTML=renderUrlResult(await r.json());loadStats()}
async function loadHistory(){let box=document.getElementById('historyResult');if(!box)return;box.innerHTML='Loading...';let r=await fetch('/api/history');let d=await r.json();if(!d.length){box.innerHTML='<div class="alert alert-info">لا يوجد سجل حتى الآن</div>';return}box.innerHTML=`<div class="table-responsive"><table class="table table-sm table-bordered history-table"><thead><tr><th>النوع</th><th>الهدف</th><th>النتيجة</th><th>المستوى</th><th>الوقت</th></tr></thead><tbody>${d.map(x=>`<tr><td>${x.scan_type}</td><td>${x.target}</td><td>${x.result_summary||'-'}</td><td>${x.risk_level||'-'}</td><td>${x.timestamp}</td></tr>`).join('')}</tbody></table></div>`}
async function clearHistory(){if(!confirm('هل تريد مسح السجل؟'))return;await fetch('/api/history/clear',{method:'DELETE'});loadHistory();loadStats()}
async function cloneSite(){let box=document.getElementById('cloneResult');box.innerHTML='جاري إنشاء النسخة...';let r=await fetch('/api/clone-site',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:cloneUrl.value,name:cloneName.value})});let d=await r.json();box.innerHTML=d.success?`<div class="alert alert-success">تم الإنشاء: <a target="_blank" href="${d.url}">${d.clone_name}</a></div>`:`<div class="alert alert-danger">${d.error}</div>`;loadStats()}
async function deleteCapture(id){await fetch('/api/delete-captured/'+id,{method:'DELETE'});location.reload()}
async function deleteClone(name){await fetch('/api/delete-clone/'+name,{method:'DELETE'});location.reload()}
loadStats();
async function generatePassword() {
    const length = document.getElementById("genLength").value || 16;
    const box = document.getElementById("generatedPasswordResult");

    box.innerHTML = "جاري التوليد...";

    const res = await fetch("/api/generate-password", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            length: parseInt(length),
            upper: true,
            lower: true,
            digits: true,
            symbols: true
        })
    });

    const data = await res.json();

    if (data.error) {
        box.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }

    box.innerHTML = `
        <div class="result-card">
            <h5>كلمة المرور المولدة</h5>
            <div class="hash-box" id="generatedPasswordText">${data.password}</div>
            <button class="btn btn-sm btn-outline-success" onclick="copyGeneratedPassword()">
                نسخ
            </button>
        </div>
    `;

    loadStats();
}

function copyGeneratedPassword() {
    const text = document.getElementById("generatedPasswordText").innerText;
    navigator.clipboard.writeText(text);
    alert("تم النسخ");
}


async function expandUrl() {
    const url = document.getElementById("expandUrlInput").value;
    const box = document.getElementById("expandUrlResult");

    box.innerHTML = "جاري فك الرابط...";

    const res = await fetch("/api/expand-url", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({url})
    });

    const data = await res.json();

    if (data.error) {
        box.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }

    box.innerHTML = `
        <div class="result-card">
            <div class="d-flex justify-content-between">
                <h5>نتيجة URL Expander</h5>
                <span class="badge bg-${data.risk === "Safe" ? "success" : "warning"}">${data.risk}</span>
            </div>

            <p><b>Original:</b> ${data.original_url}</p>
            <p><b>Final:</b> ${data.final_url}</p>
            <p><b>Redirects:</b> ${data.redirect_count}</p>

            <h6>Redirect Chain</h6>
            <ul class="clean-list">
                ${data.chain.map(x => `<li>${x}</li>`).join("")}
            </ul>

            <div class="alert alert-info mt-2">
                ${data.notes.join("<br>")}
            </div>
        </div>
    `;

    loadStats();
}


async function analyzeHeaders() {
    const url = document.getElementById("headerUrlInput").value;
    const box = document.getElementById("headerAnalyzerResult");

    box.innerHTML = "جاري تحليل الهيدرز...";

    const res = await fetch("/api/header-analyzer", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({url})
    });

    const data = await res.json();

    if (data.error) {
        box.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        return;
    }

    const color =
        data.level === "Secure" ? "success" :
        data.level === "Moderate" ? "warning" :
        "danger";

    box.innerHTML = `
        <div class="result-card">
            <div class="d-flex justify-content-between">
                <h5>Header Security Analyzer</h5>
                <span class="badge bg-${color}">${data.level}</span>
            </div>

            <div class="score-box">
                <div class="score-number">${data.score}%</div>
                <div class="progress">
                    <div class="progress-bar bg-${color}" style="width:${data.score}%"></div>
                </div>
            </div>

            <p><b>URL:</b> ${data.url}</p>
            <p><b>Final URL:</b> ${data.final_url}</p>

            <h6>Headers</h6>
            <ul class="clean-list">
                ${data.headers.map(h => `
                    <li>
                        ${h.present ? "✅" : "❌"}
                        <b>${h.header}</b>
                        <small>${h.value}</small>
                        <small>${h.recommendation}</small>
                    </li>
                `).join("")}
            </ul>
        </div>
    `;

    loadStats();
}