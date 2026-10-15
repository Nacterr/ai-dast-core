import json
import re
from pathlib import Path
from app.artex_web import BACKEND, load_llm_pool, ARTEX_HTML

def build_github_pages_html():
    raw_tasks = BACKEND.list_tasks()[:4]
    
    demo_targets = [
        ("scan_shop_01", "http://testphp.vulnweb.com", "Demo Shop E-Commerce Target"),
        ("scan_api_02", "https://api.staging-store.io", "FinTech Cloud API Gateway"),
        ("scan_auth_03", "https://auth.internal-corp.net", "Corporate Identity & SSO Portal"),
        ("scan_crm_04", "https://crm.cloud-enterprise.tech", "Customer Portal & CRM"),
    ]
    
    for idx, (sid, starget, sdesc) in enumerate(demo_targets):
        if idx < len(raw_tasks):
            t = raw_tasks[idx]
            t["id"] = sid
            t["target"] = starget
            t["summary"] = f"{sdesc} · Quét bảo mật toàn diện phát hiện {t.get('findings_count', 0)} lỗ hổng."
            for f in t.get("findings", []):
                if "127.0.0.1" in str(f.get("url", "")):
                    f["url"] = f.get("url", "").replace("http://127.0.0.1:8099", starget)
                if "127.0.0.1" in str(f.get("location", "")):
                    f["location"] = f.get("location", "").replace("http://127.0.0.1:8099", starget)
            for h in t.get("http_history", []):
                if "127.0.0.1" in str(h.get("requested_url", "")):
                    h["requested_url"] = h.get("requested_url", "").replace("http://127.0.0.1:8099", starget)

    pool = load_llm_pool()
    initial_state = {
        "tasks": raw_tasks,
        "llm_pool": pool,
    }

    # Prepare top announcement banner
    demo_banner = """
<!-- WEB DEMO HEADER BANNER -->
<div style="background: linear-gradient(90deg, #1e1b4b, #312e81, #0f172a); color: #e0e7ff; padding: 9px 20px; font-size: 12.5px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #4338ca; z-index: 999;">
  <div style="display: flex; align-items: center; gap: 10px;">
    <span style="background: #4f46e5; color: #ffffff; font-weight: 800; font-size: 10.5px; padding: 2px 7px; border-radius: 4px; letter-spacing: 0.5px;">LIVE DEMO (GITHUB PAGES)</span>
    <span>⚡ <b>Trải nghiệm ARTEX AI DAST Console trực tiếp trên trình duyệt</b> — Tương tác 100% không cần tải hay cài đặt môi trường.</span>
  </div>
  <div style="display: flex; align-items: center; gap: 14px;">
    <a href="https://github.com/Nacterr/ai-dast-core" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: 700; display: inline-flex; align-items: center; gap: 5px;">
      ⭐ Star trên GitHub →
    </a>
  </div>
</div>
"""

    html = ARTEX_HTML
    # Insert demo banner right after <body>
    html = html.replace("<body>", "<body>\n" + demo_banner)

    # Prepare client-side mock logic script to inject before </script>
    client_mock_script = f"""
// ---------------------------------------------------------------------------
// Client-side Interactive Engine for GitHub Pages (Zero-Server Architecture)
// ---------------------------------------------------------------------------
const EMBEDDED_STATE = {json.dumps(initial_state, ensure_ascii=False)};

function updateBadges() {{
  document.getElementById('badge-tasks').textContent = STATE.tasks.length;
  const totalVulns = STATE.tasks.reduce((acc, t) => acc + (t.findings_count || 0), 0);
  document.getElementById('badge-vulns').textContent = totalVulns;
  document.getElementById('badge-llm').textContent = (STATE.llm_pool.models || []).length;
}}

function saveStateLocally() {{
  try {{
    localStorage.setItem('ai_dast_artex_state', JSON.stringify(STATE));
  }} catch (e) {{}}
}}

async function refreshState() {{
  try {{
    if (window.location.protocol.startsWith('http') && (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') && window.location.port === '8788') {{
      const res = await fetch('/api/state');
      if (res.ok) {{
        STATE = await res.json();
        updateBadges();
        if (!SELECTED_TASK_ID && STATE.tasks.length > 0) SELECTED_TASK_ID = STATE.tasks[0].id;
        renderCurrentPage();
        return;
      }}
    }}
  }} catch (e) {{}}

  const saved = localStorage.getItem('ai_dast_artex_state');
  if (saved) {{
    try {{
      STATE = JSON.parse(saved);
    }} catch (e) {{
      STATE = JSON.parse(JSON.stringify(EMBEDDED_STATE));
    }}
  }} else {{
    STATE = JSON.parse(JSON.stringify(EMBEDDED_STATE));
  }}
  updateBadges();
  if (!SELECTED_TASK_ID && STATE.tasks.length > 0) {{
    SELECTED_TASK_ID = STATE.tasks[0].id;
  }}
  renderCurrentPage();
}}

async function startScan(kind) {{
  const target = kind === 'demo' ? 'http://testphp.vulnweb.com' : (document.getElementById('quick-target').value.trim() || 'https://staging.example.com');
  const mode = document.getElementById('quick-mode').value;

  try {{
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {{
      const res = await fetch('/api/scan', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ target, mode }})
      }});
      if (res.ok) {{
        const data = await res.json();
        await refreshState();
        if (data.scan_id) {{
          SELECTED_TASK_ID = data.scan_id;
          navigate('task-detail', data.scan_id);
        }}
        return;
      }}
    }}
  }} catch (e) {{}}

  showModal(`
    <h3 style="margin-bottom:10px;">🚀 Đang Khởi Chạy Chiến Dịch Quét Mới...</h3>
    <div style="font-size:13px;color:var(--muted);margin-bottom:12px;">Mục tiêu: <b>${{esc(target)}}</b> (${{mode === 'ai' ? '🤖 AI Planner (LLM Pool)' : '⚡ Scripted Recon Pro'}})</div>
    <div style="background:#0b1324;border:1px solid #1e293b;border-radius:6px;padding:12px;font-family:Consolas,monospace;font-size:11.5px;color:#38bdf8;" id="scan-term-log">
      > [1/4] Khởi tạo ScopePolicy & Giám sát Sandbox...<br>
    </div>
  `);

  const term = document.getElementById('scan-term-log');
  await new Promise(r => setTimeout(r, 600));
  if (term) term.innerHTML += '> [2/4] Thực thi Discovery: Quét sơ đồ trang, DNS, robots.txt, sitemap...<br>';
  await new Promise(r => setTimeout(r, 700));
  if (term) term.innerHTML += '> [3/4] Chạy Passive Checks & Phân tích Gói tin HTTP...<br>';
  await new Promise(r => setTimeout(r, 700));
  if (term) term.innerHTML += '> [4/4] AI Planner kích hoạt: Đánh giá bề mặt tấn công & tổng hợp lỗ hổng...<br>';
  await new Promise(r => setTimeout(r, 600));

  const newId = 'scan_' + Math.floor(Date.now() / 1000);
  const sampleTask = JSON.parse(JSON.stringify(EMBEDDED_STATE.tasks[0] || {{}}));
  sampleTask.id = newId;
  sampleTask.target = target;
  sampleTask.planner = (mode === 'ai' ? 'ai-planner-v3-groq' : 'scripted-recon-v2');
  sampleTask.started_at = new Date().toISOString().replace('T', ' ').substring(0, 19);
  sampleTask.summary = `Chiến dịch quét tự động cho ${{target}}. Hoàn tất phân tích và phát hiện ${{sampleTask.findings_count || 18}} lỗ hổng bảo mật.`;

  STATE.tasks.unshift(sampleTask);
  saveStateLocally();
  closeModal();
  SELECTED_TASK_ID = newId;
  SELECTED_TASK_TAB = 'overview';
  await refreshState();
  navigate('task-detail', newId);
}}

async function triggerRetest(url, category, title) {{
  showModal(`
    <h3 style="margin-bottom:10px;">🔄 Đang Kiểm Tra Lại Lỗ Hổng (Live Retest)...</h3>
    <p style="color:var(--muted);font-size:13px;margin-bottom:14px;">Đang gửi gói tin thẩm định trực tiếp tới <code>${{esc(url)}}</code>...</p>
  `);

  try {{
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {{
      const res = await fetch('/api/retest', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ url, category, title }})
      }});
      if (res.ok) {{
        const data = await res.json();
        renderRetestModal(data);
        return;
      }}
    }}
  }} catch (e) {{}}

  await new Promise(r => setTimeout(r, 650));
  const isFixed = title.toLowerCase().includes('csrf') || title.toLowerCase().includes('trace');
  const simResult = {{
    ok: true,
    url: url,
    tool: 'check_probe_retest',
    elapsed_ms: Math.floor(Math.random() * 80) + 95,
    still_vulnerable: !isFixed,
    verdict: !isFixed ? "🔴 VẪN TỒN TẠI LỖ HỔNG (REPRODUCED)" : "🟢 ĐÃ KHẮC PHỤC / KHÔNG TÁI HIỆN (FIXED)",
    detail: `Hệ thống đã gửi probe thẩm định trực tiếp đến ${{url}}. Máy chủ phản hồi mã 200 OK với cơ chế lỗ hổng xác nhận.`
  }};
  renderRetestModal(simResult);
}}

function renderRetestModal(data) {{
  showModal(`
    <h3 style="margin-bottom:10px;">🔬 Kết Quả Kiểm Tra Lại (Vulnerability Retest)</h3>
    <div style="margin-bottom:12px; font-weight:800; font-size:15px; color:${{data.still_vulnerable ? '#f43f5e' : '#10b981'}};">
      ${{esc(data.verdict || '')}}
    </div>
    <p style="font-size:13px; margin-bottom:10px;"><b>URL:</b> <code>${{esc(data.url || '')}}</code></p>
    <p style="font-size:13px; margin-bottom:10px;"><b>Công cụ kiểm chứng:</b> <code>${{esc(data.tool || 'check_headers')}}</code> (${{data.elapsed_ms || 0}} ms)</p>
    <p style="font-size:13px; color:var(--muted); margin-bottom:16px;">${{esc(data.detail || '')}}</p>
    <div style="text-align:right;">
      <button class="btn btn-primary" onclick="closeModal()">Đóng</button>
    </div>
  `);
}}

function getSimulatedAiPatch(cat, title) {{
  const cl = (cat + ' ' + title).toLowerCase();
  if (cl.includes('sql') || cl.includes('injection')) {{
    return `# Python (Prepared Statement with SQLAlchemy / psycopg2):\\ncursor.execute("SELECT id, name FROM users WHERE id = %s", (user_id,))\\n\\n# PHP (PDO Parameterized Query):\\n$stmt = $pdo->prepare('SELECT id, name FROM users WHERE id = :id');\\n$stmt->execute(['id' => $userId]);`;
  }}
  if (cl.includes('cors')) {{
    return `# Nginx Configuration:\\nadd_header 'Access-Control-Allow-Origin' 'https://trusted-domain.com' always;\\nadd_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;\\nadd_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;`;
  }}
  if (cl.includes('cookie') || cl.includes('session')) {{
    return `# Python (Flask / FastAPI Secure Cookies):\\nresponse.set_cookie(key="session", value=token, secure=True, httponly=True, samesite="Lax")\\n\\n# PHP Session Security:\\nsession_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);`;
  }}
  return `# Nginx Security Headers (Strict HSTS & CSP):\\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\\nadd_header X-Content-Type-Options "nosniff" always;\\nadd_header X-Frame-Options "DENY" always;\\nadd_header Content-Security-Policy "default-src 'self';" always;`;
}}

async function triggerAiAnalyzeFinding(url, category, title, severity, cwe, owasp) {{
  showModal(`
    <h3 style="margin-bottom:10px;">🤖 AI Đang Phân Tích Chuyên Sâu & Sinh Code Vá Lỗi...</h3>
    <p style="color:var(--muted);font-size:13px;">Lỗ hổng: <b>${{esc(title)}}</b> tại <code>${{esc(url)}}</code></p>
  `);

  try {{
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {{
      const res = await fetch('/api/ai_analyze', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{
          finding: {{ url, location: url, category, title, severity, cwe, owasp }}
        }})
      }});
      if (res.ok) {{
        const data = await res.json();
        renderAiFindingModal(url, category, title, severity, cwe, owasp, data.analysis || {{}});
        return;
      }}
    }}
  }} catch (e) {{}}

  await new Promise(r => setTimeout(r, 450));
  const simAnalysis = {{
    engine: "ARTEX AI Deep Dive (Llama-3.3-70b via LLM Pool)",
    latency_ms: Math.floor(Math.random() * 120) + 210,
    root_cause: `Ứng dụng tại ${{url}} chưa áp dụng kiểm tra nghiêm ngặt đối với ${{category}} (${{cwe || 'CWE'}}) dẫn đến nguy cơ vượt qua lớp kiểm soát an toàn.`,
    exploit_scenario: `Kẻ tấn công có thể gửi các gói tin đặc chế nhắm vào tham số liên quan để khai thác lỗ hổng ${{title}}, gây rò rỉ dữ liệu hoặc thay đổi hành vi xử lý của hệ thống.`,
    llm_advice: `Khuyến nghị ưu tiên xử lý trong vòng 48h. Cần kết hợp thẩm định tự động với xác thực phân quyền ở cấp độ backend controller.`,
    code_patch: getSimulatedAiPatch(category, title),
  }};
  renderAiFindingModal(url, category, title, severity, cwe, owasp, simAnalysis);
}}

function renderAiFindingModal(url, category, title, severity, cwe, owasp, a) {{
  showModal(`
    <div style="max-height:78vh;overflow-y:auto;padding-right:6px;">
      <h3 style="margin-bottom:8px;color:var(--accent);">🤖 AI Phân Tích Lỗ Hổng & Hướng Dẫn Vá Lỗi</h3>
      <div style="margin-bottom:10px;">
        <span class="sev sev-${{String(severity||'INFO').toUpperCase()}}">${{esc(severity)}}</span>
        <b style="margin-left:8px;font-size:14px;">${{esc(title)}}</b>
        <div style="font-size:11.5px;color:var(--muted);margin-top:4px;">📍 <code>${{esc(url)}}</code> · Engine: <b>${{esc(a.engine || 'AI Security Analyst')}}</b> (${{a.latency_ms || 180}} ms)</div>
      </div>
      <div style="background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.3);border-radius:8px;padding:10px;margin-bottom:10px;font-size:12.5px;">
        <b style="color:var(--accent);">🔍 Nguyên nhân gốc rễ (Root Cause):</b><br>${{esc(a.root_cause || '')}}
      </div>
      <div style="background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.3);border-radius:8px;padding:10px;margin-bottom:10px;font-size:12.5px;">
        <b style="color:var(--danger);">⚠️ Cơ chế Rủi ro (Risk Mechanism):</b><br>${{esc(a.exploit_scenario || '')}}
      </div>
      ${{a.llm_advice ? `<div style="background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.35);border-radius:8px;padding:10px;margin-bottom:10px;font-size:12.5px;white-space:pre-line;"><b style="color:var(--purple);">🧠 Nhận định từ LLM Pool:</b>\\n${{esc(a.llm_advice)}}</div>` : ''}}
      <div style="margin-bottom:12px;">
        <b style="color:var(--success);font-size:12.5px;">🛠️ Mẫu Code / Cấu Hình Vá Lỗi Đề Xuất (Remediation Patch):</b>
        <pre style="margin-top:6px;background:#070a12;color:#6ee7b7;padding:10px;border-radius:6px;border:1px solid #065f46;font-size:11.5px;">${{esc(a.code_patch || '')}}</pre>
      </div>
      <div style="text-align:right;">
        <button class="btn btn-primary" onclick="closeModal()">Đóng</button>
      </div>
    </div>
  `);
}}

async function updateLlmPool(action, payload = {{}}) {{
  try {{
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {{
      const res = await fetch('/api/llm/pool', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ action, ...payload }})
      }});
      if (res.ok) {{
        await refreshState();
        return;
      }}
    }}
  }} catch (e) {{}}

  if (action === 'toggle' && payload.model_id) {{
    const m = (STATE.llm_pool.models || []).find(x => x.id === payload.model_id);
    if (m) m.enabled = !m.enabled;
  }} else if (action === 'toggle_rr') {{
    STATE.llm_pool.round_robin = !STATE.llm_pool.round_robin;
  }} else if (action === 'add' && payload.model) {{
    STATE.llm_pool.models.push(payload.model);
  }} else if (action === 'delete' && payload.model_id) {{
    STATE.llm_pool.models = (STATE.llm_pool.models || []).filter(x => x.id !== payload.model_id);
  }}
  saveStateLocally();
  await refreshState();
}}
"""

    # Inject client_mock_script right before </script>
    html = html.replace("</script>", client_mock_script + "\n</script>")
    
    docs_dir = Path("docs")
    docs_dir.mkdir(exist_ok=True)
    out_file = docs_dir / "index.html"
    out_file.write_text(html, encoding="utf-8")
    print(f"✅ Generated {out_file} ({round(len(html)/1024, 1)} KB)")

if __name__ == "__main__":
    build_github_pages_html()
