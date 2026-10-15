"""AI Post-Scan Security Result Analyzer (AI Deep Dive & Executive Security Advisor).

Analyzes the completed scan results (findings, attack surface, technologies, HTTP exchanges,
observed facts, and hints) to produce:
1. Overall Security Posture Score (0-100) & Risk Rating
2. Multi-step Attack Chain / Kill-Chain Correlation (how findings combine in real attacks)
3. Root-Cause & Business/Technical Impact Assessment
4. Prioritized Remediation Roadmap with stack-specific code/config patches
5. Deep-dive AI analysis for any individual finding

Uses the active LLM Pool (Groq / OpenAI / Anthropic / DeepSeek) with automatic Circuit Breaker
failover, and includes a comprehensive deterministic Expert Security Engine fallback so
detailed Vietnamese analysis is always available even offline.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from dotenv import load_dotenv

load_dotenv()


def compute_security_score(findings: list[Any]) -> dict[str, Any]:
    """Calculate a 0-100 security posture score and risk rating from scan findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        if isinstance(f, dict):
            sev = str(f.get("severity") or "INFO").upper()
        else:
            s_obj = getattr(f, "severity", "INFO")
            sev = s_obj.name.upper() if hasattr(s_obj, "name") else str(s_obj).upper()
        counts[sev] = counts.get(sev, 0) + 1

    # Deduction model: Critical=-30, High=-18, Medium=-8, Low=-3, Info=-0.5
    deduction = (
        counts["CRITICAL"] * 30
        + counts["HIGH"] * 18
        + counts["MEDIUM"] * 8
        + counts["LOW"] * 3
        + min(10, counts["INFO"] * 1)
    )
    score = max(5, 100 - deduction) if sum(counts.values()) > 0 else 98

    if counts["CRITICAL"] > 0 or score < 40:
        grade = "F"
        rating = "NGUY KỊCH (CRITICAL RISK)"
        color = "#F43F5E"
    elif counts["HIGH"] > 0 or score < 65:
        grade = "D"
        rating = "RỦI RO CAO (HIGH RISK)"
        color = "#F97316"
    elif counts["MEDIUM"] > 0 or score < 82:
        grade = "C"
        rating = "RỦI RO TRUNG BÌNH (MEDIUM RISK)"
        color = "#EAB308"
    elif counts["LOW"] > 0 or score < 94:
        grade = "B"
        rating = "TƯƠNG ĐỐI AN TOÀN (LOW RISK)"
        color = "#38BDF8"
    else:
        grade = "A+"
        rating = "AN TOÀN TỐT (STRONG POSTURE)"
        color = "#10B981"

    return {
        "score": score,
        "grade": grade,
        "rating": rating,
        "color": color,
        "counts": counts,
        "total": sum(counts.values()),
    }


def _extract_finding_dict(f: Any) -> dict[str, Any]:
    if isinstance(f, dict):
        sev = str(f.get("severity") or "INFO").upper()
        cat = str(f.get("category") or "")
        return {
            "title": str(f.get("title") or ""),
            "severity": sev,
            "confidence": str(f.get("confidence") or "MEDIUM").upper(),
            "category": cat,
            "url": str(f.get("url") or ""),
            "location": str(f.get("location") or f.get("url") or ""),
            "description": str(f.get("description") or ""),
            "impact": str(f.get("impact") or ""),
            "recommendation": str(f.get("recommendation") or ""),
            "owasp": str(f.get("owasp") or ""),
            "cwe": str(f.get("cwe") or ""),
            "evidence": f.get("evidence") or [],
        }
    sev_obj = getattr(f, "severity", "INFO")
    sev = sev_obj.name.upper() if hasattr(sev_obj, "name") else str(sev_obj).upper()
    conf_obj = getattr(f, "confidence", "MEDIUM")
    conf = conf_obj.name.upper() if hasattr(conf_obj, "name") else str(conf_obj).upper()
    cat_obj = getattr(f, "category", "")
    cat = cat_obj.value if hasattr(cat_obj, "value") else str(cat_obj)
    ev_list = []
    for ev in getattr(f, "evidence", []) or []:
        ev_list.append({
            "tool": str(getattr(ev, "tool", "")),
            "url": str(getattr(ev, "url", "")),
            "location": str(getattr(ev, "location", "")),
            "observed": str(getattr(ev, "observed", "")),
            "expected": str(getattr(ev, "expected", "")),
        })
    return {
        "title": str(getattr(f, "title", "")),
        "severity": sev,
        "confidence": conf,
        "category": cat,
        "url": str(getattr(f, "url", "")),
        "location": str(getattr(f, "location", "") or getattr(f, "url", "")),
        "description": str(getattr(f, "description", "")),
        "impact": str(getattr(f, "impact", "")),
        "recommendation": str(getattr(f, "recommendation", "")),
        "owasp": str(getattr(f, "owasp", "")),
        "cwe": str(getattr(f, "cwe", "")),
        "evidence": ev_list,
    }


def _build_expert_fallback_analysis(
    target: str,
    f_dicts: list[dict[str, Any]],
    technologies: list[str],
    facts: list[str],
    hints: list[str],
    score_info: dict[str, Any],
) -> dict[str, Any]:
    """Build a rich, deterministic Vietnamese security analysis when LLM is offline or combined."""
    counts = score_info["counts"]
    tech_str = ", ".join(technologies) if technologies else "Web Server tiêu chuẩn (chưa lộ banner)"

    has_sqli = any("sql" in (f["title"] + " " + f["category"]).lower() for f in f_dicts)
    has_cors = any("cors" in (f["title"] + " " + f["category"]).lower() for f in f_dicts)
    has_files = any(
        any(k in (f["title"] + " " + f["location"]).lower() for k in ("exposed", ".env", ".git", "backup", "debug", "openapi"))
        for f in f_dicts
    )
    has_cookies = any("cookie" in (f["title"] + " " + f["category"]).lower() for f in f_dicts)
    has_headers = any("header" in (f["title"] + " " + f["category"] + " " + f["cwe"]).lower() or "csp" in f["title"].lower() for f in f_dicts)
    has_methods = any("method" in f["title"].lower() or "trace" in f["title"].lower() or "options" in f["title"].lower() for f in f_dicts)

    # 1. Executive Overview
    if score_info["total"] == 0:
        overview = (
            f"Qua quá trình rà quét tự động trên mục tiêu **{target}** (Công nghệ nhận diện: *{tech_str}*), "
            f"hệ thống không phát hiện lỗ hổng bảo mật nào có thể khai thác trực tiếp trên bề mặt công khai. "
            f"Điểm an ninh đạt **{score_info['score']}/100 ({score_info['grade']})**."
        )
    else:
        overview = (
            f"Chiến dịch kiểm thử trên **{target}** (Stack: *{tech_str}*) đã thu thập và xác thực **{score_info['total']} phát hiện bảo mật** "
            f"({counts['CRITICAL']} Critical, {counts['HIGH']} High, {counts['MEDIUM']} Medium, {counts['LOW']} Low, {counts['INFO']} Info). "
            f"Chỉ số an ninh tổng thể đạt **{score_info['score']}/100 — Xếp hạng {score_info['grade']} ({score_info['rating']})**."
        )

    # 2. Attack Chain / Correlation Scenarios
    attack_chains: list[str] = []
    if has_sqli:
        sqli_f = next(f for f in f_dicts if "sql" in (f["title"] + " " + f["category"]).lower())
        attack_chains.append(
            f"🔥 **Chuỗi tấn công #1 — Khai thác Cơ sở dữ liệu trực tiếp (SQL Injection Kill-Chain):** "
            f"Tại `{sqli_f['location']}`, tham số đầu vào được nối trực tiếp vào câu truy vấn SQL mà không qua Prepared Statement, "
            f"làm rò rỉ thông báo lỗi DB (`{sqli_f['cwe']}`). Kẻ tấn công có thể dùng kỹ thuật UNION-based hoặc Error/Boolean-based SQLi "
            f"để trích xuất toàn bộ bảng người dùng, mật khẩu băm và chiếm quyền điều khiển hệ thống."
        )
    if has_files:
        file_f = next(
            f for f in f_dicts
            if any(k in (f["title"] + " " + f["location"]).lower() for k in ("exposed", ".env", ".git", "backup", "debug", "openapi"))
        )
        attack_chains.append(
            f"📂 **Chuỗi tấn công #2 — Thu thập Thông tin Nhạy cảm & Leo thang Đặc quyền (`{file_f['location']}`):** "
            f"Tệp cấu hình/tài liệu nội bộ bị lộ công khai cho phép kẻ tấn công đọc biến môi trường, khoá bí mật (API Key / DB Credentials) "
            f"hoặc cấu trúc API ẩn mà không cần xác thực."
        )
    if has_cors:
        cors_f = next(f for f in f_dicts if "cors" in (f["title"] + " " + f["category"]).lower())
        attack_chains.append(
            f"🌐 **Chuỗi tấn công #3 — Đánh cắp Dữ liệu Liên nguồn (Cross-Origin Data Theft):** "
            f"Cấu hình CORS lỏng lẻo tại `{cors_f['location']}` cho phép trang web độc hại của bên thứ ba đọc phản hồi API "
            f"khi nạn nhân đang mở phiên làm việc."
        )
    if has_cookies or has_headers:
        attack_chains.append(
            f"🛡️ **Chuỗi tấn công #4 — Suy yếu Lớp Phòng thủ Trình duyệt (Client-Side Defense-in-Depth):** "
            f"Việc thiếu các HTTP Security Headers trọng yếu (như `Content-Security-Policy`, `X-Frame-Options`, `HSTS`) "
            f"kết hợp với cờ Cookie chưa chặt chẽ (`HttpOnly`, `Secure`, `SameSite`) làm tăng mức độ thiệt hại nếu ứng dụng xuất hiện lỗi XSS hoặc Clickjacking."
        )
    if has_methods:
        attack_chains.append(
            f"⚙️ **Chuỗi tấn công #5 — Dò tìm Phương thức HTTP & Vượt qua Kiểm soát Truy cập:** "
            f"Máy chủ phản hồi các phương thức kiểm tra (`OPTIONS` / `TRACE`), giúp kẻ tấn công lập bản đồ các phương thức được phép trên từng tuyến đường dẫn."
        )
    if not attack_chains:
        attack_chains.append(
            "✅ Không phát hiện chuỗi kết hợp lỗ hổng nguy hiểm nào có khả năng bị lợi dụng ngay lập tức."
        )

    # 3. Prioritized Remediation Roadmap & Code Patches
    remediations: list[dict[str, str]] = []
    if has_sqli:
        remediations.append({
            "priority": "KHẨN CẤP (24 GIỜ)",
            "title": "Vá triệt để lỗi SQL Injection bằng Parameterized Queries (Prepared Statements)",
            "detail": "Tuyệt đối không nối chuỗi trực tiếp từ biến `GET/POST` vào câu lệnh SQL. Tắt hiển thị chi tiết lỗi cơ sở dữ liệu ra môi trường Production.",
            "code": (
                "# Ví dụ khắc phục an toàn (Python / DB-API & SQLAlchemy):\n"
                "cursor.execute('SELECT id, name, price FROM products WHERE name LIKE %s', (f'%{q}%',))\n\n"
                "// Ví dụ khắc phục trong PHP (PDO Prepared Statement):\n"
                "$stmt = $pdo->prepare('SELECT id, name, price FROM products WHERE name LIKE :q');\n"
                "$stmt->execute(['q' => '%' . $q . '%']);"
            ),
        })
    if has_files:
        remediations.append({
            "priority": "KHẨN CẤP (24 GIỜ)",
            "title": "Chặn truy cập công khai tới các tệp nhạy cảm (.env, .git, backup, debug)",
            "detail": "Cấu hình Web Server từ chối mọi truy vấn bắt đầu bằng dấu chấm (`.`) hoặc các tệp cấu hình/sao lưu nội bộ.",
            "code": (
                "# Cấu hình Nginx chặn truy cập tệp ẩn (.env, .git) và tệp sao lưu:\n"
                "location ~ /\\.(?!well-known).* {\n"
                "    deny all;\n"
                "    access_log off;\n"
                "    log_not_found off;\n"
                "}"
            ),
        })
    if has_cors:
        remediations.append({
            "priority": "ƯU TIÊN CAO (1 - 3 NGÀY)",
            "title": "Siết chặt danh sách trắng (Allowlist) cho cấu hình CORS",
            "detail": "Không phản chiếu tuỳ ý header `Origin` của người dùng và không dùng `*` kèm `Access-Control-Allow-Credentials: true`.",
            "code": (
                "# Chỉ cho phép các tên miền Frontend tin cậy:\n"
                "ALLOWED_ORIGINS = {'https://app.example.com'}\n"
                "if request_origin in ALLOWED_ORIGINS:\n"
                "    response.headers['Access-Control-Allow-Origin'] = request_origin\n"
                "    response.headers['Vary'] = 'Origin'"
            ),
        })
    if has_headers or has_cookies:
        remediations.append({
            "priority": "NGẮN HẠN (3 - 7 NGÀY)",
            "title": "Bổ sung bộ HTTP Security Headers & Cờ Bảo mật Cookie chuẩn OWASP",
            "detail": "Thiết lập đầy đủ CSP, HSTS, X-Frame-Options, X-Content-Type-Options và gắn cờ `HttpOnly; Secure; SameSite=Lax` cho toàn bộ Session Cookie.",
            "code": (
                "# Cấu hình Security Headers chuẩn trên Nginx / Reverse Proxy:\n"
                "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n"
                "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none'; object-src 'none';\" always;\n"
                "add_header X-Frame-Options \"DENY\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                "proxy_cookie_path / \"/; HttpOnly; Secure; SameSite=Lax\";"
            ),
        })
    if not remediations:
        remediations.append({
            "priority": "DUY TRÌ ĐỊNH KỲ",
            "title": "Duy trì rà quét tự động CI/CD & Kiểm thử có xác thực",
            "detail": "Tiếp tục tích hợp quét DAST định kỳ sau mỗi lần triển khai phiên bản mới.",
            "code": "# Chạy quét tự động trong pipeline:\npython -m app.main scan https://target.example.com --active",
        })

    # 4. Next Investigation Steps
    next_steps = list(hints[:4]) if hints else []
    if not next_steps:
        next_steps = [
            "Thực hiện kiểm thử có xác thực (Authenticated Scan) để đánh giá phân quyền IDOR / Broken Access Control sau đăng nhập.",
            "Kiểm tra giới hạn tốc độ (Rate Limiting) và chống vét cạn (Brute-force) trên các biểu mẫu đăng nhập và tìm kiếm.",
            "Sử dụng tính năng 🔄 Kiểm tra lại (1-Click Retest) sau khi áp dụng các bản vá cấu hình ở trên.",
        ]

    return {
        "target": target,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "engine": "AI Security Analyst (Hybrid Expert Engine)",
        "latency_ms": 12,
        "score_info": score_info,
        "executive_summary": overview,
        "attack_chains": attack_chains,
        "remediations": remediations,
        "next_steps": next_steps,
        "llm_commentary": "",
    }


def analyze_scan_results(
    *,
    target: str,
    findings: list[Any],
    technologies: list[str] | None = None,
    facts: list[str] | None = None,
    hints: list[str] | None = None,
    http_count: int = 0,
    step_count: int = 0,
    use_llm: bool = True,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Analyze completed scan results using LLM Pool + Expert Security Engine."""
    f_dicts = [_extract_finding_dict(f) for f in (findings or [])]
    techs = list(technologies or [])
    facts_list = list(facts or [])
    hints_list = list(hints or [])
    score_info = compute_security_score(f_dicts)

    analysis = _build_expert_fallback_analysis(
        target=target,
        f_dicts=f_dicts,
        technologies=techs,
        facts=facts_list,
        hints=hints_list,
        score_info=score_info,
    )

    eff_key = (api_key or os.environ.get("DAST_API_KEY", "")).strip()
    if not use_llm or not eff_key:
        return analysis

    # Try calling the LLM Pool for custom AI Executive Commentary & Deep Insights
    from app.artex_web import load_llm_pool

    pool = load_llm_pool()
    pool_models = pool.get("models", [])
    prim = next((m for m in pool_models if m.get("is_primary") and m.get("status") != "circuit_broken"), None)
    eff_model = (model or (prim.get("model") if prim else None) or os.environ.get("DAST_MODEL", "llama-3.3-70b-versatile")).strip()
    eff_base = (base_url or (prim.get("base_url") if prim else None) or os.environ.get("DAST_BASE_URL", "https://api.groq.com/openai/v1")).strip()

    candidates = [eff_model]
    for m in pool_models:
        mid = str(m.get("model") or "")
        if mid and mid not in candidates and m.get("status") != "circuit_broken":
            candidates.append(mid)
    if "qwen/qwen3.8-27b" not in candidates:
        candidates.append("qwen/qwen3.8-27b")

    findings_brief = "\n".join(
        f"- [{f['severity']}] {f['title']} tại {f['location']} (OWASP: {f['owasp']}, CWE: {f['cwe']})"
        for f in f_dicts[:12]
    ) or "- Không phát hiện lỗ hổng nào."

    prompt = f"""Bạn là Chuyên gia Phân tích An ninh Mạng Cấp cao (Principal Penetration Tester & AI Security Advisor).
Hãy phân tích kết quả kiểm thử xâm nhập tự động (DAST) vừa hoàn tất dưới đây và viết nhận định chuyên sâu bằng tiếng Việt:

- Mục tiêu: {target}
- Công nghệ phát hiện: {', '.join(techs) or 'Chưa định danh'}
- Số bước công cụ đã chạy: {step_count} bước ({http_count} HTTP requests)
- Điểm an ninh tính toán: {score_info['score']}/100 ({score_info['rating']})
- Danh sách phát hiện ({len(f_dicts)} lỗi):
{findings_brief}

Hãy trả lời ngắn gọn, sắc bén (khoảng 150-220 từ, dùng gạch đầu dòng rõ ràng) gồm 3 ý:
1. Đánh giá thực chất mức độ rủi ro của mục tiêu này (phân biệt rõ lỗi có thể bị khai thác ngay như SQLi/Lộ file nhạy cảm với các lỗi cấu hình phòng thủ như thiếu Header/Cookie).
2. Kịch bản kẻ tấn công có thể lợi dụng các phát hiện này trong thực tế.
3. Khuyến nghị trọng tâm nhất dành cho đội ngũ kỹ thuật (DevSecOps) để xử lý triệt để.
"""

    try:
        from openai import OpenAI
        client = OpenAI(api_key=eff_key, base_url=eff_base or None)
        for cand_model in candidates[:2]:
            t0 = time.perf_counter()
            try:
                comp = client.chat.completions.create(
                    model=cand_model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=600,
                    temperature=0.2,
                )
                lat_ms = int((time.perf_counter() - t0) * 1000)
                text = (comp.choices[0].message.content or "").strip()
                if text:
                    analysis["llm_commentary"] = text
                    analysis["engine"] = f"AI LLM Pool ({cand_model})"
                    analysis["latency_ms"] = lat_ms
                    break
            except Exception:
                continue
    except Exception:
        pass

    return analysis


def analyze_single_finding(
    finding: Any,
    technologies: list[str] | None = None,
    use_llm: bool = True,
) -> dict[str, Any]:
    """Deep-dive AI analysis and remediation code generator for a single vulnerability finding."""
    f = _extract_finding_dict(finding)
    techs = ", ".join(technologies or []) or "Web Server / Application"
    ev_first = f["evidence"][0] if f["evidence"] else {}
    observed = ev_first.get("observed", "Không có")
    expected = ev_first.get("expected", "Cấu hình an toàn theo chuẩn OWASP")

    cat_lower = (f["title"] + " " + f["category"] + " " + f["cwe"]).lower()
    if "sql" in cat_lower:
        root_cause = (
            "Ứng dụng nhận dữ liệu từ tham số truy vấn URL và ghép nối trực tiếp vào câu lệnh SQL "
            "mà không sử dụng cơ chế truyền tham số an toàn (Parameterized Query / Prepared Statement), "
            "đồng thời trả trực tiếp thông báo lỗi của hệ quản trị CSDL về phía trình duyệt."
        )
        exploit_scenario = (
            "Kẻ tấn công truyền ký tự đặc biệt (`'`, `\"`, `OR 1=1--`, `UNION SELECT`) vào tham số trên URL "
            "để làm thay đổi cấu trúc logic câu lệnh SQL, từ đó trích xuất dữ liệu nhạy cảm trong DB."
        )
        code_patch = (
            "# Python (Prepared Statement):\n"
            "cursor.execute('SELECT * FROM products WHERE category = %s', (user_input,))\n\n"
            "// PHP (PDO Prepared Statement):\n"
            "$stmt = $pdo->prepare('SELECT * FROM products WHERE category = :cat');\n"
            "$stmt->execute(['cat' => $user_input]);"
        )
    elif "cors" in cat_lower:
        root_cause = (
            "Máy chủ cấu hình header `Access-Control-Allow-Origin` quá rộng hoặc phản chiếu trực tiếp "
            "giá trị header `Origin` từ yêu cầu HTTP của trình duyệt."
        )
        exploit_scenario = (
            "Khi người dùng đã đăng nhập truy cập một trang web độc hại, mã JavaScript trên trang đó có thể "
            "gửi yêu cầu `fetch(..., {credentials: 'include'})` tới mục tiêu và đọc dữ liệu trả về."
        )
        code_patch = (
            "# Chỉ cho phép danh sách tên miền cố định:\n"
            "Access-Control-Allow-Origin: https://trusted-frontend.example.com\n"
            "Vary: Origin"
        )
    elif "cookie" in cat_lower:
        root_cause = (
            f"Cookie phiên làm việc được thiết lập qua header `Set-Cookie` nhưng thiếu các thuộc tính bảo vệ quan trọng ({observed})."
        )
        exploit_scenario = (
            "Thiếu `HttpOnly` cho phép mã độc XSS đọc `document.cookie`; thiếu `Secure` khiến cookie có thể bị nghe lén qua kết nối HTTP; "
            "thiếu `SameSite` làm tăng nguy cơ tấn công giả mạo yêu cầu liên trang (CSRF)."
        )
        code_patch = "Set-Cookie: session_id=<token>; Path=/; Secure; HttpOnly; SameSite=Lax"
    elif any(k in cat_lower for k in ("exposed", "file", ".env", ".git", "backup", "openapi")):
        root_cause = (
            "Các tệp cấu hình, lịch sử quản lý mã nguồn (`.git`) hoặc điểm cuối tài liệu nội bộ được đặt trong thư mục gốc Web (DocumentRoot) "
            "và không bị chặn bởi quy tắc kiểm soát truy cập của Web Server."
        )
        exploit_scenario = (
            "Kẻ tấn công tải trực tiếp tệp nhạy cảm để thu thập khóa API, mật khẩu cơ sở dữ liệu hoặc mã nguồn ứng dụng."
        )
        code_patch = (
            "# Nginx — Chặn toàn bộ tệp ẩn (.env, .git) và tệp sao lưu:\n"
            "location ~ (/\\.|\\.(bak|sql|env|old|swp)$) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        )
    else:
        root_cause = (
            f"Phản hồi HTTP tại `{f['location']}` thiếu hoặc cấu hình yếu cơ chế bảo vệ trình duyệt (`{observed}` thay vì `{expected}`)."
        )
        exploit_scenario = (
            "Kẻ tấn công có thể lợi dụng việc thiếu lớp bảo vệ này để nhúng trang vào iframe (Clickjacking), "
            "ép kiểu MIME (MIME-sniffing) hoặc thực thi kịch bản nội tuyến nếu có điểm chèn mã."
        )
        code_patch = (
            "# Cấu hình HTTP Security Headers khuyến nghị:\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
            "X-Frame-Options: DENY\n"
            "X-Content-Type-Options: nosniff\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        )

    result = {
        "title": f["title"],
        "severity": f["severity"],
        "location": f["location"],
        "engine": "AI Security Analyst",
        "latency_ms": 10,
        "root_cause": root_cause,
        "exploit_scenario": exploit_scenario,
        "code_patch": code_patch,
        "ai_advice": "",
    }

    eff_key = os.environ.get("DAST_API_KEY", "").strip()
    if use_llm and eff_key:
        try:
            from openai import OpenAI
            from app.artex_web import load_llm_pool
            pool = load_llm_pool()
            prim = next((m for m in pool.get("models", []) if m.get("is_primary") and m.get("status") != "circuit_broken"), None)
            m_name = str(prim.get("model")) if prim else os.environ.get("DAST_MODEL", "llama-3.3-70b-versatile")
            b_url = str(prim.get("base_url")) if prim else os.environ.get("DAST_BASE_URL", "https://api.groq.com/openai/v1")

            client = OpenAI(api_key=eff_key, base_url=b_url or None)
            t0 = time.perf_counter()
            comp = client.chat.completions.create(
                model=m_name,
                messages=[{
                    "role": "user",
                    "content": (
                        f"Phân tích ngắn gọn bằng tiếng Việt (tối đa 100 từ) lỗ hổng '{f['title']}' ({f['severity']}, {f['cwe']}) "
                        f"tại '{f['location']}' (Công nghệ: {techs}; Quan sát: {observed}). "
                        f"Nêu rõ mức độ khai thác thực tế và lưu ý quan trọng nhất khi vá lỗi."
                    ),
                }],
                max_tokens=280,
                temperature=0.2,
            )
            lat = int((time.perf_counter() - t0) * 1000)
            txt = (comp.choices[0].message.content or "").strip()
            if txt:
                result["ai_advice"] = txt
                result["llm_advice"] = txt
                result["engine"] = f"LLM ({m_name})"
                result["latency_ms"] = lat
        except Exception:
            pass

    return result
