# AI DAST Core — Autonomous Security Testing Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/Architecture-Scope--Guarded%20DAST-0284C7.svg?style=for-the-badge" alt="Architecture" />
  <img src="https://img.shields.io/badge/AI%20Engine-LLM%20Pool%20%26%20Multi--Model-8B5CF6.svg?style=for-the-badge" alt="AI Engine" />
  <img src="https://img.shields.io/badge/Tests-473%20Passed-10B981.svg?style=for-the-badge" alt="Tests" />
  <img src="https://img.shields.io/badge/License-MIT-gray.svg?style=for-the-badge" alt="License" />
</p>

**AI DAST Core** là nền tảng kiểm thử bảo mật động (Dynamic Application Security Testing - DAST) kết hợp trí tuệ nhân tạo (AI Planner & LLM Pool) được xây dựng theo kiến trúc **Zero-Trust Guardrails**: AI đóng vai trò là một thành phần lập kế hoạch thông minh đưa ra quyết định (*what to do next*), trong khi hệ thống ranh giới bảo vệ (Harness) kiểm soát nghiêm ngặt những gì được phép thực thi (*what is possible*).

---

## 🌐 Trải Nghiệm Demo Trực Tiếp (Live Demo & Web Console)

> 🚀 **DÙNG THỬ NGAY TRÊN TRÌNH DUYỆT (KHÔNG CẦN CÀI ĐẶT / TẢI VỀ):**  
> 👉 **[https://nacterr.github.io/ai-dast-core/](https://nacterr.github.io/ai-dast-core/)**  
> *(Chạy 100% online trên GitHub Pages, tương tác đầy đủ: Quét Demo, Phân tích AI, Retest, Quản lý Cụm LLM Pool).*

Bạn có thể chạy thử nghiệm và tương tác với giao diện AI DAST Web Console và Desktop GUI thông qua các chế độ:

| Chế độ | Đường dẫn / Lệnh khởi chạy | Mô tả |
| :--- | :--- | :--- |
| **🌐 Online Web Demo** | **[https://nacterr.github.io/ai-dast-core/](https://nacterr.github.io/ai-dast-core/)** | **Xem ngay trên web** không cần cài đặt bất kỳ phần mềm nào. Tương tác đầy đủ tính năng! |
| **🌐 Local Web Console** | `http://127.0.0.1:8788/` | Chạy file `chay-web.bat` hoặc lệnh `python -m app.artex_web`. Giao diện Web Console cục bộ. |
| **🌍 Online Public Tunnel** | `https://xxxx.trycloudflare.com` | Chạy file `start-online.bat`. Tự động tạo đường hầm HTTPS Cloudflare công khai toàn cầu. |
| **🖥️ Native Desktop GUI** | Mở ứng dụng Desktop | Chạy file `chay-app.bat` hoặc lệnh `python -m app.desktop`. Giao diện PySide6 chuyên nghiệp cho Security Analysts. |
| **🔗 Tham chiếu Thiết kế** | [ARTEX Demo Reference](https://artex-demo.mhtsec.com/system/llm/) | Dự án lấy cảm hứng kiến trúc và tham chiếu thiết kế trực quan từ ARTEX (MHTSec) về Quản lý Cụm LLM Pool & DAST. |

---

## ⚡ Điểm Nổi Bật & Tính Năng Vượt Trội (Key Features)

### 1. 🤖 Tự Động Phân Tích AI Khi Nhấp Chọn Lỗ Hổng (On-Click AI Analysis)
- **Không cần thao tác nút bấm phụ**: Chỉ cần nhấp vào bất kỳ hàng lỗ hổng nào trên bảng kết quả (cả Web Console và Desktop App), hệ thống AI Analyst sẽ tự động kích hoạt ngay lập tức.
- **🔍 Root Cause (Nguyên nhân gốc rễ)**: Chỉ ra chính xác cơ chế gây ra lỗi (dựa theo CWE, OWASP, vị trí code và công nghệ phát hiện).
- **⚠️ Exploit Scenario (Kịch bản rủi ro)**: Mô phỏng phương thức kẻ tấn công có thể khai thác điểm yếu này trong thực tế.
- **🧠 LLM Pool Security Advisor**: Lời khuyên chiến lược từ mô hình AI phân tích chuyên sâu.
- **🛠️ Remediation Code Patch**: Cung cấp trực tiếp các đoạn code và cấu hình vá lỗi cụ thể (Python, PHP, Node.js, Nginx, Apache) sẵn sàng để lập trình viên copy và khắc phục ngay.

### 2. 🔄 Kiểm Tra Lại Trực Tiếp Chỉ 1-Click (1-Click Retest)
- Tích hợp động cơ kiểm tra lại phát hiện theo thời gian thực (Real-time finding verification).
- Kiểm tra lại phản hồi máy chủ để xác nhận ngay lỗ hổng đã được vá thành công hay vẫn còn tồn tại mà không cần phải quét lại toàn bộ hệ thống.

### 3. 🧠 Quản Trị Cụm Mô Hình AI (Multi-Engine LLM Pool `/system/llm/`)
- Quản lý đa mô hình AI: **OpenAI (GPT-4o / GPT-4o-mini)**, **Groq (Llama 3.3 / Llama 3.1)**, **Anthropic (Claude 3.5)**, **DeepSeek**, và các mô hình cục bộ qua **Ollama / vLLM**.
- Cơ chế cân bằng tải thông minh (**Round-Robin**), tự động chuyển đổi dự phòng (**Auto-Failover**), kiểm soát tốc độ truy vấn (**Rate-limit guard: RPS / RPM**) và theo dõi độ trễ thời gian thực.

### 4. 🗺️ Chuỗi Trinh Sát & Dấu Vết Hành Trình (Exploration Chain)
- Ghi lại toàn bộ hành trình trinh sát của AI: Từ bước khởi tạo mục tiêu, các công cụ đã chạy (Discovery, Passive Check, CORS, TLS, Injection probe...), suy nghĩ chiến thuật (*reasoning steps*) đến từng phát hiện bảo mật tương ứng.

### 5. 🛡️ Khung Bảo Vệ Nghiêm Ngặt (Zero-Trust Guardrails)
- **ScopeGuard**: AI tuyệt đối không thể tự ý quét ra ngoài phạm vi (Target Scope) được cho phép.
- **ArgumentGuard**: Ngăn chặn AI tự sinh payload tấn công tuỳ ý hoặc thực thi lệnh shell.
- **Safe Methods**: Toàn bộ các kiểm tra chủ động bị giới hạn trong các phương thức an toàn, không làm hỏng hóc hoặc biến đổi dữ liệu của mục tiêu.

---

## 🚀 Hướng Dẫn Cài Đặt Nhanh (Quickstart)

### Yêu cầu hệ thống:
- Python 3.11 trở lên.
- Hệ điều hành: Windows, macOS hoặc Linux.

### 1. Khởi tạo môi trường ảo & cài đặt thư viện:

```powershell
# Windows
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m playwright install chromium
```

```bash
# macOS / Linux
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m playwright install chromium
```

### 2. Cấu hình API Key AI (Tuỳ chọn):
Sao chép file cấu hình mẫu `.env.example` thành `.env` và điền API Key của bạn (nếu có):

```bash
cp .env.example .env
```
*(Nếu không có API Key, hệ thống sẽ sử dụng Local Rule-based Security Expert Engine với tốc độ phản hồi cực nhanh < 10ms).*

---

## 💻 Cách Khởi Chạy Ứng Dụng (Usage)

### Cách 1: Chạy Ứng Dụng Desktop (Khuyến nghị)
Nhấp đúp chuột vào file:
```
chay-app.bat
```
Hoặc mở terminal gõ:
```powershell
.\.venv\Scripts\python.exe -m app.desktop
```

### Cách 2: Chạy Web Console (Browser UI)
Nhấp đúp chuột vào file:
```
chay-web.bat
```
Hoặc chạy lệnh:
```powershell
.\.venv\Scripts\python.exe -m app.artex_web
```
Trình duyệt sẽ tự động mở tại địa chỉ: **`http://127.0.0.1:8788/`**.

### Cách 3: Mở Đường Hầm Online (Public Demo với Cloudflare Tunnel)
Để demo cho đối tác, bạn bè hoặc truy cập từ xa qua điện thoại:
```
start-online.bat
```
Terminal sẽ hiển thị đường link HTTPS công khai dạng: `https://xxxx.trycloudflare.com`.

### Cách 4: Quét Bằng Dòng Lệnh (CLI Scanner)
Quét thử nghiệm mục tiêu với đầy đủ quyền hạn uỷ quyền:
```powershell
.\.venv\Scripts\python.exe -m app.main scan https://staging.example.com --authorized-by "security-team@example.com"
```

---

## 🎯 Chạy Thử Với Mục Tiêu Giả Lập Nội Bộ (Bundled Demo Target)

Kho mã nguồn tích hợp sẵn một ứng dụng web demo cố ý tồn tại các lỗi bảo mật phổ biến để bạn chạy thử nghiệm an toàn:

```powershell
# Terminal 1: Bật máy chủ mục tiêu giả lập tại cổng 8099
.\.venv\Scripts\python.exe -m tools.demo_target --port 8099

# Terminal 2: Ra lệnh cho AI DAST tiến hành quét
.\.venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8099 --allow-private --yes --authorized-by "demo" --run-name demo-scan
```

Kết quả báo cáo sẽ được xuất tự động tại thư mục `runs/demo-scan/report.json` và `report.md`.

---

## 🧪 Kiểm Thử Hệ Thống (Automated Tests)

Bộ kiểm thử tự động gồm **473 bài test** bao quát từ chính sách phân quyền (Policy), công cụ trinh sát (Tools), vòng lặp lập kế hoạch (Orchestrator) đến API Service:

```powershell
.\.venv\Scripts\pytest.exe -q
```
*Kết quả: 473 passed in ~45s (100% Passed).*

---

## 📚 Tài Liệu Kỹ Thuật Chi Tiết (Documentation)

- 📖 [Hướng dẫn sử dụng toàn diện (docs/HUONG-DAN-SU-DUNG.md)](docs/HUONG-DAN-SU-DUNG.md): Chi tiết cấu hình, tham số quét, bảo mật và API reference.
- 🏛️ [Kiến trúc hệ thống (docs/ARCHITECTURE.md)](docs/ARCHITECTURE.md): Phân tích thiết kế của Harness, Planner và Dispatcher.
- 🛡️ [Mô hình bảo vệ (docs/SECURITY-MODEL.md)](docs/SECURITY-MODEL.md): Cơ chế cô lập và kiểm soát ranh giới bảo mật.

---

## 📄 Bản Quyền (License)

Dự án được phân phối dưới giấy phép mã nguồn mở [MIT License](LICENSE).
Mọi đóng góp (Pull Request, Issue) đều được chào đón nồng nhiệt!
