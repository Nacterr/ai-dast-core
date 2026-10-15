# Hướng dẫn sử dụng ai-dast-core

Tài liệu này dành cho người vận hành. Đọc tuần tự từ trên xuống là chạy được.

**Cảnh báo trước khi bắt đầu.** Công cụ này gửi request thật tới target bạn chỉ định.
Chỉ chạy với hệ thống bạn sở hữu hoặc có **uỷ quyền bằng văn bản**. Ở mọi chế độ, trường
`authorized_by` là bắt buộc và được ghi vào báo cáo làm dấu vết kiểm toán.

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Ba cách chạy](#2-ba-cách-chạy)
3. [Chạy thử với target demo](#3-chạy-thử-với-target-demo)
4. [Chế độ A — quét local bằng CLI](#4-chế-độ-a--quét-local-bằng-cli)
5. [Chế độ B — service nội bộ (khuyến nghị cho team)](#5-chế-độ-b--service-nội-bộ-khuyến-nghị-cho-team)
6. [Chế độ C — service mở ra ngoài mạng](#6-chế-độ-c--service-mở-ra-ngoài-mạng)
7. [Dùng Web UI](#7-dùng-web-ui)
8. [Gọi API từ script](#8-gọi-api-từ-script)
9. [API reference](#9-api-reference)
10. [Đọc báo cáo](#10-đọc-báo-cáo)
11. [Bật AI planner thật](#11-bật-ai-planner-thật)
12. [Xử lý sự cố](#12-xử-lý-sự-cố)
13. [Hiểu đúng về kết quả](#13-hiểu-đúng-về-kết-quả)

---

## 1. Cài đặt

Cần Python 3.11 trở lên.

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

Bước `playwright install chromium` tải khoảng 115 MB. Bắt buộc — không có nó thì tool
`browser_open` và ba tool `extract_*` không chạy được (các tool passive vẫn chạy).

Kiểm tra cài đặt:

```powershell
.\.venv\Scripts\python.exe -m app.main --version
.\.venv\Scripts\python.exe -m app.main tools
```

Nếu `tools` in ra 18 tool (16 chạy được, 2 ghi `[not implemented]`) là đã xong.

---

## 2. Các cách chạy

| Chế độ | Lệnh / Thao tác | Ai gọi được | Dùng khi nào |
|---|---|---|---|
| **Exe 1-Click** | Nháy đúp file `ai-dast-web.exe` | Máy bạn, tự mở Browser | **Tiện lợi nhất** (Web UI tự bật ngầm) |
| **A** CLI | `ai-dast-core scan URL` | Chỉ bạn, tại máy bạn | Quét nhanh qua dòng lệnh |
| **B** Service nội bộ | `ai-dast-core serve --host 127.0.0.1` | Chỉ máy bạn, qua HTTP | Có script/CI gọi vào |
| **C** Service mở rộng | `ai-dast-core serve --host 0.0.0.0 --api-key ...` | Ai có API key | Team dùng chung |

Chế độ C **bắt buộc** phải có API key. Nếu bạn quên, chương trình từ chối khởi động —
đây là chủ ý, để một scanner mạnh không bị publish nhầm ra mạng.

---

## 3. Chạy thử với target demo

Repo có sẵn một target cố tình có lỗi, để bạn thấy toàn bộ pipeline chạy mà không cần
đụng vào hệ thống thật.

**Terminal 1:**

```powershell
.\.venv\Scripts\python.exe -m tools.demo_target --port 8099
```

**Terminal 2:**

```powershell
.\.venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8099 `
    --allow-private --yes `
    --authorized-by "ban@congty.com" `
    --run-name demo --rate 20
```

Kết quả mong đợi: **17 finding** (1 high, 4 medium, 6 low, 6 info), gồm CORS mở kèm
credentials, thiếu HSTS/CSP/X-Frame-Options, 3 cookie thiếu `Secure`/`HttpOnly`/`SameSite`,
lộ `Server`/`X-Powered-By`, và 4 API route thu thập được từ JavaScript inline.

Exit code `2` = có finding high. Đây là hành vi đúng, không phải lỗi.

---

### Bảng tool

| Tool | Nhóm | Làm gì | Chi phí |
|---|---|---|---|
| `browser_open` | discovery | Mở 1 URL bằng browser thật, trả `page_id` | 1 page |
| `extract_links` | discovery | Liệt kê link, form action, script, iframe, ảnh | miễn phí |
| `extract_forms` | discovery | Liệt kê form + heuristic login/upload/thiếu CSRF | miễn phí |
| `extract_scripts` | discovery | Script, excerpt JS inline, API route, cảnh báo secret (đã che) | miễn phí |
| `read_robots` | discovery | robots.txt, sitemap.xml, security.txt → suy ra path trong scope | ≤3 request |
| `check_headers` | passive | Chấm điểm 9 header bảo mật + lộ banner | 1 request |
| `check_cookies` | passive | Kiểm tra cờ `Set-Cookie` (không lưu giá trị) | 1 request |
| `analyze_cors` | passive | Dò chính sách CORS bằng Origin cố định; probe lần 2 để xác nhận reflection | 1–3 request |
| `check_tls` | passive | Protocol, cipher, hạn certificate, self-signed. **Không** tự nâng http→https | 1 request |
| `analyze_exposed_files` | passive | Dò `/.git/HEAD`, `.env`, dump DB, backup, debug endpoint | ≤1 HEAD/path (ngân sách riêng) |
| `detect_technologies` | passive | Nhận diện server/framework/front-end | 1 request |
| `get_scan_status` | result | Tiến độ, ngân sách còn lại, gợi ý bước tiếp theo | **miễn phí** |
| `get_alerts` | result | Đọc finding đã có, lọc theo severity/category/host | **miễn phí** |
| `get_http_history` | result | Nhật ký HTTP, chuỗi redirect, redirect bị chặn | **miễn phí** |
| `run_selected_active_check` | active | 5 check **không thay đổi dữ liệu**. Cần `--active` | 1–2 request/check |
| `run_injection_probe` | active | Dò XSS phản xạ và Path Traversal bằng probe vô hại. Cần `--injection` | ≤3 request/probe |
| `run_openapi_scan` | active | Tự động phát hiện Swagger/OpenAPI spec, kiểm tra auth thiếu sót & probe non-mutating endpoint. Cần `--openapi` | 1–5 request |

### `run_selected_active_check` — tool duy nhất gửi request target không mời

Đây là tool **nguy hiểm nhất** trong bộ, nên nó có 2 lớp opt-in độc lập:

```powershell
.\.venv\Scripts\python.exe -m app.main scan https://target.example.com `
    --active --yes --authorized-by "ban@congty.com"
```

`--active` cấp capability `active_scan`. Không có nó, dispatcher từ chối:

```
[permissions] capability not granted: active_scan. Granted: browser, dns_lookup, http_egress, write_artifact
```

### Nguyên tắc quan trọng nhất

**AI chọn TÊN CHECK, không bao giờ chọn payload.**

Request model chỉ có 3 trường: `url`, `checks`, `calibrate`. **Không có** trường nào cho
method, header, body hay payload. Test khẳng định truyền `method=DELETE` hay
`payload=' OR 1=1--` đều bị **từ chối thẳng**.

### Mọi check đều KHÔNG thay đổi dữ liệu — và điều đó được *thực thi*

Engine giữ allowlist `_SAFE_METHODS = {GET, HEAD, OPTIONS, TRACE}` và **từ chối mọi method
khác tại runtime**. Nên một check viết sau này không thể vô tình thêm request thay đổi
trạng thái.

Khi cần biết server có chấp nhận method ghi hay không, check **hỏi bằng `OPTIONS`** và đọc
header `Allow` — **không bao giờ gửi chính method ghi đó**.

Vì vậy `ToolMeta.mutates_target = False` dù `requires_confirmation = True`. Confirmation ở
đây là về **sự chú ý**, không phải về thay đổi trạng thái.

| Check | Hỏi gì | Gửi gì |
|---|---|---|
| `cors_preflight` | Cross-origin có được dùng method **ghi** không? | `OPTIONS` nêu PUT từ origin `.invalid` — **không bao giờ gửi PUT** |
| `http_methods` | Endpoint quảng cáo/chấp nhận method nào? | `OPTIONS` + `TRACE` |
| `options_method` | `OPTIONS` có trả lời khi chưa xác thực không? | `OPTIONS` |
| `trace_method` | TRACE có bật không (cross-site tracing)? | `TRACE` — định nghĩa là không có side effect |
| `path_normalisation` | Biến thể path mã hoá có resolve khác không? | Chỉ `GET` |

### `path_normalisation` — check active thật, không đổi gì

Đây là check thú vị nhất. Nó gửi `GET` tới các biến thể mã hoá của **chính path của URL**
(`/api/..%2freflect`, `/api/%2e%2e%2freflect`, ...) và so sánh với path thường.

**Control làm cho nó có ý nghĩa.** Phải thoả **hai** điều kiện mới báo finding:

1. biến thể phải resolve tới một resource **thật sự tồn tại** (không phải catch-all);
2. nó phải **khác** response của path thường.

Không có điều kiện 1, mọi server có trang 404 khác trang 200 đều trông như có lỗ hổng.

### Chạy demo để thấy active check

```powershell
# terminal 1
.\.venv\Scripts\python.exe -m tools.demo_target --port 8099

# terminal 2 - endpoint reflect cho phép PUT cross-origin
.\.venv\Scripts\python.exe -m app.main scan "http://127.0.0.1:8099/api/reflect" `
    --allow-private --active --yes --authorized-by "demo" --run-name active-demo --rate 30
```

Kết quả trên demo target: **20 finding** gồm `active:cors_preflight` mức **high**
("CORS permits a cross-origin write method") và `active:http_methods` mức **low**.

Trên `/` và `/search` (chỉ quảng cáo method đọc), tool **không báo gì** — đúng như phải vậy.

---

3 tool `result` **không gửi traffic và không tiêu ngân sách**. AI gọi bao nhiêu lần cũng
được. Đây là điều khiến planner LLM thực sự hữu ích — nó nhìn được toàn bộ engagement
thay vì chỉ tool result cuối cùng.

### `analyze_cors` — tool passive có finding khai thác được

CORS sai cấu hình là một trong số ít lỗi mà passive scan tìm được và **khai thác được ngay**.
Tool này phân biệt 5 trường hợp:

| Verdict | Mức | Nghĩa |
|---|---|---|
| `reflects_origin_with_credentials` | **high** | Bất kỳ site nào đọc được response đã xác thực → chiếm tài khoản |
| `null_origin` | **high** | Bất cứ thứ gì trong sandboxed iframe đọc được response |
| `reflects_origin` | medium | Bất kỳ site nào đọc được response |
| `wildcard_with_credentials` | medium | Browser **từ chối** tổ hợp này → cấu hình hỏng, không khai thác được |
| `wildcard_no_credentials` | **không phải finding** | Đây là cấu hình **đúng** cho public API |

Hai điểm quan trọng:

**1. `Origin` là hằng số của harness.** Không có tham số nào nhận `Origin` từ người gọi —
vì `Origin` do người gọi kiểm soát sẽ là **injection vào một quyết định tin cậy** mà browser
đưa ra thay người dùng. Test khẳng định truyền `origin=...` sẽ bị từ chối.

Giá trị probe là `https://origin-probe.invalid` — domain `.invalid` được RFC 2606 dành riêng,
không bao giờ phân giải được, nên không thể bị nhầm là đang gọi tới bên thứ ba thật.

**2. Probe lần hai để xác nhận reflection.** Một lần khớp có thể là giá trị allowlist cố định
tình cờ trùng. Tool gửi probe thứ hai với Origin khác; nếu lần hai **không** bị reflect, nó
**hạ cấp** verdict thay vì báo động sai.

Lưu ý: CORS **không còn** được kiểm trong `check_headers`. Làm ở hai chỗ sẽ báo cùng một lỗi
hai lần với hai mức khác nhau.

### `check_tls` — và vì sao nó không tự nâng cấp scheme

Tool này **không** tự đổi `http://` thành `https://`. Đổi scheme ngầm nghĩa là **liên hệ tới
một endpoint mà người gọi không nêu tên và operator không uỷ quyền**. Với URL http, tool báo
"không có TLS để kiểm tra" và không gửi request nào.

Nó tìm được: protocol lỗi thời (SSLv2/v3, TLS 1.0/1.1 — RFC 8996 deprecate cả 1.1),
certificate hết hạn hoặc sắp hết hạn (mặc định cảnh báo trước 21 ngày), certificate self-signed
trên hostname public.

Nó **không** liệt kê cipher suite hay test downgrade: việc đó cần TLS client riêng thay vì
dùng connection của HTTP transport, và là kỹ thuật **active**. Nằm trong ROADMAP, không xây ở đây.

### `analyze_exposed_files` — tool mạnh nhất và cũng cần cẩn thận nhất

Đây là tool **đầu tiên có danh sách path**, nên nó có 4 lớp bảo vệ mà bạn nên hiểu:

**1. Path là hằng số do harness sở hữu.** AI chọn *origin* và *nhóm* (category), không bao
giờ chọn path. Vì vậy không thể biến nó thành content-discovery scanner quét tuỳ ý.

Nhóm có sẵn: `vcs`, `config`, `backup`, `server-info`, `editor`, `ci`, `docs`.
Mặc định (không truyền gì) chỉ quét `vcs`, `config`, `server-info` — nhóm tín hiệu cao nhất.

**2. Ngân sách riêng.** `--max-exposed-file-checks` (mặc định 40) tách khỏi
`--max-requests`, nên việc dò file không thể ăn hết ngân sách của các check sinh finding.

**3. Calibration soft-404.** Trước khi tin bất kỳ status code nào, tool dò một path
**chắc chắn không tồn tại**. Nếu path đó cũng trả `200`, status code bị coi là vô nghĩa và
**mọi hit phải vượt qua kiểm tra content signature hoặc content-type**.

Đây là điểm quan trọng nhất. Rất nhiều server cấu hình catch-all trả 200 cho mọi đường dẫn.
Không có bước này, tool sẽ báo "`/.env` của bạn đang public" trong khi thực tế không có file
nào — false positive tệ nhất có thể, vì nó khiến bạn hoảng loạn và mất niềm tin vào báo cáo.

**4. Không bao giờ lưu nội dung file.** Hit được ghi nhận là path, status, content-type,
kích thước, severity, kèm một signature match **đã che**. Với `.env` nó ghi
`DB_PASSWORD=<redacted>`, không bao giờ ghi giá trị thật.

> Một hit là **quan sát sự thật** ("path này trả về nội dung dạng dotenv"). Nó có nghiêm
> trọng hay không phụ thuộc vào nội dung file — thứ tool này **cố ý không đọc ra**.

### `detect_technologies` — match công nghệ KHÔNG phải lỗ hổng

Tool này chỉ tạo **một** finding: mức `low` khi có **số phiên bản** bị lộ trong response.
Lý do: banner phiên bản giúp attacker đi thẳng tới exploit khớp với phần mềm đang chạy.

"Site này dùng React" không phải lỗi bảo mật. Báo cáo nó như lỗi sẽ khiến người đọc học cách
bỏ qua báo cáo.

Cơ sở tri thức nhỏ và chính xác có chủ ý: một fingerprint đoán sai còn tệ hơn không đoán gì,
vì AI sẽ hành động dựa trên nó.

### `read_robots` tìm gì

Tool này fetch **danh sách path cố định do harness sở hữu** — `/robots.txt`,
`/sitemap.xml`, `/.well-known/security.txt`. AI chỉ chọn **origin**, không bao giờ chọn
path. Đó là toàn bộ lập luận an toàn: không thể biến nó thành content-discovery scanner.

Nó trả về:
- rule `Disallow`/`Allow` của block `User-agent: *` (rule của agent có tên không phải việc của ta)
- entry `<loc>` từ sitemap
- path tuyệt đối **đã lọc qua scope guard** — nên AI không bao giờ nhận link mà nó sẽ bị từ chối
- `crawl-delay` nếu có (chỉ ghi nhận; rate limit của harness vẫn là ràng buộc thật)
- contact trong `security.txt`

Entry có wildcard (`/private/*`) bị **bỏ qua**, không mở rộng — mở rộng nghĩa là đoán path,
mà đoán là đúng thứ tool này không được làm.

> **`Disallow` là gợi ý lộ thông tin, không phải lỗ hổng.** Operator tự chọn công khai path
> đó. Báo cáo nói rõ điều này thay vì ngụ ý đường dẫn là nhạy cảm.

### `get_scan_status` trả `suggestions`

Đây là phần đáng chú ý. Nó liệt kê **khoảng trống mà chính harness nhìn thấy**:
URL trong scope chưa kiểm tra header, check chưa chạy, form đổi trạng thái thiếu CSRF.
Sinh ra từ trạng thái harness, **không phải từ suy đoán của model**. AI được tự do bỏ qua.

### Điểm khác biệt với bản trước

Playbook `scripted` giờ chạy: mở trang → inventory → `check_headers` → `check_cookies` →
`read_robots` → `detect_technologies` → `analyze_cors` → `check_tls` (chỉ khi HTTPS) →
`analyze_exposed_files` → theo link có tham số → `get_alerts`. Trên demo target:
**11 tool call, 22 finding** (1 critical, 2 high, 6 medium, 7 low, 6 info) — trong đó
`/.env` mức **critical**, `/.git/HEAD` + `/.git/config` mức **high**, CORS wildcard+credentials
mức **medium**, và robots.txt đóng góp 8 path mà không link nào trỏ tới.

### Chạy demo để thấy CORS khai thác được

Demo target phục vụ 3 chính sách CORS khác nhau **có chủ ý**, để bạn thấy tool phân biệt đúng:

| Endpoint | Chính sách | Tool phải kết luận |
|---|---|---|
| `/` | `*` + credentials | `wildcard_with_credentials` (medium) |
| `/api/reflect` | echo Origin + credentials | `reflects_origin_with_credentials` (**high**) |
| `/api/null-origin` | `null` + credentials | `null_origin` (**high**) |

```powershell
# terminal 1
.\.venv\Scripts\python.exe -m tools.demo_target --port 8099

# terminal 2 - quét riêng endpoint reflect
.\.venv\Scripts\python.exe -m app.main scan "http://127.0.0.1:8099/api/reflect" `
    --allow-private --yes --authorized-by "demo" --run-name cors-demo --rate 30
```

### Chạy demo với server catch-all

Demo target có chế độ soft-404 để bạn thấy lớp bảo vệ thứ 3 hoạt động:

```powershell
# terminal 1 - server trả 200 cho MỌI path
.\.venv\Scripts\python.exe -m tools.demo_target --port 8099 --soft-404

# terminal 2
.\.venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8099 `
    --allow-private --yes --authorized-by "demo" --run-name demo-soft404 --rate 30
```

Kết quả **vẫn đúng 6 file thật** (không thêm, không bớt) dù server nói dối về mọi path —
vì mọi hit đều được xác nhận bằng content signature. Nếu không có lớp bảo vệ này, bạn sẽ
nhận khoảng 14 finding critical/high giả.

---

## 4. Chế độ A — quét local bằng CLI

### Lệnh cơ bản

```powershell
.\.venv\Scripts\python.exe -m app.main scan https://staging.example.com `
    --authorized-by "ban@congty.com" `
    --authorization-note "ticket SEC-1234, phạm vi đã thoả thuận"
```

Chương trình sẽ:
1. In ra **scope** nó hiểu, để bạn xác nhận.
2. Hỏi bạn gõ `yes` để xác nhận có uỷ quyền.
3. Quét và ghi báo cáo vào `runs/<tên>/report.json` và `report.md`.

### Thêm host vào scope

Mặc định chỉ host trong URL là được phép, cộng thêm biến thể `www.`.

```powershell
# thêm subdomain API, nhưng loại trừ host cũ
.\.venv\Scripts\python.exe -m app.main scan https://example.com `
    --scope-host api.example.com `
    --scope-host "*.cdn.example.com" `
    --exclude-host legacy.example.com `
    --authorized-by "ban@congty.com"
```

`*.example.com` khớp subdomain **nhưng không khớp** tên miền gốc. Nếu cần cả hai, ghi cả hai.

### Quét server dev trên máy bạn

```powershell
.\.venv\Scripts\python.exe -m app.main scan http://127.0.0.1:8000 `
    --allow-private --yes --authorized-by "local dev"
```

`--allow-private` là **bắt buộc** cho địa chỉ private/loopback. Không có nó, scope guard
từ chối và giải thích lý do.

> **Cẩn thận.** `--allow-private` tắt kiểm tra dải private cho **toàn bộ** scan. Chỉ dùng
> khi target thật sự nằm ở địa chỉ nội bộ mà bạn kiểm soát.

### Các cờ hay dùng

| Cờ | Mặc định | Ý nghĩa |
|---|---|---|
| `--max-steps` | 24 | Số bước planner được suy nghĩ |
| `--max-pages` | 15 | Số trang được mở |
| `--max-requests` | 120 | Tổng số HTTP request |
| `--max-exposed-file-checks` | 40 | Số path được dò bởi `analyze_exposed_files` |
| `--rate` | 4 | Request/giây. Hạ xuống nếu target yếu |
| `--max-tool-calls` | 80 | Tổng số lần gọi tool |
| `--scan-timeout` | 600 | Giây cho cả scan |
| `--yes` | tắt | Tự động đồng ý, dùng cho script |
| `--json` | tắt | In JSON ra stdout |
| `--quiet` | tắt | Không in tiến độ |

### Exit code

| Code | Nghĩa |
|---|---|
| `0` | Xong, không có finding high/critical |
| `2` | Xong, **có** finding high/critical |
| `3` | Lỗi tham số hoặc uỷ quyền |
| `4` | Lỗi runtime |

Dùng được trong CI: `if ($LASTEXITCODE -eq 2) { exit 1 }`.

---

## 5. Chế độ B — service nội bộ (khuyến nghị cho team)

Bind vào loopback, không cần API key.

```powershell
.\.venv\Scripts\python.exe -m app.main serve `
    --api-allowed-host staging.example.com `
    --api-allowed-host "*.example.com" `
    --port 8093
```

Mở http://127.0.0.1:8093/ để dùng Web UI.
OpenAPI docs ở http://127.0.0.1:8093/docs.

### Điểm quan trọng nhất của chế độ này

**Uỷ quyền thuộc về operator, không thuộc về người gọi API.**

`--api-allowed-host` là **danh sách host service được phép quét, mãi mãi**. Một request
gửi tới API chỉ có thể **thu hẹp** danh sách đó, không bao giờ mở rộng được. Cụ thể,
request **không thể**:

- chỉ định host ngoài allowlist
- bật truy cập địa chỉ private (phải do `--api-allow-private` của bạn)
- vượt trần ngân sách bạn đặt (chỉ bị hạ xuống, không bị từ chối)
- chọn planner bạn chưa cấu hình
- tự cung cấp API key cho LLM
- bật active scanning, tắt confirmation, hay đổi User-Agent

Đây là lý do service an toàn hơn một "proxy quét web": người gọi API là **không đáng tin**,
và mọi thứ nguy hiểm đều do bạn chốt lúc khởi động.

### Quét server dev nội bộ

```powershell
.\.venv\Scripts\python.exe -m app.main serve `
    --api-allowed-host 127.0.0.1 `
    --api-allowed-port 8000 `
    --api-allow-private `
    --port 8093
```

### Trần ngân sách

Mọi request đều bị kẹp theo trần bạn đặt:

```powershell
.\.venv\Scripts\python.exe -m app.main serve `
    --api-allowed-host "*.example.com" `
    --api-max-steps 40 `
    --api-max-pages 20 `
    --api-max-requests 200 `
    --api-max-rate 10 `
    --max-concurrent-scans 2
```

---

## 6. Chế độ C — service mở ra ngoài mạng

```powershell
# Đặt API key trước. Dùng chuỗi ngẫu nhiên dài, đừng dùng mật khẩu bạn nhớ.
$env:DAST_SERVICE_KEY = -join ((1..48) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })

.\.venv\Scripts\python.exe -m app.main serve `
    --api-allowed-host "*.example.com" `
    --host 0.0.0.0 `
    --port 8080 `
    --api-max-rate 5
```

Nếu bạn quên `--api-key` (hoặc `$env:DAST_SERVICE_KEY`), chương trình **từ chối khởi động**:

```
error: binding to '0.0.0.0' requires --api-key (or $DAST_SERVICE_KEY). An unauthenticated
scanner on a network interface is an open relay for attacks. Use --host 127.0.0.1 for local use.
```

### Danh sách kiểm tra trước khi mở ra ngoài

- [ ] Đã đặt API key ngẫu nhiên, đủ dài (≥ 32 ký tự)
- [ ] Allowlist chỉ chứa host bạn **thực sự** được phép quét
- [ ] `--api-max-rate` đủ thấp để không làm sập target
- [ ] `--max-concurrent-scans` = 1, trừ khi bạn có lý do rõ ràng
- [ ] **Không** bật `--api-allow-private` (nó cho phép người gọi chạm vào mạng nội bộ)
- [ ] Đã tính tới chuyện đặt sau reverse proxy có TLS (uvicorn ở đây không tự bật HTTPS)
- [ ] `runs/` nằm trên ổ đĩa bạn kiểm soát — báo cáo chứa thông tin về hệ thống của bạn

> **Vì sao API key quan trọng đến vậy.** Bất kỳ ai có key đều có thể quét mọi host trong
> allowlist. Nếu bạn allowlist `*.example.com` và key bị lộ, người đó quét được toàn bộ
> hạ tầng của bạn. Hãy coi key này như một credential có quyền.

---

## 7. Dùng Web UI

Mở http://127.0.0.1:8093/ (hoặc `http://<host>:<port>/` nếu chạy chế độ C).

### Các bước

1. **API key** (chỉ chế độ C): dán key vào ô đầu tiên. Nó chỉ nằm trong bộ nhớ của tab,
   không ghi ra đâu cả.
2. **Target URL**: nhập URL cần quét.
3. **Người uỷ quyền**: bắt buộc. Đây là dấu vết kiểm toán trong báo cáo.
4. **Host bổ sung**: tuỳ chọn, cách nhau dấu phẩy. Mỗi host phải **đã** được operator cho phép.
5. **Planner**: `scripted` (mặc định, không cần API key) hoặc `llm`.
6. **Tuỳ chọn quét nâng cao**:
   - Checkbox **Active Scan**: cho phép các check active probes và OpenAPI scan.
   - Checkbox **Injection Probes**: cho phép các probe XSS/Path Traversal non-mutating.
7. Bấm **Bắt đầu scan**.

### Tính năng tiện ích: 🚀 1-Click Bật Target Demo & Quét ngay
Nếu đang kiểm thử tại chỗ trên máy (`localhost` / `127.0.0.1`), bạn chỉ cần bấm nút màu xanh lá **"🚀 1-Click Bật Target Demo & Quét ngay"**:
- Service daemon sẽ tự động khởi động một máy chủ kiểm thử demo đa lỗ hổng tích hợp (`http://127.0.0.1:8099`) ở background.
- Tự động điền URL, người uỷ quyền (`demo-operator`), bật các cờ kiểm tra nâng cao và bắt đầu scan ngay lập tức.

### Theo dõi

- Thanh tiến độ hiện `tool calls / steps / pages / requests` đã dùng.
- Tab **Nhật ký trực tiếp** hiện từng bước planner đang làm, cập nhật mỗi 1.5 giây.
- Bấm **Huỷ** để dừng. Lệnh huỷ được quan sát ở ranh giới bước tiếp theo, không tức thời.

### Xem kết quả

| Tab | Nội dung |
|---|---|
| **Findings** | Từng lỗ hổng, kèm evidence trỏ về đúng tool call sinh ra nó |
| **Nhật ký trực tiếp** | Log đầy đủ của scan |
| **Tool trace** | Bảng mọi tool đã gọi, trạng thái, thời gian, lý do AI chọn |
| **Attack surface** | Form (kèm cảnh báo thiếu CSRF), API route, URL trong scope |
| **Scope & cấu hình** | Scope thực tế đã dùng, ngân sách đã kẹp, limitations |

Nút **Tải report.json** / **report.md** để lấy báo cáo về máy.

### Nút "Xem giới hạn"

In ra toàn bộ giới hạn của deployment hiện tại. Dùng khi cần giải thích cho đồng nghiệp
vì sao một target bị từ chối.

---

## 8. Gọi API từ script

### PowerShell

```powershell
$Base = "http://127.0.0.1:8093"
$Key  = "your-api-key"          # chỉ cần ở chế độ C

# 1. Gửi scan
$job = Invoke-RestMethod -Method Post -Uri "$Base/v1/scans" `
    -Headers @{ Authorization = "Bearer $Key" } `
    -ContentType "application/json" `
    -Body (@{
        target           = "https://staging.example.com"
        authorized_by    = "ci-pipeline"
        authorization_note = "nightly scan, ticket SEC-1234"
        max_pages        = 5
    } | ConvertTo-Json)

Write-Host "job: $($job.job_id)"

# 2. Chờ xong
do {
    Start-Sleep -Seconds 3
    $status = Invoke-RestMethod -Uri "$Base/v1/scans/$($job.job_id)" `
        -Headers @{ Authorization = "Bearer $Key" }
} while ($status.state -in @("queued", "running"))

Write-Host "state: $($status.state), findings: $($status.finding_count)"

# 3. Lấy báo cáo
$report = Invoke-RestMethod -Uri "$Base/v1/scans/$($job.job_id)/report" `
    -Headers @{ Authorization = "Bearer $Key" }

$report.report.findings |
    Select-Object severity, host, title |
    Format-Table -AutoSize

# 4. Fail CI nếu có finding high/critical
if ($report.report.severity_counts.high -gt 0 -or $report.report.severity_counts.critical -gt 0) {
    Write-Error "High/critical findings detected"
    exit 1
}
```

### Bash / curl

```bash
BASE=http://127.0.0.1:8093
KEY=your-api-key

JOB=$(curl -s -X POST "$BASE/v1/scans" \
  -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://staging.example.com","authorized_by":"ci","max_pages":5}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["job_id"])')

echo "job: $JOB"

while true; do
  STATE=$(curl -s "$BASE/v1/scans/$JOB" -H "Authorization: Bearer $KEY" \
    | python -c 'import sys,json; print(json.load(sys.stdin)["state"])')
  [ "$STATE" = "completed" ] || [ "$STATE" = "failed" ] || [ "$STATE" = "cancelled" ] && break
  sleep 3
done

curl -s "$BASE/v1/scans/$JOB/report" -H "Authorization: Bearer $KEY" \
  | python -m json.tool > report.json
```

### Python

```python
import time, requests

BASE, KEY = "http://127.0.0.1:8093", "your-api-key"
headers = {"Authorization": f"Bearer {KEY}"}

accepted = requests.post(
    f"{BASE}/v1/scans",
    headers=headers,
    json={
        "target": "https://staging.example.com",
        "authorized_by": "ci-pipeline",
        "authorization_note": "nightly scan",
        "max_pages": 5,
    },
    timeout=30,
).json()

job_id = accepted["job_id"]

while True:
    status = requests.get(f"{BASE}/v1/scans/{job_id}", headers=headers, timeout=30).json()
    if status["state"] in {"completed", "failed", "cancelled"}:
        break
    time.sleep(3)

report = requests.get(f"{BASE}/v1/scans/{job_id}/report", headers=headers, timeout=30).json()["report"]

for finding in report["findings"]:
    print(f"[{finding['severity'].upper()}] {finding['host']} — {finding['title']}")

counts = report["severity_counts"]
raise SystemExit(1 if counts["high"] or counts["critical"] else 0)
```

---

## 9. API reference

Base URL: `http://<host>:<port>`

Xác thực: `Authorization: Bearer <api-key>` — bắt buộc khi `auth_required: true` trong
`/v1/capabilities`.

### Không cần xác thực

| Method | Path | Mô tả |
|---|---|---|
| `GET` | `/v1/health` | Kiểm tra service còn sống |
| `GET` | `/v1/capabilities` | Toàn bộ giới hạn của deployment này |
| `GET` | `/` | Web UI |
| `GET` | `/docs` | OpenAPI docs |

### Cần xác thực

| Method | Path | Mô tả |
|---|---|---|
| `GET` | `/v1/tools?include_schema=false` | Danh mục tool. Có `?include_schema=true` để lấy JSON Schema |
| `POST` | `/v1/scans` | Gửi scan, trả `202` kèm `job_id` |
| `GET` | `/v1/scans?limit=50` | Lịch sử job |
| `GET` | `/v1/scans/{id}` | Trạng thái + tiến độ + log gần nhất |
| `GET` | `/v1/scans/{id}/report` | Báo cáo JSON (`409` nếu chưa xong) |
| `GET` | `/v1/scans/{id}/report.md` | Báo cáo Markdown |
| `GET` | `/v1/scans/{id}/events?tail=200` | Log đầy đủ |
| `POST` | `/v1/scans/{id}/cancel` | Yêu cầu huỷ |

### Body của `POST /v1/scans`

```json
{
  "target": "https://staging.example.com",
  "authorized_by": "ban@congty.com",
  "authorization_note": "ticket SEC-1234",
  "scope_hosts": ["api.example.com"],
  "planner": "scripted",
  "max_steps": 20,
  "max_tool_calls": 60,
  "max_pages": 5,
  "max_requests": 80,
  "requests_per_second": 4.0
}
```

| Trường | Bắt buộc | Ghi chú |
|---|---|---|
| `target` | ✅ | Phải nằm trong allowlist của deployment |
| `authorized_by` | ✅ | Không có thì trả `422` |
| `authorization_note` | | Ghi vào báo cáo |
| `scope_hosts` | | Mỗi host phải đã được operator cho phép. Có thể dùng `*.example.com` |
| `planner` | | `scripted` (mặc định) hoặc `llm` |
| `max_*`, `requests_per_second` | | Bị kẹp theo trần của deployment |

**Lưu ý:** không có trường nào để đổi scope, đổi quyền, bật active scan, hay chạy một
tool đơn lẻ. Đó là chủ ý, không phải thiếu sót.

### Mã lỗi

Mọi lỗi trả cùng một cấu trúc:

```json
{ "error": "mô tả ngắn", "detail": "chi tiết", "category": "forbidden_scope" }
```

| HTTP | `category` | Khi nào |
|---|---|---|
| `401` | `unauthorized` | Thiếu hoặc sai API key |
| `403` | `forbidden_scope` | Target ngoài uỷ quyền của deployment |
| `404` | `not_found` | Không có job với id đó |
| `409` | `conflict` | Báo cáo chưa sẵn sàng, hoặc job đã kết thúc |
| `422` | `invalid_request` | Body sai schema |
| `503` | `service_unavailable` | Service đang tắt, không nhận job mới |

### Ví dụ response `403`

```json
{
  "error": "the requested target is outside this deployment's authorisation",
  "detail": "target: host 'evil.test' is not authorised by this deployment. Authorised hosts: staging.example.com. An operator can add it with --api-allowed-host.",
  "category": "forbidden_scope"
}
```

Thông báo được viết để bạn có thể copy gửi thẳng cho người đang xin quyền truy cập.

---

## 10. Đọc báo cáo

Mỗi scan tạo một thư mục trong `runs/`:

```
runs/<job-id>/
├── job.json      # metadata: scope, config, trạng thái, thờigian
├── events.log    # log đầy đủ
├── report.json   # báo cáo máy đọc
├── report.md     # báo cáo người đọc
└── artifacts/    # ảnh chụp màn hình (nếu bật)
```

### Cấu trúc `report.json`

| Khối | Nội dung |
|---|---|
| `scope` | Scope **thực tế** đã dùng |
| `config` | Ngân sách **thực tế** đã áp dụng (đã kẹp theo trần) |
| `authorization` | Ai uỷ quyền, ghi chú gì |
| `findings[]` | Từng lỗ hổng, có `evidence[]` trỏ về `tool_call_index` |
| `merged_observations[]` | Finding nào gộp nhiều quan sát, gộp bao nhiêu |
| `attack_surface` | Trang, URL, form, script, API route đã thu thập |
| `checks_executed[]` | Tool nào **đã chạy thành công** |
| `checks_skipped[]` | Tool nào bị từ chối/lỗi, vì sao |
| `tool_trace[]` | Toàn bộ nhật ký gọi tool |
| `limitations[]` | Những gì scan này **không** làm được |
| `disclaimer` | Cảnh báo pháp lý |

### Vì sao mỗi finding đều có evidence

Mỗi finding mang theo mảng `evidence`, mỗi phần tử có `tool`, `tool_call_index`, `url`,
`observed`, `expected`. `tool_call_index` trỏ vào `tool_trace` — nghĩa là bạn luôn truy
ngược được: *finding này do lần gọi tool nào sinh ra, quan sát được giá trị gì*.

Đây là điều phân biệt báo cáo này với một danh sách phỏng đoán. Nếu không truy ngược
được, nó không nằm trong báo cáo.

### Mục `merged_observations`

Một lỗ hổng được định danh bằng `category + host + location`, **không** phải bằng URL. Vì
vậy "thiếu CSP" thấy trên 3 trang của cùng một host là **một** finding với 3 dòng evidence,
không phải 3 finding trùng lặp.

Ví dụ từ target demo: **39 quan sát thô gộp thành 13 finding**. Không mất thông tin nào —
mọi URL vẫn nằm trong `evidence`.

---

## 11. Bật AI planner thật

Mặc định `--planner scripted` là một playbook recon cố định, chạy không cần API key. Để AI
tự chọn tool:

### CLI

```bash
export DAST_API_KEY=sk-...
.venv/Scripts/python.exe -m app.main scan https://example.com \
    --planner llm --model gpt-4o-mini --authorized-by "ban@congty.com"
```

```powershell
$env:DAST_API_KEY = "sk-..."
.\.venv\Scripts\python.exe -m app.main scan https://example.com `
    --planner llm --model gpt-4o-mini --authorized-by "ban@congty.com"
```

### Dùng endpoint OpenAI-compatible khác

```bash
.venv/Scripts/python.exe -m app.main scan https://example.com \
    --planner llm --model qwen3 --base-url http://localhost:8000/v1 \
    --authorized-by "ban@congty.com"
```

Hoạt động với OpenAI, DeepSeek, OpenRouter, vLLM, LM Studio, Ollama — bất cứ thứ gì nói
được chat-completions API.

### Qua service

```powershell
$env:DAST_API_KEY = "sk-..."
.\.venv\Scripts\python.exe -m app.main serve `
    --api-allowed-host "*.example.com" `
    --api-planner-llm --api-model gpt-4o-mini `
    --port 8093
```

Sau đó request dùng `"planner": "llm"`.

**API key của LLM thuộc về service, không bao giờ nhận từ request.** Người gọi API không
thể cung cấp key riêng.

### AI được và không được làm gì

AI **chỉ** chọn tool, truyền tham số hợp lệ, đọc kết quả, quyết định dừng, phân loại
finding, và viết summary. AI **không thể**:

- chạy shell (không tool nào nhận lệnh)
- tự gửi HTTP request (chỉ có tool build request của chính nó)
- sinh payload tuỳ ý (không request model nào có trường payload)
- đổi scope (scope chốt một lần, bất biến)
- chạm host ngoài allowlist (scope guard chặn trước khi mở socket)
- submit form, xác thực, upload (không tool nào làm được)

Đây không phải lời hứa trong prompt. Đây là **thuộc tính của cấu trúc dữ liệu** — những
hành động đó không biểu diễn được trong `PlannerDecision`. Test suite khẳng định điều này.

---

## 12. Xử lý sự cố

### `ModuleNotFoundError: No module named 'playwright'`

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### `Executable doesn't exist at ...chromium...`

```powershell
.\.venv\Scripts\python.exe -m playwright install chromium
```

### `browser_open` trả về lỗi timeout

Target chậm hoặc chặn headless browser. Thử tăng timeout:

```powershell
.\.venv\Scripts\python.exe -m app.main scan https://example.com `
    --request-timeout 30 --tool-timeout 90 --authorized-by "ban@congty.com"
```

### `out of scope: host '...' is not in scope`

Host chưa được cho phép. Thêm bằng `--scope-host` (CLI) hoặc `--api-allowed-host` (service).
Thông báo lỗi liệt kê danh sách host đang được phép.

### `private ranges require --allow-private`

Target là địa chỉ private/loopback. Thêm `--allow-private` (CLI) hoặc `--api-allow-private`
(service) — nhưng chỉ khi bạn thật sự kiểm soát mạng đó.

### Service trả `job is queued` mãi không chạy

Worker không khởi động. Kiểm tra log service có dòng `Application startup complete`. Nếu
không, xem có exception lúc khởi động không.

### `error: binding to '0.0.0.0' requires --api-key`

Đây là bảo vệ chủ ý. Đặt `$env:DAST_SERVICE_KEY` hoặc dùng `--api-key`, hoặc bind về
`127.0.0.1`.

### Service chạy chậm lần đầu

Import Playwright mất khoảng 10–12 giây. Bình thường, không phải lỗi.

### Muốn xem service đang thực sự được phép làm gì

```powershell
Invoke-RestMethod http://127.0.0.1:8093/v1/capabilities
```

Hoặc bấm **Xem giới hạn** trong Web UI.

---

## 13. Hiểu đúng về kết quả

Phần này quan trọng nhất. Đọc kỹ trước khi báo cáo kết quả cho ai.

### Công cụ này tìm được gì

**Lỗ hổng cấu hình và lộ thông tin** — có thật, có CWE, thuộc OWASP Top 10:

- CORS `Access-Control-Allow-Origin: *` kèm `Allow-Credentials: true` → bất kỳ site nào
  cũng đọc được response đã xác thực (**A05**)
- Cookie session thiếu `HttpOnly` → mọi XSS leo thang thành chiếm session (**A07**)
- Cookie thiếu `Secure` → attacker cùng mạng đọc được session (**A02**)
- Cookie thiếu `SameSite` → yếu phòng chống CSRF (**A01**)
- Thiếu HSTS → TLS stripping ở request đầu tiên (**A02**)
- Thiếu CSP → XSS dễ khai thác hơn nhiều (**A03**)
- Thiếu X-Frame-Options/COOP/CORP → clickjacking, rò rỉ cross-origin
- Lộ `Server`/`X-Powered-By` → tăng tốc tấn công có chủ đích

### Công cụ này KHÔNG tìm được gì

App có thể kiểm tra **error-based SQL injection** và ghi nhận thay đổi hành vi từ một số
NoSQL operator bằng `run_injection_check` khi được bật với `--injection` hoặc
`--injection-only`. Payload do harness sở hữu; caller không thể tự cung cấp payload.

App vẫn không phát hiện XSS, SSTI, SSRF, IDOR, auth bypass, path traversal, command
injection, business logic flaw, hoặc các dạng SQLi union/boolean-blind/time-based/stacked.

Với các lớp chưa hỗ trợ, lý do vẫn là **thiếu năng lực gửi input phù hợp**:

| Thành phần của một lỗ hổng | App thấy được? |
|---|---|
| Điểm vào — tham số `q` tồn tại | ✅ `extract_links` trả `query_keys` |
| Đường đi — `q` chảy vào truy vấn nào | ❌ |
| Hành vi lỗi — query không tham số hoá | ❌ |

Không có cái thứ 2 và 3 thì **không thể kết luận**. Đó là lý do active scan tồn tại: gửi
`q='` rồi so sánh response với `q=shoes` — sự khác biệt *là* bằng chứng. Passive scan
không có phép so sánh nào.

3 tool mở rộng (`run_zap_baseline`, `run_authenticated_crawl`, `run_openapi_scan`) đã được khai báo nhưng
`implemented=False`. Chúng hiện trong `/v1/tools` và **không bao giờ được đưa cho AI**.

### "Không có finding" không có nghĩa là "an toàn"

Báo cáo luôn ghi rõ nó đã chạy những check nào trong `checks_executed`. Không có finding
nghĩa là *các check đó* không phát hiện gì. Nó **không** có nghĩa ứng dụng không có lỗ hổng.

Mục `limitations[]` trong mọi báo cáo liệt kê:
- Chỉ kiểm tra injection theo catalogue read-only khi operator bật; không fuzz, không submit form
- Không xác thực: mọi thứ sau login chưa được đánh giá
- Độ sâu có giới hạn: inventory là mẫu, không phải bản đồ đầy đủ
- Header/cookie phụ thuộc route, thiết bị, địa lý, thời điểm
- Kết quả tự động **cần người review** trước khi coi là lỗ hổng đã xác nhận

### Subresource bên thứ ba

Khi mở một trang, browser sẽ tải script/style/font/image từ host khác (CDN, analytics).
App **cho phép** việc này vì chặn sẽ làm hỏng hầu hết site thật.

Quy tắc:
- `fetch`/XHR/WebSocket → **phải** trong scope, nếu không bị chặn
- script/stylesheet/image/font/media → cho phép, **và ghi vào báo cáo**

Hệ quả: quét target nội bộ có thể khiến HTML của nó gọi CDN public. Report ghi lại điều
này. Đây là điều không tránh được với bất kỳ scanner dùng browser nào — và là lý do scope
mặc định rất hẹp, còn `--allow-private` phải bật thủ công.

### Tỉ lệ false positive

Mọi finding trong báo cáo đều có evidence quan sát được. Không có finding nào được sinh ra
từ suy đoán. Nói cách khác: nếu báo cáo nói thiếu header, header đó thật sự thiếu — bạn
kiểm tra lại bằng `curl -I` sẽ thấy.

Điều này khác với active scanner, nơi "nghi ngờ SQLi" thường có 50–90% false positive.

---

## Phụ lục — Tham chiếu nhanh

```powershell
# Xem danh mục tool
.\.venv\Scripts\python.exe -m app.main tools
.\.venv\Scripts\python.exe -m app.main tools --schema

# Quét một lần
.\.venv\Scripts\python.exe -m app.main scan https://example.com --authorized-by "ban"

# Service local
.\.venv\Scripts\python.exe -m app.main serve --api-allowed-host example.com --port 8093

# Service cho team
$env:DAST_SERVICE_KEY = "chuoi-ngau-nhien-dai"
.\.venv\Scripts\python.exe -m app.main serve --api-allowed-host "*.example.com" --host 0.0.0.0 --port 8080

# Chạy test
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pytest -m "not integration"   # nhanh, không cần browser
.\.venv\Scripts\python.exe -m pytest tests/test_scope.py     # chỉ ranh giới bảo mật
```

Đọc thêm: [SECURITY-MODEL.md](SECURITY-MODEL.md) (mô hình mối đe dọa, giới hạn thật sự) ·
[ARCHITECTURE.md](ARCHITECTURE.md) (thiết kế các tầng) · [ROADMAP.md](ROADMAP.md) (làm gì tiếp).
