# Sentinel UI 重設計設計文件

**日期：** 2026-06-02
**作者：** andy
**狀態：** 已確認，待實作

---

## 背景

Sentinel 是一個 Kubernetes Cilium TracingPolicy 管理 console，目前前端使用 React 19 + Ant Design v6 + Vite。本次重設計目標是將 UI 風格改為接近 NeuVector 的企業資安管理 console 外觀（CoreUI 風格後台模板），並同時重新設計 UX 流程。

---

## 設計決策

| 決策點 | 選擇 |
|---|---|
| 技術框架 | 保留 React 19 + Vite + TypeScript（不切換 Angular） |
| UI 庫 | **Ant Design → CoreUI React**（`@coreui/react` + `bootstrap`） |
| 版面 | 固定深色左側邊欄 + 淺色內容區（NeuVector 預設主題） |
| 配色 | 深海軍藍 Sidebar（`#1b2a3b`）+ 淺灰白內容區（`#f5f6fa`）|
| 主色調 | `#2d7dd2`（CoreUI 藍） |
| 重設計範疇 | 換皮 + 重新設計 UX（新增 Dashboard + 重組 Sidebar 多層導覽） |

---

## 技術棧變更

### 移除

```
antd
@ant-design/icons
```

### 新增

```
@coreui/react       # 核心 UI 元件庫
@coreui/icons-react # 圖示元件
@coreui/icons       # 圖示資源
bootstrap           # CoreUI 底層 CSS
```

### 保留不動

- React 19、Vite、TypeScript、React Router DOM 7
- `web/src/api/client.ts`、`web/src/api/types.ts`（API 層完全不改）
- `@monaco-editor/react`（YAML 編輯器）
- `js-yaml`、`web/src/utils/formToYaml.ts` 及其測試
- 所有 Go 後端（`internal/`、`cmd/`、`deploy/`）

---

## 路由與導覽結構

```
/login                    → LoginPage（重設計，獨立於 sidebar layout）
/dashboard                → DashboardPage（新增）
/policies                 → PolicyListPage（重定向至 /policies/tracing）
/policies/tracing         → TracingPolicyListPage（重設計）
/policies/tracing/new     → PolicyEditPage（新建，重設計）
/policies/tracing/:name/edit → PolicyEditPage（編輯，重設計）
/cluster/mode             → ModePage（從 Header ModeToggle 獨立為頁面）
/cluster/namespaces       → NamespacesPage（新增，列出所有 namespace）
```

### Sidebar 結構

```
[Sentinel Logo]
─────────────────────
Dashboard
─────────────────────
POLICIES
  All Policies
    ↳ TracingPolicy       ← 目前唯一類型，保留擴充空間
─────────────────────
CLUSTER
  Mode Control            ← 原本在 Header 的 ModeToggle
  Namespaces
─────────────────────
[admin 頭像]  [登出]
```

### Header（頂部列）

- 左：Sidebar 折疊開關 + 麵包屑導覽
- 右：目前 Mode 狀態 Badge（唯讀）+ 使用者頭像 Dropdown

---

## 頁面設計

### 1. Dashboard（`/dashboard`）【新增】

**目的：** 提供叢集整體狀態一覽，作為登入後預設首頁。

**版面：**
- 4 個統計卡片（水平排列）：
  - Total Policies（藍色左邊框）
  - Current Mode（橘色左邊框，Monitoring / Protect）
  - Active Namespaces（綠色左邊框，`GET /api/namespaces` 回傳的總數量）
  - Cluster-scoped Policies（紅色左邊框）
- 主區塊（2 欄）：
  - 左（2/3）：Recent Policies 表格（最近 5 筆，欄位：Name / Scope / Namespace / Created）
  - 右（1/3）：Mode Control Widget（顯示目前模式 + 切換按鈕，點擊切換需確認）

**資料來源：**
- `GET /api/policies`（count + 最近 5 筆）
- `GET /api/mode`（目前模式）
- `GET /api/namespaces`（namespace 數量）

---

### 2. TracingPolicy List（`/policies/tracing`）【重設計】

**版面：**
- 頁首：標題 + "New Policy" 按鈕（右上角）
- 工具列：搜尋輸入框 + Scope 篩選下拉（所有 / namespace / cluster）+ 筆數顯示
- CoreUI CTable：
  - 欄位：Name（可點擊）/ Scope（CBadge）/ Namespace / Created / Actions
  - Actions：Edit 按鈕（輪廓藍）、Delete 按鈕（輪廓紅）
  - Delete 觸發 CModal 確認對話框（取代 Ant Design Popconfirm）
- 分頁器（CSmartPagination）

**Scope Badge 配色：**
- `namespace` → `color="primary"`（藍）
- `cluster` → `color="danger"`（紅）

---

### 3. Policy 編輯頁（`/policies/tracing/:name/edit`、`.../new`）【重設計】

**版面：**
- 頁首：標題（Edit Policy / New Policy）+ Policy 名稱副標題 + Save / Cancel 按鈕（右上角）
- CTabs（底線式）：Form | YAML
- **Form Tab（主要）：** 左右雙欄
  - 左欄（彈性寬度）：Bootstrap Card 分區
    - Basic Information Card：Name（必填）+ Namespace（CFormSelect）雙欄並排
    - Process Rules Card：動態列表 + Add / Remove 按鈕
    - File Rules Card：動態列表（路徑 + 操作類型 select）
    - Network Rules Card：動態列表（協定 / CIDR / Port）
  - 右欄（340px，sticky）：YAML Preview 深色面板（Monaco 風格，顯示即時 YAML + valid/invalid 狀態）
- **YAML Tab：** Monaco Editor 全寬（保留現有邏輯）

**表單狀態管理：** 從 `Form.useForm()` 改為 `useState` 陣列管理，不引入 React Hook Form（避免增加依賴）

---

### 4. Mode Control 頁（`/cluster/mode`）【從 Header 移出】

**版面：**
- 狀態卡片：目前模式（大字體顯示）
- 說明文字：Monitoring / Protect 各自的行為說明
- 切換按鈕：切換前顯示 CModal 確認（特別是切換至 Protect 時有警告）

---

### 5. Namespaces 頁（`/cluster/namespaces`）【新增】

**版面：**
- CTable 列出所有 namespace
- 每列顯示 namespace 名稱 + 該 namespace 下 Policy 數量（客戶端從 `GET /api/policies` 結果計算，無獨立 API）

---

### 6. Login 頁【重設計】

- 全頁居中卡片（不使用 Sidebar layout）
- CCard + CCardBody
- CForm 表單（帳號 / 密碼）+ CButton 登入
- CAlert 顯示錯誤訊息（取代 antd Alert）

---

## 元件對應表

| 類型 | Ant Design | CoreUI React / Bootstrap |
|---|---|---|
| 版面框架 | `Layout` | `CContainer` + CSS |
| 頂部列 | `Layout.Header` | `CHeader` + `CHeaderNav` |
| 側邊欄 | `Layout.Sider` | `CSidebar` + `CSidebarNav` |
| 內容區 | `Layout.Content` | `CContainer fluid` |
| 麵包屑 | `Breadcrumb` | `CBreadcrumb` + `CBreadcrumbItem` |
| 頁籤 | `Tabs` / `TabPane` | `CTabs` + `CTabList` + `CTabPanel` |
| 卡片 | `Card` | `CCard` + `CCardHeader` + `CCardBody` |
| 表格 | `Table` | `CTable` + `CTableHead` + `CTableBody` |
| 標籤/徽章 | `Tag` | `CBadge` |
| 表單container | `Form` + `Form.Item` | `CForm` + `CFormLabel` |
| 文字輸入 | `Input` | `CFormInput` |
| 下拉選單 | `Select` | `CFormSelect` |
| 切換開關 | `Switch` | `CFormSwitch` |
| 按鈕 | `Button` | `CButton` |
| 動態列表 | `Form.List` | `useState` 陣列 + add/remove |
| 對話框 | `Modal` / `Popconfirm` | `CModal` + `CModalHeader` + `CModalFooter` |
| 全域通知 | `message.error/success` | `CToast` + `CToaster` |
| 警告欄 | `Alert` | `CAlert` |
| 載入指示 | `Spin` | `CSpinner` |
| 下拉選單 | `Dropdown` | `CDropdown` + `CDropdownMenu` |
| 圖示 | `@ant-design/icons` | `@coreui/icons-react` |
| **YAML 編輯器** | `@monaco-editor/react` | `@monaco-editor/react`（不變） |

---

## 檔案結構變更

### 新增檔案

```
web/src/
├── layout/
│   ├── AppLayout.tsx           # 主框架（Sidebar + Header + Content）
│   ├── AppSidebar.tsx          # CSidebar + 多層導覽
│   ├── AppHeader.tsx           # CHeader + 麵包屑 + Mode Badge
│   └── AppToaster.tsx          # 全域 CToast container
├── pages/
│   ├── DashboardPage.tsx       # 新增
│   ├── ModePage.tsx            # 新增
│   ├── NamespacesPage.tsx      # 新增
│   ├── LoginPage.tsx           # 重寫
│   ├── PolicyListPage.tsx      # 重寫
│   └── PolicyEditPage.tsx      # 重寫
└── components/
    ├── StatCard.tsx             # Dashboard 統計卡片
    ├── PolicyForm/
    │   ├── PolicyForm.tsx       # 重寫（useState 取代 Form.useForm）
    │   ├── ProcessSection.tsx   # 重寫（Bootstrap 表單元件）
    │   ├── FileSection.tsx      # 重寫
    │   └── NetworkSection.tsx   # 重寫
    ├── ModeToggle.tsx           # 重寫（CFormSwitch）
    └── YamlEditor.tsx           # 保留（Monaco，僅調整container樣式）
```

### 刪除檔案

```
web/src/components/PolicyForm/YamlPreview.tsx  # 整合進 PolicyForm
```

---

## 不在範疇內

- 後端 Go 程式碼任何修改
- API 格式變更
- 新增認證機制
- i18n / 多語言
- 暗黑模式切換（固定淺色內容區）
- 單元測試更新（formToYaml.test.ts 不動）

---

## 成功標準

1. 所有現有功能正常運作（Policy CRUD、YAML 編輯、Mode 切換）
2. 視覺風格達到 NeuVector / CoreUI 企業資安 console 外觀
3. Sidebar 導覽正確對應所有路由
4. Dashboard 正確顯示 Policy 數量、Mode 狀態、Namespace 數量
5. `npm run build` 無錯誤、`npm run test` 通過
