# Sentinel

Sentinel 是一個輕量的 Kubernetes 管理 console，專為管理 **Cilium TracingPolicy** 而設計。提供表單式編輯器與原始 YAML 編輯器，並支援叢集層級的 Monitoring / Protect 模式切換。

![UI Style](https://img.shields.io/badge/UI-CoreUI%20%2F%20NeuVector%20Style-2d7dd2)
![Go](https://img.shields.io/badge/Go-1.22-00ADD8)
![React](https://img.shields.io/badge/React-19-61DAFB)
![License](https://img.shields.io/badge/License-Apache%202.0-blue)

---

## 功能特色

- **Dashboard**：Policy 數量、執行模式、Namespace 統計一覽
- **TracingPolicy 管理**：列表、新增、編輯、刪除，支援搜尋與 Scope 篩選
- **雙模式編輯器**：表單式 UI（含即時 YAML 預覽）與 Monaco YAML 編輯器
- **執行模式切換**：Monitoring ↔ Protect，含切換確認對話框
- **Namespace 檢視**：列出所有 Namespace 與其 Policy 數量
- **JWT 身份驗證**：bcrypt 密碼雜湊，Session cookie 管理

---

## 技術架構

```
┌─────────────────────────────────────────────────┐
│  Browser                                        │
│  React 19 + CoreUI React 5 + Bootstrap 5        │
│  Monaco Editor (YAML)                           │
└────────────────────┬────────────────────────────┘
                     │ HTTP / REST API
┌────────────────────▼────────────────────────────┐
│  Go HTTP Server (chi router)                    │
│  JWT Auth Middleware                            │
│  ┌─────────────┐  ┌──────────────────────────┐ │
│  │  Auth       │  │  Policy / Mode / NS      │ │
│  │  Handler    │  │  Handlers                │ │
│  └─────────────┘  └──────────┬───────────────┘ │
└─────────────────────────────-┼─────────────────┘
                               │ Kubernetes API
┌──────────────────────────────▼─────────────────┐
│  Kubernetes Cluster                             │
│  cilium.io/TracingPolicy CRDs                  │
│  cilium.io/TracingPolicyNamespaced CRDs        │
└─────────────────────────────────────────────────┘
```

---

## 前置需求

- Kubernetes 1.26+（含 Cilium 與 TracingPolicy CRD）
- 容器 registry 存取權限（部署時）
- `kubectl` + `kustomize`（或 `kubectl apply -k`）

---

## 快速部署

### 1. 設定認證憑證

編輯 `deploy/base/secret.yaml`，替換預設的密碼 hash 與 JWT Secret：

```bash
# 產生 bcrypt 密碼 hash（需安裝 htpasswd 或使用 Python）
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt(12)).decode())"
```

```yaml
# deploy/base/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: sentinel-credentials
  namespace: sentinel-system
type: Opaque
stringData:
  admin: <bcrypt-hash-of-your-password>
  jwt-secret: <your-random-jwt-secret>
```

> ⚠️ **安全警告**：絕對不要使用預設憑證上生產環境。

### 2. 部署到叢集

```bash
kubectl apply -k deploy/base/
```

確認 Pod 正常啟動：

```bash
kubectl get pods -n sentinel-system
# NAME                        READY   STATUS    RESTARTS   AGE
# sentinel-xxxxxxxxx-xxxxx    1/1     Running   0          30s
```

### 3. 存取 UI

```bash
# Port-forward 到本機
kubectl port-forward -n sentinel-system svc/sentinel 8080:8080

# 或透過 Ingress（依叢集設定）
```

開啟瀏覽器前往 `http://localhost:8080`，使用 `admin` 帳號登入。

---

## 容器映像

預設映像：`quay.io/cooloo9871/sentinel:latest`

### 自行 Build 映像

```bash
# 從專案根目錄執行
docker build -t your-registry/sentinel:latest .
docker push your-registry/sentinel:latest
```

更新 `deploy/base/deployment.yaml` 中的 `image` 欄位後重新部署：

```bash
kubectl apply -k deploy/base/
```

---

## 本機開發

### 後端（Go）

```bash
# 確保有 kubeconfig 或 in-cluster 設定
go run ./cmd/server/

# 預設監聽 :8080
# API 路由：/api/...
# 靜態檔案：/（嵌入 web/dist/）
```

### 前端（React + Vite）

```bash
cd web
npm install
npm run dev
# Dev server：http://localhost:5173
# API proxy：/api → http://localhost:8080
```

### 測試

```bash
# Go 後端測試
go test ./...

# 前端測試
cd web && npm run test
```

---

## API 參考

所有 API 端點需附帶有效的 JWT cookie（登入後自動設定）。

| Method | Path | 說明 |
|--------|------|------|
| `POST` | `/api/auth/login` | 登入，回傳 JWT cookie |
| `POST` | `/api/auth/logout` | 登出，清除 cookie |
| `GET` | `/api/policies` | 列出所有 TracingPolicy |
| `GET` | `/api/policies/:name` | 取得單一 Policy（`?namespace=` 可選） |
| `POST` | `/api/policies` | 建立 Policy（form 或 yaml 來源） |
| `PUT` | `/api/policies/:name` | 更新 Policy |
| `DELETE` | `/api/policies/:name` | 刪除 Policy（`?namespace=` 可選） |
| `POST` | `/api/policies/preview` | 預覽 form 轉 YAML（不寫入） |
| `GET` | `/api/mode` | 取得目前執行模式 |
| `PUT` | `/api/mode` | 切換執行模式（`Monitoring` / `Protect`） |
| `GET` | `/api/namespaces` | 列出所有 Namespace |

### 建立 Policy 範例

```bash
# 從表單資料建立
curl -X POST http://localhost:8080/api/policies \
  -H "Content-Type: application/json" \
  -b "token=<jwt>" \
  -d '{
    "source": "form",
    "form": {
      "name": "my-policy",
      "namespace": "default",
      "process": [{"binaries": ["/usr/bin/nginx"]}]
    },
    "action": "Post"
  }'

# 從 YAML 建立
curl -X POST http://localhost:8080/api/policies \
  -H "Content-Type: application/json" \
  -b "token=<jwt>" \
  -d '{
    "source": "yaml",
    "rawYaml": "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\n..."
  }'
```

---

## 執行模式說明

| 模式 | 說明 |
|------|------|
| **Monitoring** | 記錄違規行為但不攔截（`Post` action） |
| **Protect** | 主動終止違規行為（`Sigkill` action） |
| **Mixed** | 部分 Policy 為 Monitoring，部分為 Protect |

切換模式會影響後續透過表單建立或更新的 Policy 所套用的 action。

---

## RBAC 權限

Sentinel 需要以下 ClusterRole 權限：

```yaml
rules:
  - apiGroups: ["cilium.io"]
    resources: ["tracingpolicies", "tracingpoliciesnamespaced"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["sentinel-credentials"]
    verbs: ["get"]
```

---

## 專案結構

```
sentinel/
├── cmd/server/          # Go 應用程式進入點
├── internal/
│   ├── auth/            # JWT 驗證與 bcrypt
│   ├── handler/         # HTTP 路由與 middleware
│   ├── k8s/             # Kubernetes client 與 CRUD
│   └── policy/          # TracingPolicy YAML 產生邏輯
├── web/
│   ├── src/
│   │   ├── api/         # Axios client 與型別定義
│   │   ├── components/  # 可重用 UI 元件
│   │   ├── layout/      # AppLayout、AppSidebar、AppHeader、AppToaster
│   │   ├── pages/       # 各頁面元件
│   │   └── utils/       # formToYaml 工具函式
│   └── package.json
├── deploy/
│   └── base/            # Kustomize 資源（RBAC、Deployment、Service、Secret）
└── Dockerfile           # 多階段 build（Node → Go → distroless）
```

---

## 授權

[Apache License 2.0](LICENSE)
