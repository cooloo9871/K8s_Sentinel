# Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="Sentinel" width="320" />
</p>

Sentinel 是一個部署在 Kubernetes 叢集內的 **Cilium Tetragon 安全策略管理 console**。透過網頁介面即可建立、編輯、刪除 TracingPolicy，即時監控叢集內的安全事件，並自動學習 Pod 行為以輔助策略建立，不需要直接操作 `kubectl`。

---

## 功能

### Policies

**TracingPolicy 管理**
- 列表搜尋、新增、編輯、刪除，支援 `TracingPolicy`（cluster-wide）與 `TracingPolicyNamespaced`（namespace-scoped）兩種範疇
- 支援指定 Pod Selector（Label 篩選）

**表單編輯器**
- Process Rules：攔截指定 binary 的執行（`sys_execve`）
  - **Whitelist** 模式（NotPostfix，預設）：只允許列出的 binary 執行，其他全封鎖
  - **Blacklist** 模式（Postfix）：封鎖列出的 binary，其他允許
- File Rules：監控指定路徑的檔案存取（`security_file_permission`，Blacklist）
- Network Rules：管控對外連線，支援 Blacklist（DAddr）與 Whitelist（NotDAddr）兩種模式，可搭配 Port 限制
- 即時 YAML Preview，切換 Tab 時自動同步

**YAML 編輯器**
- 直接貼上或編輯原始 YAML，內建語法驗證

**執行模式（Mode）**
- 每條 Policy 可獨立設定 Monitoring（Post，觀測不攔截）或 Protect（Sigkill，主動終止違規行為）
- Global Enforcement Mode：一鍵將所有 Policy 切換為同一模式，僅在手動設定時變更

**Behavior Discovery（行為探索）**
- 從 Tetragon base sensor 與 process cache 自動學習叢集中各 Pod 執行過的 process binary
- **不需要建立任何 TracingPolicy**，無額外叢集資源負擔
- Sentinel 啟動時透過 `tetra dump processcache` 取得所有節點已在執行的進程（含 Sentinel 啟動前），後續持續透過事件流收集新進程
- 自動依 Controller 分組顯示（Deployment / DaemonSet / StatefulSet / Pod），同一個 Deployment 的多個副本合併為一張卡片，顯示聯集 binary 列表
- **資料夾圖示按鈕**：切換至 Namespace 分組視圖，每個 Namespace 以獨立色塊框包覆，框內顯示該 namespace 下所有 workload 卡片
- Namespace 篩選 + Pod 名稱搜尋
- **Create Policy**：一鍵從學習到的資料預填 Policy 表單，自動帶入：
  - Policy 名稱（`{workload}-policy`）
  - 目標 Namespace
  - Pod Selector（從 pod labels 自動取得，過濾 auto-generated labels，pod 重啟後仍有效）
  - Process Rules（Whitelist 模式，每個學習到的 binary 各為一條規則）

---

### Notifications

**Security Events**
- 即時串流叢集所有 Tetragon kprobe 事件，永久保存於瀏覽器 localStorage，重新整理不消失
- 僅顯示有明確 policy 名稱的策略觸發事件，排除背景噪音
- 嚴重程度分類：Warning（monitor，偵測未攔截）/ Critical（kill，已攔截終止）
- 點擊展開詳情：違規檔案路徑（File Rule）、網路目標 IP:port（Network Rule）、binary 完整路徑、arguments、執行的 effective user（root 或 uid=N）、parent binary、觸發的 kprobe function、節點名稱、完整時間戳（台灣時區）；所有超長內容自動換行，不需橫向捲動
- Rule Type 標籤：自動識別 File Rule / Network Rule / Process Rule
- 搜尋 Pod 名稱、依嚴重程度篩選
- 每個 event 獨立展開，互不干擾
- 時間顯示：秒 → 分 → 時 → 天（超過 24 小時以天為單位）
- 自動解析 `runc exec` 與 `kubectl exec` 觸發的事件：從 container ID 或 parent 進程反查 Kubernetes pod/namespace

---

### Cluster

**Namespaces**
- 列出叢集所有 Namespace 與套用的 Policy 數量

---

### Dashboard

- Policy 總數、執行模式、Namespace 數量一覽
- Recent Policies 唯讀顯示（不可點擊進入編輯）
- 可直接切換 Global Enforcement Mode

---

## 部署到 Kubernetes

### 前置需求

- Kubernetes 1.26+ 叢集，已安裝 Cilium 並啟用 Tetragon（TracingPolicy CRD）v1.3+
- `kubectl` 已設定好 kubeconfig
- container registry 存取權限（若需自行 build image）

---

### 步驟一：Clone 專案

```bash
git clone https://github.com/cooloo9871/Sentinel.git
cd Sentinel
```

---

### 步驟二：更新 container image（選用）

若要使用自行 build 的 image，編輯 `deploy/base/deployment.yaml`：

```yaml
containers:
  - name: sentinel
    image: your-registry/sentinel:your-tag  # 替換此行
```

Build 並推送 image：

```bash
podman build -t your-registry/sentinel:latest .
podman push your-registry/sentinel:latest
```

預設使用公開 image `quay.io/cooloo9871/sentinel:latest`，可直接跳過此步驟。

---

### 步驟三：部署

**方式 A — Kubernetes Job（推薦，不需要本機 helm）**

```bash
kubectl apply -f deploy/install-job.yaml
kubectl logs -n kube-system job/sentinel-installer -f
```

Job 執行流程：
1. 偵測是否已有 Tetragon DaemonSet，沒有則透過 Helm 安裝最新版
2. Clone Sentinel 原始碼
3. 建立 `sentinel-system` namespace（已存在則跳過）
4. 套用 Sentinel K8s 資源並等待 Deployment 就緒

**方式 B — 本機安裝腳本**

```bash
bash deploy/install.sh
kubectl get all -n sentinel-system
```

---

### 步驟四：存取 UI

```bash
kubectl port-forward -n sentinel-system svc/sentinel 8080:80
# 開啟瀏覽器：http://localhost:8080
```

---

### 部署的 Kubernetes 資源

| 資源 | 名稱 | 說明 |
|------|------|------|
| Namespace | `sentinel-system` | 所有資源的 namespace |
| ServiceAccount | `sentinel` | Pod 使用的服務帳號 |
| ClusterRole | `sentinel` | TracingPolicy CRUD + Namespace/Pod/Apps 讀取權限 |
| ClusterRoleBinding | `sentinel` | 綁定 ServiceAccount 與 ClusterRole |
| Deployment | `sentinel` | 應用程式 Pod，1 個 replica |
| Service | `sentinel` | ClusterIP，port 80 → 8080 |

---

### RBAC 權限說明

| API Group | 資源 | 操作 |
|-----------|------|------|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | get, list, watch, create, update, patch, delete |
| `""` (core) | `namespaces`, `pods`, `pods/exec` | get, list |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |

---

### 解除安裝

```bash
kubectl delete -k deploy/base/
kubectl delete namespace sentinel-system
```

---

## 本機開發

```bash
# 後端（需要 kubeconfig）
go run ./cmd/server/

# 前端 Dev Server（自動 proxy /api → localhost:8080）
cd web && npm install && npm run dev
```

---

## 授權

[Apache License 2.0](LICENSE)
