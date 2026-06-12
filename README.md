# Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="Sentinel" width="320" />
</p>

Sentinel 是一個部署在 Kubernetes 叢集內的 **Cilium Tetragon 安全策略管理 console**，讓你透過網頁介面管理 TracingPolicy、監控安全事件、自動學習 Pod 行為。

---

## 功能總覽

### Policies — 策略管理

- 建立、編輯、刪除 TracingPolicy（cluster-wide 或 namespace-scoped）
- 依 namespace、scope 篩選策略清單
- **Process Rules**：控制哪些 binary 可以執行（Whitelist / Blacklist）
- **File Rules**：控制哪些檔案路徑可以存取（Blacklist，支援 Prefix 比對）；可指定僅封鎖讀取或寫入；可設定例外 process
- **Network Rules**：控制對外連線（Whitelist / Blacklist，支援 IP 與 Port）
- 每條 Policy 可個別切換 Monitoring（觀測）/ Protect（封鎖）模式
- **Global Enforcement Mode**：一鍵切換所有 Policy 為同一模式
- 即時 YAML Preview；支援直接以 YAML 建立或修改 Policy

### Behavior Discovery — 行為探索

- 自動學習叢集中各 Pod 執行過的 process，**不需要任何 TracingPolicy**
- 依 Deployment / DaemonSet / StatefulSet 分組顯示（同一 workload 的多個副本合併）
- 資料夾圖示可切換 Namespace 分組視圖
- 副本數增減時自動更新（最多 60 秒同步）
- **Create Policy**：一鍵從學習到的資料預填 Policy 表單，帶入 Pod Selector 與 Process Rules（Whitelist 模式）

### Notifications — 安全通知

- 即時串流叢集所有 Tetragon kprobe 事件；重新整理後不消失
- Warning（偵測未攔截）/ Critical（已攔截終止）嚴重程度分類
- 依 Namespace、Pod 名稱、嚴重程度篩選
- 點擊展開事件詳情：違規路徑、網路目標、執行 user（UID）、parent process 等
- 時間顯示支援秒、分、時、天

### Cluster — 叢集資訊

- Namespace 列表及各 Namespace 的 Policy 數量

### Dashboard — 總覽

- Policy 數量、Namespace 數量、Global Enforcement Mode 一覽
- 快速切換全域執行模式

---

## 部署

### 前置需求

- Kubernetes 1.26+，已安裝 Cilium + Tetragon（TracingPolicy CRD，建議 v1.3+）
- `kubectl` 已設定 kubeconfig

### 步驟

**Clone 專案**

```bash
git clone https://github.com/cooloo9871/Sentinel.git
cd Sentinel
```

**方式 A — Kubernetes Job（不需本機 helm）**

```bash
kubectl apply -f deploy/install-job.yaml
kubectl logs -n kube-system job/sentinel-installer -f
```

**方式 B — 本機腳本**

```bash
bash deploy/install.sh
```

### 存取 UI

```bash
kubectl port-forward -n sentinel-system svc/sentinel 8080:80
# 開啟 http://localhost:8080
```

---

## RBAC 權限

| API Group | 資源 | 操作 |
|---|---|---|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | CRUD |
| `""` (core) | `namespaces`, `pods`, `pods/exec` | get, list |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |

---

## 本機開發

```bash
go run ./cmd/server/          # 後端（需 kubeconfig）
cd web && npm install && npm run dev  # 前端 dev server
```

---

## 授權

[Apache License 2.0](LICENSE)
