# Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="Sentinel" width="320" />
</p>

**Sentinel** 是一個部署在 Kubernetes 叢集內的 **Cilium Tetragon 安全策略管理 console**，讓你不需要操作 `kubectl` 或手寫 YAML，就能透過網頁介面管理 TracingPolicy、監控安全事件、自動學習 Pod 行為，讓你完整掌握 K8s workload 實現零信任的關鍵技術。

---

## 功能總覽

### Policies — 策略管理

- 建立、編輯、刪除 TracingPolicy（cluster-wide 或 namespace-scoped）
- 依 namespace、scope 篩選策略清單
- **Process Rules**：控制哪些 binary 可以執行（Whitelist / Blacklist）
- **File Rules**：控制哪些檔案路徑可以存取（Blacklist，支援 Prefix 比對）；可指定僅封鎖讀取或寫入；可設定例外 process
- **Network Rules**：控制對外連線（Whitelist / Blacklist，支援 IP 與 Port）
- 每條 Policy 可個別切換 Monitoring（觀測）/ Protect（封鎖）模式
- **Global Protect Mode**：一鍵 Turn On / Turn Off 所有 Policy 的封鎖模式
- 即時 YAML Preview；支援直接以 YAML 建立或修改 Policy
- **Created By**：記錄每條 Policy 的建立者；透過 `kubectl apply` 建立的顯示 `k8s-apply`
- **Policy Templates**：內建常用範本與自訂範本；點擊 **Use Template** 可設定名稱後直接建立 Policy；點擊 **Open in Editor** 可檢視或修改自訂範本 YAML（僅限儲存，不可從 editor 建立 Policy）；範本資料儲存在 `/data/sentinel/templates.json`（可掛 PV 永存）

### Behavior Discovery — 行為探索

- 自動學習叢集中各 Pod 執行過的 process，**不需要任何 TracingPolicy**
- 依 Deployment / DaemonSet / StatefulSet 分組顯示（同一 workload 的多個副本合併）
- 資料夾圖示可切換 Namespace 分組視圖
- 副本數增減時自動更新（最多 60 秒同步）
- **Create Policy**：一鍵從學習到的資料預填 Policy 表單，帶入 Pod Selector 與 Process Rules（Whitelist 模式）

### Notifications — 安全通知

- 即時串流叢集所有 Tetragon kprobe 事件；重新整理後不消失（7 天 TTL）
- Warning（偵測未攔截）/ Critical（已攔截終止）嚴重程度分類；Warning 最多 300 條、Critical 最多 200 條，兩者獨立上限
- 依 Namespace、Pod 名稱、嚴重程度篩選
- 點擊展開事件詳情：違規路徑、網路目標、執行 user（UID）、Pod / Container、Policy 名稱、parent process 等
- **Pause / Resume**：暫停畫面更新，慢慢讀取目前事件，Resume 後一次刷入所有暫存事件
- 時間顯示支援秒、分、時、天

### Cluster — 叢集資訊

- Namespace 列表及各 Namespace 的 Policy 數量
- **Tetragon Agents**：各節點 Tetragon DaemonSet pod 的健康狀態（Ready / Not Ready / Failed）、重啟次數、啟動時間，每 30 秒自動刷新

### Dashboard — 總覽

- Policy 數量、Namespace 數量、Global Protect Mode 狀態一覽
- 快速切換 Global Protect Mode

### 使用者管理 — User Management

- 本地帳號登入（JWT，有效期 24 小時）
- **Admin**：完整操作權限，包含建立/修改/刪除 Policy、管理使用者
- **Viewer**：唯讀，可瀏覽所有頁面及查看 Policy / Template YAML，無法執行任何寫入操作
- 首次啟動自動建立預設帳號 `admin` / `admin`，請立即修改密碼
- 使用者資料儲存在 `/data/sentinel/users.json`（可掛 PV 永存）

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

### 持久化儲存（PV）

Sentinel 將使用者、Templates 及 JWT secret 存放於 `/data/sentinel/`。掛載 PersistentVolume 可在 Pod 重啟後保留資料：

```yaml
volumeMounts:
  - name: data
    mountPath: /data/sentinel
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: sentinel-data
```

> Pod 以 `sentinel` user（UID 10001）執行，PV 需設定 `fsGroup: 10001`。

---

## RBAC 權限

| API Group | 資源 | 操作 |
|---|---|---|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | CRUD |
| `""` (core) | `namespaces`, `pods`, `pods/exec` | get, list |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |

---

## 授權

[MIT License](LICENSE)
