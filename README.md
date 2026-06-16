# Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="Sentinel" width="320" />
</p>

**Sentinel** 是一個部署在 Kubernetes 叢集內的 **K8s 安全管理 console**，整合 Cilium Tetragon 執行期監控與 ValidatingAdmissionPolicy 控制，讓你不需要操作 `kubectl` 或手寫 YAML，就能透過網頁介面管理 Tracing Policy、Admission Policy、監控安全事件、推送告警，全面掌握 K8s workload 的零信任安全防線。

---

## 功能總覽

### Policies — 策略管理

- 建立、編輯、刪除 **Tracing Policy**（cluster-wide 或 namespace-scoped）
- 依 namespace、scope 篩選策略清單
- **Process Rules**：控制哪些 binary 可以執行（Whitelist / Blacklist）
- **File Rules**：控制哪些檔案路徑可以存取；可指定僅封鎖讀取或寫入；可設定例外 process
- **Network Rules**：控制對外連線（Whitelist / Blacklist，支援 IP 與 Port）
- 每條 Policy 可個別切換 Monitoring（觀測）/ Protect（封鎖）模式
- **Global Protect Mode**：一鍵 Turn On / Turn Off 所有 Policy 的封鎖模式
- **Created By**：記錄每條 Policy 的建立者；透過 `kubectl apply` 建立的顯示 `k8s-apply`
- **Policy Templates**：三個內建範本與自訂範本；可依名稱搜尋或依 Cluster-wide / Namespace 分類篩選
  - **Monitor All Process Executions**：監控叢集所有 Pod 的 process 執行
  - **Monitor All File Access**：監控敏感檔案讀寫（`security_file_permission`、`security_mmap_file`、`security_path_truncate`）
  - **Monitor All Network (Outside Cluster)**：偵測 Pod 連線到叢集外的行為；Pod CIDR、Service CIDR、Node IP 自動從叢集偵測
- **Admission Policy**（ValidatingAdmissionPolicy）：管理 K8s 原生 VAP 資源，支援 YAML 編輯器建立/修改 Policy 與 Binding

### Behavior Discovery — 行為探索

- 自動學習叢集中各 Pod 執行過的 process，**不需要任何 TracingPolicy**
- 依 Deployment / DaemonSet / StatefulSet 分組顯示
- **Create Policy**：一鍵預填 Policy 表單，帶入 Pod Selector 與 Process Rules

### Notifications — 安全通知

#### Security Events
- 即時串流叢集所有 Tetragon kprobe 事件；重新整理後不消失（7 天 TTL）
- Warning / Critical 嚴重程度分類；Warning 最多 500 條、Critical 最多 300 條，30 秒去重
- 點擊展開詳情：觸發檔案路徑與操作類型、網路連線目的地與來源、執行 user（UID）、Policy 名稱等
- **Pause / Resume**、**Export CSV**

#### Admission Events
- 記錄 ValidatingAdmissionPolicy 違規事件；依 namespace、severity 篩選
- **Critical**（`Deny` action，請求被阻擋）/ **Warning**（`Audit` action，請求放行但記錄）
- 來源：K8s Warning Events（controller 資源，免設定）或 **kube-apiserver audit webhook**（完整覆蓋，需設定）
- Audit webhook 設定：`POST /api/admission-events/webhook`（kube-apiserver 直接呼叫）
- 最多保留 500 筆，**自動持久化**至 `/data/sentinel/admission-events.json`（掛 PV 後永存，重啟不消失）

### Cluster — 叢集資訊

- **Tetragon Agents**：各節點健康狀態、重啟次數、啟動時間，每 30 秒自動刷新

### Dashboard — 總覽

- Policy 數量、Namespace 數量、Global Protect Mode 狀態一覽
- **Tracing Policy** 與 **Admission Policy** 清單快覽

### Settings — 設定

- **Users（使用者管理）**：本地帳號登入（JWT）、Admin / Viewer 角色、Session Timeout 設定
- **Alerts（Webhook 告警）**：將 Security Events 和 Admission Events 推送到 Slack、Teams、Discord 等；可設定 Event Type（Security / Admission）、severity、Namespace、Policy 篩選及 cooldown；設定儲存在 `/data/sentinel/alerts.json`
- **Syslog 轉送**：將事件轉送至 rsyslog/syslog server（UDP 或 TCP）；可設定 Event Type、severity、Namespace、Policy 篩選；設定儲存在 `/data/sentinel/rsyslog.json`

---

## 部署

### 前置需求

- Kubernetes 1.26+
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

Sentinel 將以下資料存放於 `/data/sentinel/`，**強烈建議掛載 PersistentVolume**，否則 Pod 重啟後所有設定將會消失：

| 檔案 | 說明 |
|---|---|
| `users.json` | 使用者帳號與 session 設定 |
| `.jwt-secret` | JWT 簽章 secret |
| `templates.json` | 自訂 Policy Templates |
| `alerts.json` | Webhook 告警規則 |
| `rsyslog.json` | Syslog 轉送設定 |
| `admission-events.json` | Admission Events 記錄（最多 500 筆）|

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

### Admission Events — Audit Webhook 設定

kube-apiserver audit webhook 可讓 Sentinel 接收完整的 VAP 違規記錄：

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    verbs: ["create", "update", "patch", "delete"]
    omitStages: ["RequestReceived"]
```

```yaml
# /etc/kubernetes/audit-webhook.yaml
apiVersion: v1
kind: Config
clusters:
  - name: sentinel
    cluster:
      server: http://<sentinel-clusterip>/api/admission-events/webhook
users:
  - name: sentinel
contexts:
  - name: default
    context: { cluster: sentinel, user: sentinel }
current-context: default
```

kube-apiserver 加上：
```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
--audit-webhook-batch-max-wait=5s
```

### 環境變數

| 變數 | 預設值 | 說明 |
|---|---|---|
| `TETRAGON_NAMESPACE` | `kube-system` | Tetragon 安裝的 namespace |

---

## RBAC 權限

| API Group | 資源 | 操作 |
|---|---|---|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | CRUD |
| `admissionregistration.k8s.io` | `validatingadmissionpolicies`, `validatingadmissionpolicybindings` | CRUD |
| `""` (core) | `namespaces`, `pods`, `pods/log`, `pods/exec` | get, list, watch, create |
| `""` (core) | `events` | get, list, watch |
| `""` (core) | `nodes` | get, list |
| `""` (core) | `configmaps` (`cilium-config`, `kube-proxy`) | get |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |

---

## 授權

[MIT License](LICENSE)
