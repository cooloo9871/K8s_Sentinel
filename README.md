# K8s Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="K8s Sentinel" width="340" />
</p>

**K8s Sentinel** 是一個部署在 Kubernetes 叢集內的 **K8s 安全管理 console**，整合 Cilium Tetragon 執行期監控與 ValidatingAdmissionPolicy 控制，讓你不需要操作 `kubectl` 或手寫 YAML，就能透過網頁介面管理 Tracing Policy、Admission Policy、監控安全事件、推送告警、視覺化叢集網路流量，全面掌握 K8s workload 的零信任安全防線。

---

## 功能總覽

### Policies — 策略管理

#### Tracing Policy
- 建立、編輯、刪除 **Tracing Policy**（cluster-wide 或 namespace-scoped）
- 依 namespace、scope 篩選策略清單
- **Process Rules**：控制哪些 binary 可以執行（Whitelist / Blacklist）
- **File Rules**：控制哪些檔案路徑可以存取；可指定僅封鎖讀取或寫入；可設定例外 process
- **Network Rules**：控制對外連線（Whitelist / Blacklist，支援 IP 與 Port）
- 每條 Policy 可個別切換 Monitoring（觀測）/ Protect（封鎖）模式
- **Global Protect Mode**：一鍵 Turn On / Turn Off 所有 Policy 的封鎖模式
- **Created By**：記錄每條 Policy 的建立者；透過 `kubectl apply` 建立的顯示 `k8s-apply`
- **Policy Templates**：內建範本與自訂範本；可依名稱搜尋或依 Cluster-wide / Namespace 分類篩選
  - **Monitor All Process Executions**：監控叢集所有 Pod 的 process 執行
  - **Monitor All File Access**：監控敏感檔案讀寫
  - **Monitor External Network (Outside Cluster)**：偵測 Pod 連線到叢集外；CIDR 自動偵測
  - **Monitor Internal Network (Inside Cluster)**：監控 Pod 之間及 Pod 到 Service 的連線；供 Network Topology 使用

#### Admission Policy（ValidatingAdmissionPolicy）
- 管理 K8s 原生 VAP 資源，支援 YAML 編輯器建立/修改 Policy 與 Binding
- **UI Policy Builder**：不需手寫 YAML，透過表單建立常見安全策略，右側即時預覽生成的 YAML

  | Rule Type | 說明 |
  |---|---|
  | **Label Check** | 要求/禁止資源帶有特定 label key=value；支援多條規則；可指定套用資源範圍 |
  | **Annotation Check** | 要求/禁止資源帶有特定 annotation key=value；可指定套用資源範圍 |
  | **Image Policy** | 禁止 `:latest` tag；要求 image 必須來自指定 registry；涵蓋所有 workload 類型及 initContainers |
  | **Replica Limit** | 限制 Deployment / StatefulSet 的最大 replica 數 |
  | **Resource Limits** | 要求 container 設定 CPU / Memory limits；涵蓋所有 workload 類型及 initContainers |
  | **Security Context** | 禁止 privileged container；要求 runAsNonRoot（正確繼承 pod/container 層級） |
  | **Host Access** | 禁止 hostNetwork / hostPID / hostIPC；涵蓋 Pod 及所有 template-based workload |

- **UI Binding Builder**：選擇 Policy、Namespace、Validation Actions（Deny / Audit / Warn）
- 透過 UI 建立的資源標記 `sentinel.io/builder: "true"`，點 Edit 自動回到 UI 表單

### Behavior Discovery — 行為探索

- 自動學習叢集中各 Pod 執行過的 process，**不需要任何 TracingPolicy**
- 依 Deployment / DaemonSet / StatefulSet 分組顯示
- **Create Policy**：一鍵預填 Policy 表單，帶入 Pod Selector 與 Process Rules

### Network Topology — 網路拓樸

- 以圖形化方式顯示叢集內 Pod 的 TCP 連線關係，資料來源為 Tetragon kprobe 事件
- **節點類型**：Pod（紫色）、Service（綠色）、External IP（橘色）
- **連線類型**：
  - 彩色實線 — 允許的連線（紫 = pod-to-pod、綠 = pod-to-service、橘 = 出叢集）
  - 紅色虛線 — 被 Protect 模式攔截的連線；**即使 retention 設很小，被拒絕的連線也會持續顯示**（獨立的 topology buffer，以 TTL 為基準而非事件數量）
- **Auto Layout**：一鍵使用 Dagre 演算法自動排版
- 點擊節點或連線查看詳情（IP、port、連線次數）
- 依 Namespace / Pod 名稱 / Service 名稱篩選
- 每 30 秒自動刷新
- 需先套用 **Monitor Internal Network** 範本才能收集資料

### Notifications — 安全通知

#### Security Events
- 即時串流叢集所有 Tetragon kprobe 事件；後端持久化，重啟不消失
- Warning / Critical 嚴重程度分類；30 秒 content-based 去重
- 點擊展開詳情：觸發檔案路徑、網路連線目的地、執行 user（UID）、Policy 名稱等
- **Pause / Resume**：凍結畫面閱讀事件，暫存新進事件並顯示待讀計數
- **Export CSV**
- 保留策略（預設）：Warning 最多 500 條、Critical 最多 300 條、TTL 7 天（可在 Settings 調整）

#### Admission Events
- 記錄 ValidatingAdmissionPolicy 違規事件；依 source、namespace、severity 篩選
- **Critical**（`Deny` action，請求被阻擋）/ **Warning**（`Audit` action，請求放行但記錄）
- 來源：K8s Warning Events（免設定）或 **kube-apiserver audit webhook**（完整覆蓋，需設定）
- 30 秒去重；自動持久化；預設最多 500 筆，TTL 30 天（可在 Settings 調整）

### Dashboard — 總覽

- **Tetragon Agents**：各節點 agent 就緒狀態（ready / total）；未全數就緒時以紅色標示
- Security Events 統計（Critical / Warning）、Admission Events 統計（即時更新）、Global Protect Mode 狀態
- **Tracing Policy** 與 **Admission Policy** 清單快覽

### Settings — 設定

- **Users（使用者管理）**：本地帳號登入（JWT + token 主動撤銷）、Admin / Viewer 角色、Session Timeout 設定
- **Event Retention**：
  - Security Events：Warning/Critical 最大筆數（1–5000/1–2000）及 TTL（1–90 天）
  - Admission Events：最大筆數（1–5000）及 TTL（1–365 天）
- **Alerts（Webhook 告警）**：將 Security Events 和 Admission Events 推送到 Slack、Teams、Discord 等
- **Syslog 轉送**：將事件轉送至 rsyslog/syslog server（UDP 或 TCP）

---

## 部署

### 前置需求

- Kubernetes 1.26+
- `kubectl` 已設定 kubeconfig
- Cilium Tetragon 已安裝於叢集

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

### Container image

部署使用 GitHub Container Registry 上的 image：

```
ghcr.io/cooloo9871/sentinel:latest
```

各版本的 tag 見 [Releases](https://github.com/cooloo9871/K8s_Sentinel/releases)。生產環境建議在 `deploy/base/deployment.yaml` 改為固定版本（例如 `:v0.2.0`）而非 `:latest`，以確保部署可重現。

### 存取 UI

```bash
kubectl port-forward -n sentinel-system svc/sentinel 8080:80
# 開啟 http://localhost:8080
```

### 持久化儲存（PV）

K8s Sentinel 將以下資料存放於 `/data/sentinel/`（可透過 `DATA_DIR` 環境變數修改），**強烈建議掛載 PersistentVolume**，否則 Pod 重啟後所有設定與事件記錄將會消失：

| 檔案 | 說明 |
|---|---|
| `users.json` | 使用者帳號與 session 設定 |
| `.jwt-secret` | JWT 簽章 secret |
| `templates.json` | 自訂 Policy Templates |
| `alerts.json` | Webhook 告警規則 |
| `rsyslog.json` | Syslog 轉送設定 |
| `admission-events.json` | Admission Events 記錄（預設最多 500 筆，30 天 TTL）|
| `security-events.json` | Security Events 記錄（預設最多 800 筆，7 天 TTL）|

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

kube-apiserver audit webhook 可讓 K8s Sentinel 接收完整的 VAP 違規記錄（包含直接 `kubectl apply` 被拒絕的情況）：

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
| `DATA_DIR` | `/data/sentinel` | 資料目錄路徑；啟動時若無法寫入會印出警告 |
| `TETRAGON_NAMESPACE` | `kube-system` | Tetragon 安裝的 namespace |

---

## 資源需求

| | requests | limits |
|---|---|---|
| CPU | 200m | 500m |
| Memory | 128Mi | 256Mi |

> 叢集節點數較多（> 5 個 Tetragon pod）或 TracingPolicy 規則密集時，建議將 CPU limit 調高至 750m。

---

## RBAC 權限

| API Group | 資源 | 操作 |
|---|---|---|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | CRUD |
| `admissionregistration.k8s.io` | `validatingadmissionpolicies`, `validatingadmissionpolicybindings` | CRUD |
| `""` (core) | `namespaces`, `pods`, `pods/log`, `pods/exec` | get, list, watch, create |
| `""` (core) | `events` | get, list, watch |
| `""` (core) | `nodes` | get, list |
| `""` (core) | `services` | get, list |
| `""` (core) | `configmaps` (`cilium-config`, `kube-proxy`) | get |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |

---

## 授權

[MIT License](LICENSE)
