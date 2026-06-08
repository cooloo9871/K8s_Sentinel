# Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="Sentinel" width="320" />
</p>

Sentinel 是一個部署在 Kubernetes 叢集內的 **Cilium TracingPolicy 管理 console**。透過網頁介面即可建立、編輯、刪除 TracingPolicy，並切換整體叢集的執行模式（Monitoring / Protect），不需要直接操作 `kubectl`。

---

## 功能

- **Dashboard**：Policy 總數、執行模式、Namespace 數量一覽，並可直接切換模式
- **TracingPolicy 管理**：列表搜尋、新增、編輯、刪除，支援 namespace 與 cluster 兩種範疇
- **表單編輯器**：以欄位填寫 Process / File / Network 規則，即時預覽產生的 YAML
- **YAML 編輯器**：直接貼上或編輯原始 YAML，內建語法驗證
- **執行模式切換**：Monitoring（觀測，不攔截）↔ Protect（主動 Sigkill 違規行為），切換前需確認
- **Namespace 檢視**：列出叢集所有 Namespace 與其套用的 Policy 數量

---

## 部署到 Kubernetes

### 前置需求

- Kubernetes 1.26+ 叢集，已安裝 Cilium 並啟用 TracingPolicy CRD
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
docker build -t your-registry/sentinel:latest .
docker push your-registry/sentinel:latest
```

預設使用公開 image `quay.io/cooloo9871/sentinel:latest`，可直接跳過此步驟。

---

### 步驟三：部署

**方式 A — Kubernetes Job（推薦，不需要本機 helm）**

透過 Job 在叢集內部執行安裝，pod 負責 helm 安裝 Tetragon 以及 Sentinel 部署：

```bash
kubectl apply -f deploy/install-job.yaml
```

查看安裝進度：

```bash
kubectl logs -n kube-system job/sentinel-installer -f
```

Job 執行流程：
1. 偵測是否已有 Tetragon DaemonSet，沒有則在 pod 內透過 Helm 安裝最新版
2. Clone Sentinel 原始碼
3. 建立 `sentinel-system` namespace（已存在則跳過）
4. 套用 Sentinel K8s 資源並等待 Deployment 就緒

Job 完成 10 分鐘後自動清除 pod（`ttlSecondsAfterFinished: 600`）。手動清除：

```bash
kubectl delete -f deploy/install-job.yaml
```

---

**方式 B — 本機安裝腳本**

需要本機有 `kubectl`，helm 不存在時會自動下載到暫存目錄：

```bash
bash deploy/install.sh
```

確認所有資源正常建立：

```bash
kubectl get all -n sentinel-system
```

```
NAME                             READY   STATUS    RESTARTS   AGE
pod/sentinel-xxxxxxxxx-xxxxx     1/1     Running   0          30s

NAME               TYPE        CLUSTER-IP      PORT(S)   AGE
service/sentinel   ClusterIP   10.96.xxx.xxx   80/TCP    30s

NAME                        READY   UP-TO-DATE   AVAILABLE
deployment.apps/sentinel    1/1     1            1
```

---

### 步驟四：存取 UI

**方式 A — Port-forward（快速測試）**

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
| ClusterRole | `sentinel` | TracingPolicy CRUD + Namespace 讀取權限 |
| ClusterRoleBinding | `sentinel` | 綁定 ServiceAccount 與 ClusterRole |
| Deployment | `sentinel` | 應用程式 Pod，1 個 replica |
| Service | `sentinel` | ClusterIP，port 80 → 8080 |

---

### RBAC 權限說明

Sentinel 需要以下叢集層級權限才能正常運作：

| API Group | 資源 | 操作 |
|-----------|------|------|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | get, list, watch, create, update, patch, delete |
| `""` (core) | `namespaces` | get, list |

---

### 解除安裝

```bash
# 移除 Sentinel
kubectl delete -k deploy/base/
kubectl delete namespace sentinel-system

# 移除 Tetragon（若是由本腳本安裝）
kubectl delete -f deploy/tetragon.yaml
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
