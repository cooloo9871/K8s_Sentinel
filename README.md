# Sentinel

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
- 容器 registry 存取權限（若需自行 build 映像）

---

### 步驟一：設定認證憑證

Sentinel 使用 bcrypt 雜湊密碼。先產生管理員密碼的 hash：

```bash
# 使用 Python（大多數系統均可用）
python3 -c "
import bcrypt, getpass
pw = getpass.getpass('Password: ').encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(12)).decode())
"
```

編輯 `deploy/overlays/production/secret-patch.yaml`，填入自訂的密碼 hash 與 JWT Secret：

```yaml
# deploy/overlays/production/secret-patch.yaml
apiVersion: v1
kind: Secret
metadata:
  name: sentinel-credentials
  namespace: sentinel-system
type: Opaque
stringData:
  admin: "$2b$12$<your-bcrypt-hash>"      # 替換為上面產生的 hash
  jwt-secret: "<your-random-secret>"      # 隨機字串，建議 32 字元以上
```

> ⚠️ **安全警告**：絕對不要在生產環境使用預設憑證。請務必替換 `admin` hash 與 `jwt-secret`。

---

### 步驟二：更新容器映像（選用）

若要使用自行 build 的映像，編輯 `deploy/base/deployment.yaml`：

```yaml
containers:
  - name: sentinel
    image: your-registry/sentinel:your-tag  # 替換此行
```

Build 並推送映像：

```bash
docker build -t your-registry/sentinel:latest .
docker push your-registry/sentinel:latest
```

預設使用公開映像 `quay.io/cooloo9871/sentinel:latest`，可直接跳過此步驟。

---

### 步驟三：部署

```bash
# 使用 production overlay（含自訂憑證）
kubectl apply -k deploy/overlays/production/

# 或使用 base（含預設憑證，僅供測試）
kubectl apply -k deploy/base/
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

**方式 B — Ingress**

建立 Ingress 資源指向 `sentinel` Service（port 80）：

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sentinel
  namespace: sentinel-system
spec:
  rules:
    - host: sentinel.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: sentinel
                port:
                  number: 80
```

登入帳號為 `admin`，密碼為步驟一設定的密碼。

---

### 部署的 Kubernetes 資源

| 資源 | 名稱 | 說明 |
|------|------|------|
| Namespace | `sentinel-system` | 所有資源的命名空間 |
| ServiceAccount | `sentinel` | Pod 使用的服務帳號 |
| ClusterRole | `sentinel` | TracingPolicy CRUD + Namespace 讀取權限 |
| ClusterRoleBinding | `sentinel` | 綁定 ServiceAccount 與 ClusterRole |
| Deployment | `sentinel` | 應用程式 Pod，1 個 replica |
| Service | `sentinel` | ClusterIP，port 80 → 8080 |
| Secret | `sentinel-credentials` | 管理員密碼 hash 與 JWT Secret |

---

### RBAC 權限說明

Sentinel 需要以下叢集層級權限才能正常運作：

| API Group | 資源 | 操作 |
|-----------|------|------|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | get, list, watch, create, update, patch, delete |
| `""` (core) | `namespaces` | get, list |
| `""` (core) | `secrets/sentinel-credentials` | get |

---

### 解除安裝

```bash
kubectl delete -k deploy/overlays/production/
# 或
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
