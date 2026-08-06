# K8s Sentinel — 架構

**狀態：** 反映現況（隨程式碼更新）
**取代：** `docs/superpowers/specs/` 下兩份實作前的設計文件。那兩份描述的是 Ant Design 與
CoreUI 的前端，兩者都沒有進到專案裡，內容已無法對照。

README 說明**怎麼裝、怎麼設定**。這份文件說明**為什麼是這個形狀**，以及哪些不變條件
（invariant）不能打破。

---

## 1. 全貌

一個 Pod，兩個東西：Go 後端，以及編進同一個 binary 的 React SPA。

```
                    ┌──────────────────────────────────────┐
   瀏覽器  ────────▶ │  sentinel (單一 Pod, replicas: 1)     │
                    │                                      │
                    │   chi router  ──▶  embed FS (SPA)    │
                    │       │                              │
                    │       ├── /api/*  handler            │
                    │       │                              │
                    │   ┌───▼──────────────────────────┐   │
                    │   │ internal/k8s.Store           │   │
                    │   │  · Tetragon 事件廣播          │   │
                    │   │  · Hubble flow 廣播 + 拓樸緩衝 │   │
                    │   │  · 各種 TTL 快取              │   │
                    │   └───┬──────────────────────────┘   │
                    └───────┼──────────────────────────────┘
                            │ kubectl exec / API
              ┌─────────────┴─────────────┐
              ▼                           ▼
      tetragon DaemonSet          cilium-agent DaemonSet
      (tetra getevents)           (hubble observe --follow)
```

**沒有資料庫。** 所有狀態不是在記憶體，就是 `DATA_DIR` 底下的 JSON 檔。

---

## 2. 後端套件

| 套件 | 職責 |
|---|---|
| `cmd/server` | 組裝：建 client、起背景 goroutine、掛 router、graceful shutdown |
| `internal/k8s` | 與叢集之間的所有互動。Store 是唯一的入口 |
| `internal/handler` | HTTP 路由、認證中介層、拓樸圖組裝 |
| `internal/security` | Security Events 的保存、去重、保留策略、SSE |
| `internal/admission` | Admission Events：watch K8s Event + audit webhook |
| `internal/policy` | TracingPolicy 的表單模型與 YAML 產生 |
| `internal/auth` | 使用者、bcrypt、JWT 簽發與撤銷 |
| `internal/alert` | Webhook 通知 |
| `internal/rsyslog` | syslog 轉發 |

`internal/k8s.Store` 是刻意做大的：所有對叢集的讀寫都經過它，快取與廣播也在裡面，
handler 只負責把結果轉成 JSON。

---

## 3. 兩條事件攝取管線

### 3.1 Tetragon —— 執行期事件

`StartTetragonBroadcast` 對**每一個** Tetragon Pod `kubectl exec` 一次
`tetra getevents -o json`，把 NDJSON 逐行解析成 `TetragonEvent`，扇出給所有訂閱者。

為什麼要對每個 Pod 各開一條：**每個 agent 只看得到自己節點的事件**，少連一個節點就是
那個節點的事件全部消失。

訂閱者只有 `security.Store`。

**alert 與 rsyslog 不訂閱這條原始流**，而是訂閱 `security.Store.SubscribeFirstSightings()`
—— 只在事件**開出新的一列**時收到通知。原本三者各自讀原始流，於是同一筆重試迴圈在畫面上是
一列、在 webhook 上是幾百則。現在「什麼算一個事件」只有一個裁判：`security.Fingerprint`。

alert 的 cooldown 沒有被取代 —— 去重窗口只有 30 秒，間隔更長的重複仍會開新列，cooldown
負責的正是這一段。兩者現在用**同一個 identity**，所以 cooldown 只會壓制同一件事的重複，
不會再把同一個 pod 的不同事件互相蓋掉。

> **已知重複**：`StartDiscoveryLoop` 沒有訂閱這個廣播，而是自己再開一條
> `StreamTetragonEvents`。所以每個節點實際上有**兩條** `tetra getevents`。改成訂閱會
> 讓 Discovery 在緩衝滿時丟事件（廣播是 non-blocking 扇出），自開的那條則有背壓 ——
> 這個取捨還沒決定。

### 3.2 Hubble —— 網路 flow

`StartCiliumBroadcast` 先 `DetectCilium`，再對每個 cilium-agent exec
`hubble observe --follow -o json --all-namespaces`。

**Cilium 的 namespace 必須偵測一次、後續一路沿用。** 偵測會找 `kube-system`、`cilium`、
`cilium-system`；如果 exec 時改用預設值，裝在其他 namespace 的叢集會出現「偵測到了但永遠
找不到 agent」的死循環（v0.21.0 修）。

每筆 flow 有三個去向：
1. 併入拓樸緩衝
2. 廣播給 SSE 訂閱者（只有 allowed/dropped）
3. 若是可歸因的政策拒絕 → 合成成 `TetragonEvent` 進入安全事件流

---

## 4. 拓樸圖

### 4.1 緩衝

`ciliumTopo` 是一個 map，key 是 `srcID|dstID|port|verdict`，值累加 count 與 lastSeen。
視窗 **15 分鐘**。

**verdict 是 key 的一部分**，這點很重要：拿掉它，後來的 allowed flow 會就地覆蓋掉一筆
denial，圖上紅線會在政策還在擋的時候變綠。

### 4.2 哪些 flow 不進緩衝

| 排除 | 理由 |
|---|---|
| verdict 非 allowed/dropped | TRACED / TRANSLATED 是中間觀測點，不是結果 |
| `is_reply = true` | 邊的方向是**連線發起方向**。回應方向會讓 pod 對外的 curl 看起來像收到外部流量 |
| ICMP 錯誤訊息 | 那是網路在回報「你剛送的封包出事了」，來源欄位是**回報者**。當成邊會把因果講反 |

ICMP **echo** 保留 —— ping 是真實流量，ping sweep 正是安全工具該顯示的。

### 4.3 位址如何解析成節點（`resolveID`）

順序有意義：

1. **有 pod 名稱** → pod
2. **link-local**（`169.254.0.0/16`、`fe80::/10`）→ 自成一類。RFC 3927 不可路由出本地鏈路，
   不可能是叢集外的客戶端。`169.254.169.254` 具名為 cloud metadata
3. **`reserved:world` 身分** → external。**身分蓋過位址**：跨節點轉送的 NodePort 流量會被
   SNAT 成入口節點的 `cilium_host`，位址看起來在叢集內，但身分仍是 world
4. **節點位址**（實體 IP 或 `cilium_host`）→ node
5. **在 pod CIDR 內但不是已知 pod** → 略過
6. 其餘 → external

把 link-local 當成 external 不只是標籤錯：UI 會對「收到 external 流量卻沒有 exposure
path」的 pod 標紅色警告，等於把 sidecar 自己的管線報成入侵（v0.21.1 修）。

### 4.4 一個 pair 只顯示一個 verdict

L7 拒絕時，L3/L4 是 allowed 而 L7 是 dropped，**兩者同時存在且都是最新的**。單純比新舊
會在兩者之間跳動，而且多半顯示 allow，把拒絕整個藏起來。

規則是：**還在發生的拒絕直接勝出**（`denialStillLive = 2 分鐘`），只有已經停止的拒絕才
讓位給取代它的流量。平手時算拒絕。

### 4.5 kubelet 探針辨識

`IsHealthProbe` 要求**兩個條件同時成立**：來源節點 == pod 所在節點，且目的 port ∈ pod 宣告
的探測 port。缺一不可 —— 同一個 port 從別處連進來是一般流量，同一個節點連別的 port 也不是
探針。

探測 port 的來源涵蓋：

- `livenessProbe` / `readinessProbe` / `startupProbe`
- `httpGet` / `tcpSocket` / `grpc`
- 具名 port（對**該容器自己**的 `ports` 解析，跟 kubelet 一樣）
- `postStart` / `preStop` 的 `httpGet` lifecycle hook —— 也是 kubelet 發的請求
- **一般容器與原生 sidecar**（`restartPolicy: Always` 的 initContainer）

最後一項是 Istio 在 K8s 1.29+ 注入 proxy 的方式。只讀 `spec.containers` 會漏掉 sidecar 的
15021 readiness probe，畫面上就是一條無法解釋、也無法隱藏的節點連線（v0.21.3 修）。

**明確不隱藏**：`kubectl port-forward` 也是從節點來的，但那是有人伸手進 pod ——
安全主控台該顯示。

### 4.6 無法區分的情況

探測 port 與服務 port 相同時（例如 app 與 probe 都在 8080），從該節點對該 port 的連線
無法區分是 kubelet 還是人。kubelet 與節點上的 shell 都在 host network namespace，
Hubble 看到的身分、位址、port 範圍完全一樣，flow 裡也沒有 process 資訊。

解法只有兩個：測試時取消勾選 `Hide health probes`，或讓探針使用專用 port。

---

## 5. 政策歸因

Hubble 只有在**明確的 `ingressDeny` / `egressDeny` 規則**觸發時才會指出是哪條政策。
allowlist 政策靠的是 default-deny —— **缺少 allow 規則**，沒有規則可以回報。

`AttributePolicyDenial` 補這一段：找出在該方向上治理該 pod 的政策。

三個不變條件：

- **從不發明政策名稱。** 找不到就不產生事件。Policy 欄位只能出現叢集裡真的存在的政策
- **多條符合就全部列出。** default-deny 無法歸咎於其中某一條，挑一條會把人送到錯的規則
- **`matchExpressions` 不評估。** 部分比對就宣稱命中會指認錯誤的政策

同一份快取也提供容器名稱（flow 沒有這個欄位）與探測 port，30 秒 TTL。

---

## 6. Exposure 偵測

**這是設定的靜態分析，不是觀測到的流量。** 回答的是「外面的人要打哪裡才會到這個 pod」。

| 類型 | 來源 |
|---|---|
| nodeport / loadbalancer / externalip | Service |
| ingress | Ingress + TLS 區塊決定 scheme |
| gateway | Gateway API `Gateway` + `HTTPRoute` / `GRPCRoute` |
| istio | Istio `Gateway` + `VirtualService` |
| hostnetwork / hostport | Pod spec |

Service → Pod 走 **EndpointSlice**，不是已棄用的 Endpoints —— 後者在 1000 個位址就截斷，
會讓大型 Service 的 pod 悄悄從 exposure 偵測中消失。

**Istio 需要讀 Gateway，不能只看 VirtualService。** VS 的 `hosts: ["*"]` 意思是「這個
Gateway 服務的所有 host」，是相對於 Gateway 的萬用字元；主機名與 port 都只存在 Gateway 上。
兩者取交集後**取較具體的那一個**，這是 Istio 自己的解析規則。VS 指定了 Gateway 不服務的
host 時，Istio 會忽略該路由 —— 那就不是一條對外路徑（v0.22.0）。

讀不到 Gateway（不存在或缺 RBAC）時**退回顯示 VS 的 hosts**，而不是丟掉整條路徑。在一個
盤點攻擊面的畫面上，講得不夠精確好過什麼都不說。

ClusterIP **不算** exposure，這是刻意的。

---

## 7. 儲存

| 資料 | 位置 |
|---|---|
| 使用者、JWT secret、安全事件、admission 事件、alert 規則、rsyslog 設定、template | `DATA_DIR` 下的 JSON |
| 拓樸緩衝、SSE 訂閱、token 撤銷名單、各種快取 | 記憶體 |

寫檔是**非同步**的：快照 + 世代編號，過期的 goroutine 會放棄寫入，rename 在 mutex 內完成
以消除 TOCTOU。

> ### ⚠ 已知缺陷：`DATA_DIR` 目前是 `emptyDir`
>
> `deploy/sentinel.yaml` 把 `/data/sentinel` 掛成 `emptyDir`，所以 Pod 一重啟就失去
> **全部**上述 JSON：使用者帳號退回 admin/admin、JWT secret 重生（所有 session 失效）、
> 安全事件與 admission 事件的歷史歸零。
>
> `main.go` 的可寫性檢查**不會**觸發 —— 目錄是可寫的，只是會消失。
>
> 修法是 PVC + `strategy: Recreate`（單副本掛 RWO volume，滾動更新會卡住）。尚未套用，
> 因為需要叢集有預設 StorageClass。

保留策略按嚴重度分別設上限（預設 500 warning / 300 critical / 7 天），超過先淘汰最舊的。

---

## 8. 認證

Cookie 內的 JWT（HS256），`HttpOnly` + `SameSite=Strict`，HTTPS 時加 `Secure`。
簽章方法會驗證，擋掉 alg confusion。

secret 是 32 bytes 隨機值，存在 `DATA_DIR/.jwt-secret`。**長度相符時原樣採用**，不先 trim ——
隨機值最後一個 byte 有 4/256 機率是空白字元，先 trim 會誤判長度、重新產生 secret，
把所有人踢出去（v0.21.0 修）。

登出會把 JTI 放進撤銷名單。該路由**刻意公開**（token 過期也要能登出），所以 handler
自己解析 cookie，不從 context 讀 claims —— 從 context 讀的話中介層沒跑過，永遠是 nil，
撤銷等於沒做（v0.21.0 修）。

角色只有兩種：`admin` 可寫，`viewer` 唯讀。

> **已知弱點**：登入沒有速率限制；密碼沒有長度下限；改自己的密碼不需要舊密碼；
> 撤銷名單只在記憶體（見上一節）；沒有 CSP 等安全標頭。

---

## 9. 前端

React 19 + TypeScript + Vite，**shadcn/ui + Tailwind v4**。編進 Go binary
（`web/dist` 由 `//go:embed` 嵌入），所以只有一個成品。

```
web/src/
  api/          fetch 封裝
  layout/       AppLayout、Sidebar、SSE Provider（每種事件一條連線，全站共用）
  pages/        一頁一檔
  components/   跨頁共用：ScopeFilter、FilterPopover、NamespaceSelect、PolicyForm
                ui/ 底下是 shadcn 產生的原始元件
  hooks/        自訂 hook
  lib/          cn()（clsx + tailwind-merge）
  data/         靜態資料（policy template 等）
  utils/        cnpForm（CNP 表單 ↔ YAML）、time、exportEvents
```

**共用元件是刻意的**：namespace 篩選器與篩選面板曾經每頁各寫一套，然後各自漂移。
現在 Tracing Policy / Network Policy / Network Topology / Security Events /
Admission Events 用的是同一個 `ScopeFilter`。

一個規則貫穿所有篩選器：**沒有勾選任何項目 = 不篩選**，而不是「比對空值」。

版本號在 build 時經 `VERSION` build arg → `VITE_APP_VERSION` 印進 bundle，顯示在 sidebar 底部。
沒帶 build arg 會顯示 `dev`。

---

## 10. 尚未解決的架構問題

依嚴重度排序。前兩項需要決策，不只是實作。

1. **`emptyDir` 持久化**（見 §7）—— 最嚴重。安全產品每次重啟丟掉自己的稽核軌跡
2. **`pods/exec` 的 `create` 開在全叢集** —— 等同 cluster-admin。這是「用 exec 跑
   `hubble observe` / `tetra getevents`」這個傳輸選擇的直接後果。改用 Hubble Relay 的
   gRPC API 可以完全拿掉這個授權
3. **audit webhook 未認證** —— `/api/admission-events/webhook` 是公開的，可以偽造事件；
   配上保留上限還能把真實事件擠掉。加認證需要同步改 kube-apiserver 的 audit webhook 設定
4. **沒有 informer** —— 每個快取各自週期性 full LIST 全部 pod（歸因 30s、ClusterIPs 30s、
   workload 60s），`ListNodeIPMap` 甚至完全沒快取，每次拓樸輪詢都是 2 次 list
5. **兩條 Tetragon 事件流**（見 §3.1）
6. **認證弱點**（見 §8）
