# NODOZE 项目介绍

本仓库为论文 **《NODOZE: Combatting Threat Alert Fatigue with Automated Provenance Triage》**（NDSS 2019）的复现实现。NODOZE 通过系统调用依赖图与异常分数，对安全告警进行自动化筛选（Triage），缓解告警疲劳。

---

## 一、项目结构

```
NODOZE/
├── app.py         # Web 前端 API 服务（Flask）
├── events.py      # 事件抽象：从 ndjson 解析依赖事件 <SRC, DST, REL>
├── freq_db.py     # 事件频率库：构建 Freq(E)、Freq_src_rel(E)
├── graph.py       # 依赖图与路径枚举：Algorithm 1
├── scoring.py     # 异常打分：Eq.(1)(2)(3)(6)
├── triage.py      # 告警 Triage 主流程：Algorithm 1/2/3
├── config.json    # 运行参数配置（前端与 CLI 共用）
├── static/        # Web 前端静态资源
│   └── index.html # NODOZE 仪表板（告警列表、依赖图、攻击路径说明）
├── data/          # ndjson 历史日志
└── scripts/
    └── gen_data.py # 测试数据生成（含 --large 大规模基线）
```

---

## 二、核心概念

### 2.1 依赖事件（Dependency Event）

依赖事件定义为三元组 **E := \<SRC, DST, REL\>**：

- **SRC**：源实体（进程、socket、用户等）
- **DST**：目标实体
- **REL**：关系类型（`Pro Start`、`Pro End`、`IP Write`、`IP Read`）

实体抽象遵循论文思想：去掉时间戳、PID 等实例相关字段，使用 `host|program_name`、`IP:port`、`user` 等稳定标识。

### 2.2 实体类型

| 类型    | 示例 ID          |
| ------- | ---------------- |
| process | `host\|sshd`     |
| socket  | `192.168.1.1:22` |
| user    | `root`           |

### 2.3 支持的事件类型

- **sshd 认证失败 / 暴力破解 / 无效用户**：\<host\|sshd, 外部IP:port, IP Write\>
- **PAM session opened**：\<host\|su, user, Pro Start\>
- **PAM session closed**：\<host\|su, user, Pro End\>
- **进程创建**（decoder: process_exec）：\<parent_proc, child_proc, Pro Start\>
- **连接接受**（decoder: connection）：\<socket, process, IP Read\>
- **用户发起登录**（decoder: user_login）：\<user, process, Pro Start\>

---

## 三、算法与公式

### 3.1 事件频率统计（§VII-A, Eq.(7)(8)）

按 **(host, day)** 去重统计：

- **Freq(E)**：三元组 \<SRC, DST, REL\> 在多少 (host, day) 上出现
- **Freq_src_rel(E)**：\<SRC, REL\> 在多少 (host, day) 上出现

### 3.2 转移概率（Eq.(1)）

$$
M_e = \frac{\text{Freq}(E)}{\text{Freq}_{src,rel}(E)}
$$

表示在给定源实体和关系类型下，到达目标实体的条件概率。

### 3.3 路径正则性分数（Eq.(2)(3)）

$$
RS(P) = \prod_{e \in P} \left( IN(v_{src}) \cdot M_e \cdot OUT(v_{dst}) \right)
$$

- **IN(v)**：顶点 v 的入度相关分数（§VI-C）
- **OUT(v)**：顶点 v 的出度相关分数

### 3.4 异常分数（Eq.(6)）

$$
AS(P) = 1 - RS(P)
$$

正则性越高，异常分数越低；罕见依赖路径对应高异常分数。

### 3.5 Algorithm 1：路径枚举（GETPATHANOMALYSCORE）

```
输入: 告警事件 E_α, 依赖图 G, 最大路径长度 τl
1. G ← GETDEPENDENCYGRAPH(events)
2. vsrc ← E_α.src, vdst ← E_α.dst
3. Lb ← DFS 后向遍历(vsrc, τl-1)   // 祖先路径
4. Lf ← DFS 前向遍历(vdst, τl-1)   // 后继路径
5. Lp ← COMBINEPATHS(E_α, Lb, Lf, τl)
6. 对 Lp 中每条路径 P 计算 AS(P)
7. 返回路径及其异常分数
```

**路径组合**：完整路径 P = [B_k, ..., B_1, E_α, F_1, ..., F_m]，长度 ≤ τl。

### 3.6 Algorithm 3：路径合并（τm）

按异常分数降序排列路径，若相邻路径分数差 **S1 - S2 ≥ τm** 则停止合并，保留高分数路径簇，生成 true alert dependency graph。

---

## 四、模块说明

### 4.1 app.py

- Flask API 服务，提供 `/api/config`、`/api/datasets`、`/api/build-db`、`/api/triage` 等接口
- 静态资源：`static/index.html` 为 NODOZE 仪表板

### 4.2 events.py

- `Entity`、`DependencyEvent`：依赖事件与实体抽象
- `parse_dependency_events_from_line(line)`：从 ndjson 单行解析依赖事件
- `iter_dependency_events_from_file(path)`：流式读取 ndjson 并生成事件

### 4.3 freq_db.py

- `build_event_frequency_db(ndjson_path, sqlite_path)`：构建事件频率 SQLite 库
- 表：`event_freq`（src, dst, rel, count）、`event_freq_src_rel`（src, rel, count）

### 4.4 graph.py

- `build_dependency_graph(events)`：构建 backward/forward 邻接表
- `dfs_traversal_backward`、`dfs_traversal_forward`：DFS 路径枚举
- `combine_paths`：组合后向与前向路径
- `get_path_anomaly_scores`：枚举包含告警的依赖路径

### 4.5 scoring.py

- `EventFrequencyDB`：查询 Freq(E)、Freq_src_rel(E)
- `transition_probability`：Eq.(1) 转移概率
- `compute_in_out_scores_for_graph`：IN/OUT 分数
- `score_path`：计算 RS(P)、AS(P)

### 4.6 triage.py

- `ALERT_RULE_IDS`：攻击相关 rule.id 集合（如 5763 SSH 暴力破解）
- `is_alert_record`：判断是否为攻击告警
- `load_ndjson_with_events`：加载 ndjson 并解析事件
- `get_context_events`：按同 host、行窗口选取上下文
- `merge_paths_by_threshold`：Algorithm 3 路径合并
- `run_triage`：对全部告警执行 triage 并按异常分数排序

---

## 五、数据流

```
ndjson 历史日志
       │
       ├──► freq_db.py ──► event_freq.db（Freq, Freq_src_rel）
       │
       └──► triage.py
                │
                ├── 1. 识别攻击告警（rule.id ∈ ALERT_RULE_IDS）
                ├── 2. 获取上下文事件（同 host，window_lines）
                ├── 3. Algorithm 1：枚举依赖路径
                ├── 4. scoring：计算 AS(P)
                ├── 5. Algorithm 3：路径合并
                └── 6. 按 aggregate_score 排序输出
```

---

## 六、参数说明

| 参数         | 说明                                                         | 默认值 |
| ------------ | ------------------------------------------------------------ | ------ |
| τl (tau_l)   | 最大路径长度：DFS 枚举时单条路径允许的最大边数，越大图越复杂 | 20     |
| τm (tau_m)   | 路径合并阈值：相邻路径分数差 ≥ τm 时停止合并，越大保留路径越少 | 0.1    |
| τd (tau_d)   | 决策阈值：低于此分数的告警视为误报并过滤，null 表示不过滤    | null   |
| window_lines | 上下文窗口行数：告警前后各取多少行日志构建依赖图             | 500    |
| top_n        | 仅输出前 N 条告警，null 表示全部输出                         | null   |

---

## 七、Web 前端

### 方式一：本地运行

```bash
pip install flask flask-cors
python app.py
```

### 方式二：Docker 容器

**构建并运行：**

```bash
# 使用 docker run
docker build -t nodoze .
docker run -p 5000:5000 nodoze

# 或使用 docker-compose（推荐，支持挂载 data 和 config）
docker-compose up --build
```

**持久化说明**：`docker-compose.yml` 已挂载 `./data` 和 `./config.json`。若需持久化频率库，请在 `config.json` 中将 `db_path` 设为 `data/event_freq.db`。

浏览器访问 http://localhost:5000 使用 NODOZE 仪表板。

**功能**：

- **配置面板**：选择基线/待检测日志，调整 τl、τm、τd、window_lines、top_n
- **构建频率库**：基于基线数据生成 event_freq.db
- **运行 Triage**：执行告警分析，按异常分数排序
- **告警列表**：点击告警查看其依赖图
- **依赖图**：Cytoscape.js 可视化，支持多节点、菱形分支
- **攻击路径说明**：文字描述依赖链（用户/进程/套接字及关系类型）

**数据文件**：

- `normal_baseline.ndjson`：常规基线（约 4600 条）
- `large_baseline.ndjson`：大规模基线（约 10 万条，`python scripts/gen_data.py --large`）
- `attack_complex_graph.ndjson`：复杂依赖图测试（11 节点 + 菱形分支）

---

## 八、参考文献

> Hassan, W. U., Guo, S., Li, D., Chen, Z., Jee, K., Li, Z., & Bates, A. (2019). NODOZE: Combatting Threat Alert Fatigue with Automated Provenance Triage. *NDSS 2019*.
