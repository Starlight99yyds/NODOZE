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

| 类别            | 实体类型         | 说明                         |
| :-------------- | :--------------- | :--------------------------- |
| Subject（主体） | Process（进程）  | 唯一能作为信息流发起方的实体 |
| Object（客体）  | Process          | 可作为信息流接收方           |
|                 | File（文件）     | 文件实体                     |
|                 | Socket（套接字） | 网络连接实体                 |

### 2.3 依赖事件关系

| SRC     | DST     | REL（关系类型）                     |
| :------ | :------ | :---------------------------------- |
| Process | Process | Pro Start；Pro End                  |
| Process | File    | File Write；File Read；File Execute |
| Process | Socket  | IP Write；IP Read                   |

### 2.4 支持的事件类型

- **sshd 认证失败 / 暴力破解 / 无效用户**：\<host\|sshd, 外部IP:port, IP Write\>
- **PAM session opened**：\<host\|su, user, Pro Start\>
- **PAM session closed**：\<host\|su, user, Pro End\>
- **进程创建**（decoder: process_exec）：\<parent_proc, child_proc, Pro Start\>
- **连接接受**（decoder: connection）：\<socket, process, IP Read\>
- **用户发起登录**（decoder: user_login）：\<user, process, Pro Start\>

---

## 三、算法与公式

### 3.1 事件频率统计（§VII-A, Eq.(7)(8)）

按 **(host, day)** 去重统计，其中 host 为日志来源主机，day 为事件日期（YYYY-MM-DD）。

| 符号                | 含义                                                         |
| ------------------- | ------------------------------------------------------------ |
| **Freq(E)**         | 依赖边 E = \<SRC, DST, REL\> 在**多少不同的 (host, day)** 上出现过。同一 (host, day) 内多次出现只计一次。反映该边在基线中的**空间-时间覆盖广度**：值越大表示该边越常见、越“正常” |
| **Freq_src_rel(E)** | 二元组 \<SRC, REL\> 在**多少不同的 (host, day)** 上出现过。即“从源实体 SRC 出发、以关系 REL 发出”的总 (host, day) 数。作为 Freq(E) 的**分母基数**，表示该源-关系组合的总体活跃度 |

---

### 3.2 转移概率 M_e（Eq.(1)）

$$
M_e = \frac{\text{Freq}(E)}{\text{Freq}_{src,rel}(E)}
$$

| 符号                | 含义                                                         |
| ------------------- | ------------------------------------------------------------ |
| **Freq(E)**         | 边 E 的 (host, day) 出现次数（见 3.1）                       |
| **Freq_src_rel(E)** | 边 E 的源-关系 (host, day) 出现次数（见 3.1）                |
| **M_e**             | **条件概率**：在给定 (SRC, REL) 下，信息流到达 DST 的概率。取值范围 [0, 1]。M_e 接近 1 表示该边是常见走向；M_e 接近 0 或为 0 表示基线中几乎未出现，对应**罕见/异常边**。分母为 0 时 M_e 取 0 |

---

### 3.3 IN/OUT 分数（§VI-C）

基于**当前上下文图**（告警窗口内的依赖事件）统计每个顶点的度，并转换为分数。

| 符号           | 含义                                                         |
| -------------- | ------------------------------------------------------------ |
| **out_deg[v]** | 顶点 v 的**出度**：在上下文中，以 v 为源（SRC）的依赖边数量  |
| **in_deg[v]**  | 顶点 v 的**入度**：在上下文中，以 v 为目标（DST）的依赖边数量 |
| **OUT(v)**     | 出度相关分数：1 / (1 + out_deg[v])。出度越大，OUT 越小，表示高度数节点（如 sshd）作为源时，单条出边被“稀释”，贡献降低；若无出边则 OUT = 1 |
| **IN(v)**      | 入度相关分数：1 / (1 + in_deg[v])。入度越大，IN 越小，表示高度数节点作为目标时，单条入边被“稀释”；若无入边则 IN = 1 |

---

### 3.4 路径正则性分数 RS(P)（Eq.(2)(3)）

$$
RS(P) = \prod_{e \in P} \left( IN(v_{src}) \cdot M_e \cdot OUT(v_{dst}) \right)
$$

| 符号           | 含义                                                         |
| -------------- | ------------------------------------------------------------ |
| **P**          | 一条依赖路径，即边的有序序列，包含告警边及其上下游依赖链     |
| **e**          | 路径 P 中的单条边，对应依赖事件 \<SRC, DST, REL\>            |
| **v_src**      | 边 e 的源顶点                                                |
| **v_dst**      | 边 e 的目标顶点                                              |
| **IN(v_src)**  | 源顶点的入度分数（见 3.3），对路径中该边的贡献做惩罚         |
| **M_e**        | 边 e 的转移概率（见 3.2），反映该边在基线中的常见程度        |
| **OUT(v_dst)** | 目标顶点的出度分数（见 3.3），对路径中该边的贡献做惩罚       |
| **RS(P)**      | 路径 P 上所有边对应三项的**连乘积**。RS 越高表示路径越“常规”、在基线中越常见；RS 越低表示路径越罕见 |

---

### 3.5 异常分数 AS(P)（Eq.(6)）

$$
AS(P) = 1 - RS(P)
$$

| 符号      | 含义                                                         |
| --------- | ------------------------------------------------------------ |
| **RS(P)** | 路径正则性分数（见 3.4）                                     |
| **AS(P)** | 异常分数，取值范围 [0, 1]。RS 越高 → AS 越低（路径常规）；RS 越低 → AS 越高（路径异常）。空路径视为完全异常，AS = 1 |

---

### 3.6 Algorithm 1：路径枚举（GETPATHANOMALYSCORE）

```
输入: 告警事件 E_α, 依赖图 G, 最大路径长度 τl
1. 构建依赖图 G（backward/forward 邻接）
2. vsrc ← E_α 的源顶点, vdst ← E_α 的目标顶点
3. Lb ← 从 vsrc 沿入边后向 DFS，深度 ≤ τl-1（祖先路径）
4. Lf ← 从 vdst 沿出边前向 DFS，深度 ≤ τl-1（后继路径）
5. Lp ← 组合：P = [B_k,...,B_1, E_α, F_1,...,F_m]，总长度 ≤ τl
6. 对 Lp 中每条路径 P 计算 AS(P)
7. 返回路径及其异常分数
```

| 符号                | 含义                                                         |
| ------------------- | ------------------------------------------------------------ |
| **E_α**             | 告警对应的依赖事件                                           |
| **τl (tau_l)**      | 最大路径长度：单条路径允许的最大边数。控制枚举深度，越大图越复杂、计算量越大 |
| **Lb**              | 后向路径列表：从告警源回溯得到的祖先依赖链                   |
| **Lf**              | 前向路径列表：从告警目标延伸得到的后继依赖链                 |
| **aggregate_score** | 单条告警的最终分数：取该告警**所有路径中的最大 AS(P)**。任一路径高度异常则告警高优先级 |

---

### 3.7 Algorithm 3：路径合并（τm）

按异常分数降序排列路径，依次保留路径，当相邻路径分数差 **S1 − S2 ≥ τm** 时停止，保留高分数路径簇。

| 符号           | 含义                                                         |
| -------------- | ------------------------------------------------------------ |
| **S1, S2**     | 相邻两条路径的异常分数（S1 ≥ S2）                            |
| **τm (tau_m)** | 路径合并阈值：分数差 ≥ τm 视为“断崖”，停止合并。τm 越大保留路径越少（只留最异常）；τm 越小保留路径越多 |

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
| max_paths    | 路径数量上限，防止 DFS 路径爆炸；null 表示不限制             | 2000   |
| top_n        | 仅输出前 N 条告警，null 表示全部输出                         | null   |

**构建图成本优化建议**（日志量大时）：

- 减小 `window_lines`（如 200）以缩小上下文
- 减小 `tau_l`（如 10）以限制路径深度
- 设置 `max_paths`（如 2000）防止路径爆炸
- `load_ndjson_with_events` 默认使用 `minimal_record=True`，仅保留 agent/predecoder/rule，显著降低内存

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
