# RLDump — Rocket League Training Packs (`.Tem`) & Replay (`.replay`) Deep Analysis

本仓库包含针对 `RLorig.zip`（包含 **3 个自定义训练包 `.Tem` 文件**、**1 个 RLCS 世界赛级别回放 `.replay` 文件** 以及 **macOS 容器元数据/取证信息**）的完整逆向解析方法、工具脚本与全量结构化解析成果。

---

## 目录结构 (Repository Layout)

```text
├── README.md                                   # 完整解析报告、技术原理与成果汇总
├── raw/                                        # 原始归档与解压文件
│   ├── RLorig.zip                              # 原始 ZIP 压缩包
│   └── RLorig/                                 # 原始文件目录 (.Tem, .replay, .DS_Store)
├── src/                                        # 逆向解析与提取脚本
│   ├── parse_tem.py                            # .Tem 训练包 CRC32 校验、AES-256-ECB 解密与 UE3 SaveData 解析器
│   ├── parse_replay.py                         # .replay 回放头部、NetStream 位流帧解析与物理/Boost 遥测提取器
│   ├── parse_forensics.py                      # ZIP 结构、.DS_Store 与 AppleDouble (._*) 扩展属性取证解析器
│   └── CHN_Stadium_P.json                      # 地图 (Forbidden Temple) 34 个 Boost Pad 坐标与属性映射表
└── parsed/                                     # 解析产出数据
    ├── training_packs/                         # 三个训练包的解密二进制与结构化 JSON
    │   ├── summary.json                        # 三个训练包核心元数据对比汇总
    │   ├── 172CA0CF4A0FF134062365815A6A5816.json
    │   ├── 172CA0CF4A0FF134062365815A6A5816.decrypted.bin
    │   ├── A2AD27B74DE54E9E99B104982853DE26.json
    │   ├── A2AD27B74DE54E9E99B104982853DE26.decrypted.bin
    │   ├── 5F69C04047BEF4D8509A7289138FAFFB.json
    │   └── 5F69C04047BEF4D8509A7289138FAFFB.decrypted.bin
    ├── replay/                                 # 回放文件全量解析数据
    │   ├── replay_analytics.json               # 比赛元数据、14 名房间成员档案、涂装/镜头配置、事件与遥测统计
    │   ├── replay_header.json                  # 原始回放 Header、TickMarks、KeyFrames、ClassNetCache 结构
    │   ├── boost_pad_pickups.json              # 全场 472 次有效 Boost Pad 拾取事件时间线（含偷取判定）
    │   ├── ball_trajectory.csv                 # 足球全场 8,877 个刚体物理状态采样点 (X, Y, Z, Vx, Vy, Vz, Speed)
    │   └── replay_full_netstream.json.gz       # 全场 9,379 帧完整网络流 (NetStream) Actor 更新转储 (Gzip 压缩)
    └── forensics/                              # 容器与宿主环境取证数据
        └── macos_and_zip_forensics.json        # ZIP Central Directory、.DS_Store 与 AppleDouble 扩展属性完整解析
```

---

## 一、 核心解析方法论 (Methodology & Reverse Engineering)

### 1. 自定义训练包 (`.Tem`) 解密与反序列化方法
Rocket League 的自定义训练包文件（后缀 `.Tem`）本质上是**经过加密的 Unreal Engine 3 `SaveData_GameEditor_Training_TA` 序列化对象**：
1. **外层帧头 (8 Bytes)**：
   - `0x00..0x03` (`uint32 LE`)：`Part1Length`，即后续加密负载的字节长度（必为 16 字节的整数倍）。
   - `0x04..0x07` (`uint32 LE`)：`Part1CRC`，基于 Rocket League 专用的 **MSB-first CRC-32 算法**（多项式 `0x04C11DB7`，初始种子 `CRC_SEED = 0xEFCBF201`，初值与终值按位取反 `~seed`）。
2. **AES-256-ECB 解密**：
   - 紧随其后的 `Part1Length` 字节采用 **AES-256-ECB** 模式加密（无 IV，尾部以 `0x00` 对齐至 16 字节块边界）。
   - 逆向提取的 32 字节固定密钥（源自 `RocketRP` / 游戏客户端）：
     ```text
     D7 8C 32 4A 94 42 94 3C 6D 65 CE 98 81 85 4C 41
     68 99 22 0C C7 A1 46 40 93 9B 96 3C 93 2A 6F AF
     ```
3. **内层 SaveData 二进制结构**：
   - **Magic 校验头 (8 Bytes)**：`0xF005BA11` (`FOOSBALL` 魔数，小端序为 `11 BA 05 F0`) + `0x7FFFFFFF` (`MAGIC`)。
   - **版本信息 (12 Bytes)**：`EngineVersion` (`int32`)、`LicenseeVersion` (`int32`)、`TypeVersion` (`int32`)。
   - **SaveData 块**：`savedataLength` (`int32`) + `savedataLength - 4` 字节的序列化属性流，随后是 `ObjectTypes` 索引表（记录 `TAGame.TrainingEditorData_TA` 在流中的偏移 `FilePosition`）。
   - **Unreal 属性反射树 (`TrainingEditorData_TA`)**：包含 `TM_Guid`、`Code`、`TM_Name`、`Type`、`Difficulty`、`CreatorName`、`Tags`、`MapName`、`CreatedAt`、`UpdatedAt`、`CreatorPlayerID` 以及 `Rounds` 数组。
   - **内嵌 JSON 原型 (`SerializedArchetypes`)**：每个回合 (`EditorRoundData`) 包含 `TimeLimit`（秒）以及由 3 个 JSON 字符串组成的 `SerializedArchetypes` 数组：
     - `Archetypes.Ball.Ball_GameEditor`：球初始坐标 $(X, Y, Z)$、发射初速度方向 $(P, Y, R)$ 与初速度标量 `VelocityStartSpeed` ($\text{uu/s}$)。
     - `Archetypes.GameEditor.DynamicSpawnPointMesh`：玩家车辆生成点坐标与朝向。
     - `{"IsPC": true, ...}`：编辑器自由视角相机 (Editor FreeCam) 的保存坐标与朝向。
   - **角度与速度换算**：Unreal 旋转单位 (`URU`) 满足 $65536\text{ URU} = 360^\circ$，即 $\theta_{\text{deg}} = \text{URU} \times \frac{360}{65536}$；球的三维初速度分量为：
     $$v_x = S \cos(P)\cos(Y),\quad v_y = S \cos(P)\sin(Y),\quad v_z = S \sin(P)$$

---

### 2. 比赛回放 (`.replay`) 头部与 NetStream 位流解析方法
1. **双段式 CRC-32 结构**：
   - `.replay` 文件未加密，分为 **Part 1 (Header 属性树)** 与 **Part 2 (Content + NetStream 压缩位流)** 两部分，各自以 `uint32 Length + uint32 CRC` 开头，使用与 `.Tem` 完全相同的 `CRC_SEED = 0xEFCBF201` 校验。
2. **Part 1 (Header)**：
   - 采用与 `.Tem` 相同的 UE3 属性树格式，可直接读取比赛基础概览（比分、玩家面板统计 `PlayerStats`、高亮帧 `HighLights`、进球记录 `Goals`、游戏构建版本 `BuildVersion`、地图 `MapName` 等）。
3. **Part 2 (NetStream 网络复制流)**：
   - 包含地图层级 `Levels`、关键帧索引 `KeyFrames`、长达 9,379 帧的 **Bit-packed Network Stream (`NetStreamData`)**、BakkesMod 调试日志 `Logs`、时间轴标记 `TimelineKeyframes`、`Packages`、`Objects`（441 个对象名）、`Names`（226 个名称）以及 `ClassNetCaches`（网络属性映射树）。
   - 通过 `rrrocket` (`boxcars`) 对位流进行逐比特反序列化，结合 `src/parse_replay.py` 跨帧状态机追踪全部 Actor 通道的创建、更新与销毁，能够还原出**仅存在于网络帧流中、不在 Header 里的深层隐藏数据**（如服务器名称、全部 8 名裁判/OB 观察者账号、每个玩家的完整车身涂装 ID、视角参数 `ProfileSettings`、转向灵敏度 `SteeringSensitivity`、每次爆炸/击毁的瞬间三维速度矢量、34 个 Boost Pad 的精确拾取与偷取记录，以及 30 FPS 刚体运动轨迹）。

---

### 3. macOS 容器与文件系统取证解析方法
- 解析 ZIP Central Directory 条目属性、`.DS_Store` (Buddy Allocator B-Tree 结构) 以及 `__MACOSX/._*` (AppleDouble v2 格式 `0x00051607`) 中的 `ATTR` 扩展属性表与内嵌 `bplist00` 二进制属性列表，还原文件下载来源 URL、浏览器 Quarantine 隔离时间戳、LocalSend 跨设备传输痕迹及窗口布局。

---

## 二、 三个自定义训练包 (`.Tem`) 完整解析结果

### 1. 元数据与校验总览

| 属性字段 | 训练包 1 (`172CA0CF...Tem`) | 训练包 2 (`A2AD27B7...Tem`) | 训练包 3 (`others/5F69C040...Tem`) |
| :--- | :--- | :--- | :--- |
| **文件路径** | `RLorig/172CA0CF4A0FF134062365815A6A5816.Tem` | `RLorig/A2AD27B74DE54E9E99B104982853DE26.Tem` | `RLorig/others/5F69C04047BEF4D8509A7289138FAFFB.Tem` |
| **文件大小 / 密文长度** | 1,848 B / 1,840 B | 1,128 B / 1,120 B | 35,304 B / 35,296 B |
| **CRC-32 (存储 / 计算)** | `0xE9328B99` / `0xE9328B99` (通过) | `0xF8F36FAA` / `0xF8F36FAA` (通过) | `0x39781F9A` / `0x39781F9A` (通过) |
| **Engine / Licensee 版本** | `868` / `34` (较新版本本地创建) | `868` / `34` (较新版本本地创建) | `868` / `32` (线上下载包) |
| **Root 属性** | `TrainingData: 0` | `TrainingData: 0` | `TrainingData: 0`, `bUnowned: true` |
| **TM_Guid** | `172CA0CF-4A0FF134-06236581-5A6A5816` | `A2AD27B7-4DE54E9E-99B10498-2853DE26` | `5F69C040-47BEF4D8-509A7289-138FAFFB` |
| **训练包名称 (`TM_Name`)** | `New Sequence` | `New Sequence` | `Kevpert: Adv Double Taps 1 F10` |
| **分享码 (`Code`)** | `None` (未上传发布) | `None` (未上传发布) | `3115-DC26-525D-F409` |
| **训练类型 (`Type`)** | `Training_Striker` (前锋射门) | `Training_Striker` (前锋射门) | `Training_Striker` (前锋射门) |
| **难度 (`Difficulty`)** | 未设置 (默认 Rookie) | 未设置 (默认 Rookie) | `D_Medium` (Pro / 中等) |
| **地图 (`MapName`)** | `woods_p` (Sovereign Heights) | `music_p` (Deadmau5 / Neon Fields 类音乐图) | `EuroStadium_Night_P` (Mannfield Night) |
| **创建者 (`CreatorName`)** | `None` (本地未命名作者) | `None` (本地未命名作者) | `Hampert` (知名教练/主播 Kevpert 小号) |
| **创建者平台与 ID** | `None` | `None` | Steam: `76561198141307920` |
| **创建时间 (`CreatedAt`)** | `None` | `None` | `1608246054` (`2020-12-17T23:00:54Z`) |
| **更新时间 (`UpdatedAt`)** | `None` | `None` | `1744572550` (`2025-04-13T19:29:10Z`) |
| **回合数 (`Rounds`)** | **2 回合** | **1 回合** | **50 回合** |

---

### 2. 训练包 1 (`172CA0CF4A0FF134062365815A6A5816.Tem`) 逐回合物理参数
本地在 `woods_p` 地图创建的 2 回合射门训练包：
- **Round 1**（限时 `10.0s`）：
  - **球 (`Ball_GameEditor`)**：初始位置 $(-3798.04, -1111.01, 1663.37)$（高空静止悬停球），发射朝向 $(P=2931\text{ URU } [16.10^\circ], Y=-23881\text{ URU } [-131.18^\circ], R=0)$，初速度 **`0.0 uu/s`**（静止高空球）。
  - **车辆生成点 (`DynamicSpawnPointMesh`)**：位置 $(602.21, -4733.64, 30.0)$，朝向 $(P=0, Y=-38822\text{ URU } [-213.26^\circ], R=0)$。
  - **编辑器相机 (`EditorFreeCam`)**：位置 $(-542.00, -609.03, 530.0)$，朝向 $(P=10012\text{ URU } [55.00^\circ], Y=10464\text{ URU } [57.48^\circ], R=0)$。
- **Round 2**（限时 `10.0s`）：
  - **球 (`Ball_GameEditor`)**：初始位置 $(-2699.80, 2868.59, 100.00)$，发射朝向 $(P=235\text{ URU } [1.29^\circ], Y=-27545\text{ URU } [-151.31^\circ], R=0)$，初速度 **`3650.0 uu/s` (`131.4 kph`)**，三维初速度矢量 $(-3200.62, -1751.62, 82.18)\text{ uu/s}$。
  - **车辆生成点 (`DynamicSpawnPointMesh`)**：位置 $(602.21, -4733.64, 30.0)$（与第 1 回合完全相同），朝向 $-213.26^\circ$。
  - **编辑器相机 (`EditorFreeCam`)**：位置 $(2016.34, -4429.56, 530.0)$，朝向 $(P=28\text{ URU } [0.15^\circ], Y=23951\text{ URU } [131.57^\circ], R=0)$。

---

### 3. 训练包 2 (`A2AD27B74DE54E9E99B104982853DE26.Tem`) 逐回合物理参数
本地在 `music_p` 地图创建的 1 回合射门训练包：
- **Round 1**（限时 `10.0s`）：
  - **球 (`Ball_GameEditor`)**：初始位置 $(-129.32, 2698.33, 1673.39)$（球门前高空悬停球），发射朝向 $(P=1747\text{ URU } [9.60^\circ], Y=-8221\text{ URU } [-45.16^\circ], R=0)$，初速度 **`0.0 uu/s`**。
  - **车辆生成点 (`DynamicSpawnPointMesh`)**：球场中心原点 $(0.0, 0.0, 30.0)$，朝向正前方 $(P=0, Y=16384\text{ URU } [90.0^\circ], R=0)$。
  - **编辑器相机 (`EditorFreeCam`)**：位置 $(-600.00, -700.00, 530.0)$，朝向 $(P=500\text{ URU } [2.75^\circ], Y=12940\text{ URU } [71.08^\circ], R=0)$。

---

### 4. 训练包 3 (`others/5F69C04047BEF4D8509A7289138FAFFB.Tem`) 详细分析
这是由社区知名训练创作者 **Hampert (Kevpert)** 制作并发布的进阶双触训练包 **`Kevpert: Adv Double Taps 1 F10`**（代码：`3115-DC26-525D-F409`）：
- 包含完整的 **50 个回合**（每回合限时 `10.0s`），全部 50 个回合的精确球位置、三维初速度、车辆出生点及相机位置均已完整导出至 `parsed/training_packs/5F69C04047BEF4D8509A7289138FAFFB.json`。
- **物理特征统计**：
  - 球初速度范围：`1151.16 uu/s` (`41.44 kph`) 至 `2343.30 uu/s` (`84.36 kph`)。
  - 球初始高度 $Z$ 范围：`98.41 uu`（地面贴地球）至 `1476.33 uu`（高空球）。
  - 注意：`VelocityStartRotationR`（翻滚角 Roll）在多个回合中非零（如 Round 1 为 `-1852 URU` 即 `-10.17°`），说明该训练包通过 BakkesMod / 外部训练编辑器微调过旋转参数。

---

## 三、 比赛回放 (`3adc59ea-2a3d-49b0-bd92-15f0d27bb3f6.replay`) 全量解析结果

### 1. 比赛基础信息与服务器底层配置

| 字段分类 | 字段名 | 解析值 | 说明 |
| :--- | :--- | :--- | :--- |
| **比赛信息** | `ReplayName` | `WORLDS P-L KC vs FLCN G2 2026-09-20.13.37` | RLCS 世界赛 Play-In / Playoffs: **Karmine Corp vs Team Falcons** 第 2 局 |
| **唯一标识** | `Id` / `MatchGUID` | `92468BAF4847478F181A2882B9873616` / `91C3752A11F1B521D5514198DFFAAFCB` | 回放文件 ID 与对局全局唯一 GUID |
| **时间信息** | `MatchStartEpoch` / `GameStartTime` | `1789929120` (`2026-09-20T18:32:00Z`) / `2026-09-20T13:32:04-0500` | BakkesMod 记录当地时区为 `UTC-5`（美国中部夏令时 CDT），回放保存于 `13:37:49` |
| **版本信息** | `BuildVersion` / `Changelist` | `260825.79374.526531` (BuildID: `-1887694083`) | Engine `868`, Licensee `33`, NetVersion `11`, ReplayVersion `8`, GameVersion `30` |
| **服务器信息** | `ServerName` / `GameServerID` | `LAN230-Laserath-5` / `200114737` | 锦标赛专用服务器，Region: `TR21` (Tournament Region)，Playlist: `6` (Private Match) |
| **地图与帧率** | `MapName` / `NumFrames` | `CHN_Stadium_P` (Forbidden Temple) | 录制帧率 `30.0 FPS`，总帧数 `9,379` 帧，比赛时长 `301.45685s` |
| **最终比分** | **KARMINE CORP (Team 0)** vs **TEAM FALCONS (Team 1)** | **1 : 0** | 全场唯一进球由 **Atow** 在第 `1,169` 帧（比赛剩余约 4:10，流时间 `58.38s`）打进，**juicy** 助攻 |
| **插件签名** | `debug_info[0]` | `Message from the Wizard` | 录制端开启了 **BakkesMod** 注入附加回放数据 |

---

### 2. 房间全员档案：6 名参赛选手 + 8 名隐藏裁判/导播观察者 (共 14 人)

Header 的 `PlayerStats` 仅记录了 6 名上场选手，但通过解析 NetStream 中的 `TAGame.Default__PRI_TA` 与 `ProjectX.GRI_X:Reservations`，我们还原了房间内**全部 14 个连接客户端**的真实账号、Epic PUID、战队 Club ID、称号与角色：

#### (A) 参赛选手 (6 人，全部使用 Steam 登录并绑定 Epic PUID，全部驾驶 **Fennec [ID: 4284]**)

| 队伍 | 选手名称 | PlayerID | 匿名代号 | Steam 64位 ID | Epic PUID | Club ID | 游戏内称号 (`Title`) | 转向灵敏度 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **KARMINE CORP (Team 0)** | **vatira** | 286 | Player 3 | `76561198960239428` | `0002150d5a464203b32587e683f90749` | `32975387` | `RLCS_2026_Major_2_Champion` | `1.50` |
| **KARMINE CORP (Team 0)** | **Atow** | 293 | Player 10 | `76561198289610054` | `0002235ce23143fd8e5f47688d344671` | `32975387` | `RLCS_2026_Major_2_Champion` | `2.00` |
| **KARMINE CORP (Team 0)** | **juicy** | 290 | Player 7 | `76561199013030566` | `0002beb5193a457199c59bc01785cb90` | `32975387` | *(未装备称号)* | `1.40` |
| **TEAM FALCONS (Team 1)** | **dralii** | 284 | Player 1 | `76561199031413358` | `0002207a58cf4fbdbb9abe889f4c82ea` | `25765418` | `RLCS_2024_World_Champion` | `1.77` |
| **TEAM FALCONS (Team 1)** | **Rw9** | 289 | Player 6 | `76561199017029799` | `000254224e3f45579238fa90697be5f8` | `25765418` | `RLCS_2025_Major_2_Champion` | `1.50` |
| **TEAM FALCONS (Team 1)** | **Kiileerrz** | 285 | Player 2 | `76561198980777579` | `00028e46a31746eb89d68318c30db8b4` | `25765418` | `RLCS_2025_Major_2_Champion` | `2.00` |

#### (B) 隐藏裁判与赛事导播观察者 (8 人，`PawnType = 1` 即观察者席)

| 名称 (`PlayerName`) | PlayerID | 匿名代号 | 平台与唯一账号 ID | Epic PUID | 称号 (`Title`) | 预设车辆 / 灵敏度 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RLCS REFEREE** (裁判 1) | 295 | Player 12 | Steam: `76561198129459418` | `0002571ddf884a918558e467274150b6` | `RLCS_Referee` | Octane (`23`) / — |
| **RLCS REFEREE** (裁判 2) | 296 | Player 13 | Steam: `76561198139620936` | `0002b3f8e0d64906b1b33a62a1a346a6` | `RLCS_Referee` | Dominus (`1568`) / `1.30`, Club: `30767366` |
| **baguetteobs1** (法语流 OB) | 292 | Player 9 | Epic: `aab96296dc704222b85ee9985361a612` | `0002ed7d155a4806bb1747ab2c3151a0` | `Bracket_Rivalry_Team1` | Fennec (`4284`) / `1.80` |
| **blastobserver1** (BLAST 主导播) | 288 | Player 5 | Epic: `5d11da18ca094606826cb11d4d776046` | `00025258ec5d4775a2a533aa37e2475a` | `Bathroom_Title` | Octane (`23`) / — |
| **blastobserver2** (BLAST 导播 2) | 297 | Player 14 | Epic: `f935828ffd104990a5af3c2c41baba85` | `00023f16fc1a4be89f395fad9589734d` | `Bathroom_Title` | Octane (`23`) / — |
| **blastobserver3** (BLAST 导播 3) | 287 | Player 4 | Epic: `c7c09cddf9384f6c9d41bba992b55c99` | `0002b51eb11a4631ab0797acd7286768` | `Bathroom_Title` | Octane (`23`) / — |
| **blastobserver4** (BLAST 导播 4) | 291 | Player 8 | Epic: `298a10606ed04dccbc59fe2ce1a92ea4` | `0002107270c24a429f76bf41ae2b08d9` | `jstncrdbl` | Octane (`23`) / — |
| **blastobserver5** (BLAST 导播 5) | 294 | Player 11 | Epic: `f7cb8ded2c8f4d29b0f0dbba914ec1af` | `00024534ceb74afbbd3efcf630c7af27` | `jstncrdbl` | Octane (`23`) / — |

---

### 3. 选手相机设置 (`ProfileSettings`) 与表现遥测统计

| 选手 | FOV | 高度 | 角度 | 距离 | 刚度 (Stiffness) | 旋转速度 (Swivel) | 过渡速度 | 得分 | 进球/助攻/扑救/射门 | 摧毁/被摧毁 | 平均车速 (uu/s / kph) | 超音速占比 | 腾空占比 | 高空 (>300uu) 占比 | 前场占比 | 平均 Boost | 拾取大球/小球 (偷大/偷小) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Atow** (KC) | 110 | 100 | -3.0° | 270 | 0.40 | 4.2 | 1.4 | 320 | **1** / 0 / 1 / 3 | **3** / 0 | **1672.8** (60.2) | **20.18%** | 46.61% | **22.78%** | **48.39%** | 46.9 | 15 / **104** (**6** / **45**) |
| **vatira** (KC) | 110 | 90 | -5.0° | 270 | 0.35 | 8.5 | 1.7 | 291 | 0 / 0 / 2 / 4 | 1 / 1 | 1631.4 (58.7) | 19.71% | 44.87% | 17.05% | 42.10% | **57.6** | **22** / 71 (3 / 22) |
| **juicy** (KC) | 110 | 90 | -4.0° | 270 | 0.45 | 7.2 | 1.2 | 330 | 0 / **1** / 2 / 1 | 2 / 0 | 1628.6 (58.6) | 15.17% | 41.73% | 19.10% | 45.33% | 53.4 | 16 / 80 (1 / 30) |
| **dralii** (FLCN) | 110 | 90 | -5.0° | 270 | 0.50 | 4.2 | 1.5 | 196 | 0 / 0 / 1 / 2 | 1 / 1 | 1575.5 (56.7) | 15.57% | 41.25% | 15.14% | 26.94% | 49.3 | 21 / 81 (3 / 19) |
| **Rw9** (FLCN) | 110 | 100 | -5.0° | 270 | 0.35 | 3.5 | 1.0 | 287 | 0 / 0 / 2 / 4 | 0 / 1 | 1575.2 (56.7) | 19.15% | 47.15% | 20.82% | 28.02% | 43.2 | 16 / 69 (1 / 22) |
| **Kiileerrz** (FLCN) | 110 | 100 | -5.0° | 270 | 0.40 | 10.0 | 1.5 | **375** | 0 / 0 / **3** / 0 | 0 / **4** | 1449.0 (52.2) | 12.52% | **47.70%** | 21.36% | 24.81% | 48.1 | 17 / 67 (2 / 11) |

> **战术洞察**：Karmine Corp 全场制造了 **6 次击毁 (Demolishes)**（其中 Atow 独造 3 次，且全部针对 Kiileerrz，导致 Kiileerrz 全场被炸 4 次、0 射门，车速被严重限制在 1449 uu/s）；同时 Atow 在对方半场偷取了 6 个大 Boost 和 45 个小 Boost，帮助 KC 将战火长期压制在 Falcons 半场（KC 三人前场占比 42%~48%，而 Falcons 三人前场占比仅 24%~28%）。

---

### 4. 全场 7 次击毁 (`ReplicatedDemolishExtended`) 精确时间线

| 序号 | 帧号 (`Frame`) | 流时间 (`Time`) | 攻击者 (`Attacker`) | 受害者 (`Victim`) | 攻击者三维速度 ($\text{m/s}$) | 攻击者速率 ($\text{uu/s}$) | 受害者速率 ($\text{uu/s}$) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `1442` | `76.467s` | **Atow** (KC) | **Kiileerrz** (FLCN) | $(2.08, 22.75, 1.02)$ | `2287.0` | `2300.0` |
| 2 | `2709` | `119.059s` | **Atow** (KC) | **Kiileerrz** (FLCN) | $(-7.60, -21.71, 0.00)$ | `2300.0` | `1818.0` |
| 3 | `4193` | `169.410s` | **vatira** (KC) | **Kiileerrz** (FLCN) | $(22.90, -0.06, 2.12)$ | `2300.0` | `1132.0` |
| 4 | `5206` | `203.540s` | **juicy** (KC) | **Rw9** (FLCN) | $(-16.94, -14.71, 3.08)$ | `2265.0` | `1560.0` |
| 5 | `5467` | `212.384s` | **dralii** (FLCN) | **vatira** (KC) | $(-10.77, -20.32, 0.00)$ | `2300.0` | `1768.0` |
| 6 | `7028` | `264.920s` | **Atow** (KC) | **Kiileerrz** (FLCN) | $(1.49, 19.47, 12.05)$ | `2295.0` (空中击毁) | `1972.0` |
| 7 | `9186` | `337.627s` | **juicy** (KC) | **dralii** (FLCN) | $(-22.73, 1.18, 0.00)$ | `2276.0` | `1580.0` |

---

## 四、 容器与 macOS 宿主环境取证 (`parsed/forensics/macos_and_zip_forensics.json`)

通过对 `RLorig.zip`、`.DS_Store` 以及 `__MACOSX/._*` (AppleDouble) 资源分叉文件的取证分析，还原出以下传播链路：
1. **回放文件来源 (`._3adc59ea-2a3d-49b0-bd92-15f0d27bb3f6.replay`)**：
   - `com.apple.metadata:kMDItemWhereFroms`：直接记录了该回放的原始下载直链：
     `https://ballchasing.com/dl/replay/3adc59ea-2a3d-49b0-bd92-15f0d27bb3f6?g=kc-vs-flcn-cm34xu0wmm`（对应 Ballchasing 上的比赛组 `kc-vs-flcn-cm34xu0wmm`）。
   - `com.apple.metadata:kMDItemDownloadedDate` & `com.apple.lastuseddate#PS`：`2026-10-24T10:04:46.083091Z`（精确到纳秒 `86591959 ns`）。
   - `com.apple.quarantine`：`q/0083;6adc82be;Safari;2A49FA1C-BE29-4C98-AC59-9B64D0C1041B`（使用 macOS **Safari** 浏览器下载，Quarantine 事件 UUID 为 `2A49FA1C-BE29-4C98-AC59-9B64D0C1041B`）。
2. **第三方训练包传输来源 (`others/._5F69C04047BEF4D8509A7289138FAFFB.Tem`)**：
   - `com.apple.quarantine`：`q/0082;6a1aa0fb;LocalSend;` —— 表明该文件于 `2026-05-30T08:34:03Z` 通过局域网跨设备传输工具 **LocalSend** 接收。
   - `com.apple.provenance`：`01020039ea8b2f98326147`（与另外两个本地 `.Tem` 文件具有完全一致的 macOS 设备 Provenance 标识 `39ea8b2f98326147`，证明它们在同一台 Mac 上被操作处理）。
3. **Finder 窗口与目录状态 (`RLorig/.DS_Store`)**：
   - 记录了子目录 `others` 的逻辑大小 (`lg1S = 35,304 Bytes`)、物理分配块大小 (`ph1S = 36,864 Bytes`)、修改时间 (`moDD = 2026-10-24T09:50:27.321507Z`)，以及打包者当时的 macOS Finder 窗口坐标与尺寸：`{{589, 735}, {920, 492}}`（开启了状态栏、工具栏、标签页视图和侧边栏）。

---

## 五、 复现与运行指南 (Reproduction)

```bash
# 1. 解析并解密全部 .Tem 训练包文件
python3 src/parse_tem.py

# 2. 解析 .replay 回放文件（需先使用 rrrocket 导出帧流或直接运行脚本）
python3 src/parse_replay.py

# 3. 提取 macOS 与 ZIP 容器取证数据
python3 src/parse_forensics.py
```
