# ue5hook — UE5 MinHook 示例（KARDS）

一个可编译、已验证的 UE5 inline hook 示例：用 AOB 特征码定位
`UObject::StaticConstructObject_Internal`，用 [MinHook](https://github.com/TsudaKageyu/minhook)
挂上 detour，把每次对象构造记录到日志，且不给游戏主线程添负担。

参考：[CCB-TEAM · UE5 游戏手动逆向](https://ccb-team.github.io/ue5-re/)，重点第 06 章（AOB 特征码）
与第 09 章（MinHook 上手）。

**适用边界**：单机 mod、私服研究、自有构建的调试。不涉及反作弊绕过、检测规避、驱动级隐藏。
在线多人环境里注入通常违反 EULA 与 ToS，动手前先确认授权——这属于你自己的判断。

---

## 一、已实测确认的事实

### 特征码

```
4C 8B DC 55 53 41 56 49 8D AB 28 FE FF FF 48 81 EC C0 02 00 00
48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 A0 01 00 00 8B 41 70 33 DB 49 89 73 10
```

47 字节，4 个通配符。反汇编对照：

| 字节 | 指令 | 说明 |
|---|---|---|
| `4C 8B DC` | `mov r11, rsp` | 帧指针保存 |
| `55` `53` `41 56` | `push rbp` / `push rbx` / `push r14` | 寄存器保存 |
| `49 8D AB 28 FE FF FF` | `lea rbp, [r11-1D8h]` | 栈帧 |
| `48 81 EC C0 02 00 00` | `sub rsp, 2C0h` | 栈分配 |
| `48 8B 05 ?? ?? ?? ??` | `mov rax, [rip+disp]` | **`__security_cookie`，唯一变化的 4 字节** |
| `48 33 C4` | `xor rax, rsp` | 栈 cookie |
| `48 89 85 A0 01 00 00` | `mov [rbp+1A0h], rax` | 存 cookie |
| `8B 41 70` | `mov eax, [rcx+70h]` | **`rcx` 即 `&FStaticConstructObjectParameters`** |
| `33 DB` `49 89 73 10` | `xor ebx, ebx` / `mov [r11+10h], rsi` | 尾部 |

那 4 个通配符正好覆盖 RIP 相对位移——它是地址，任何重链接都会变。多一个少一个都会让签名
在下次更新时失效。

### 定位结果

用 `tools/aobscan.mjs`（按节表把文件偏移换算成 RVA）与 `selftest.exe`（走 DLL 里同一份
`scan.h` 代码）两条独立路径扫描，结论一致：

| 二进制 | 命中数 | 段 | RVA |
|---|---|---|---|
| `kards-Win64-Shipping.exe` | 1 | `.text` | `0x015C6C80` |
| `kards-Win64-Shipping1.exe` | 1 | `.text` | `0x015C6C80` |
| `dlw1.exe` | 1 | `.text` | `0x015C6C80` |
| `CMTEST测卡服.exe` | 1 | `.text` | `0x015C6C80` |

四个 exe 的 SHA256 各不相同（是不同构建），但该签名在四处**都是唯一命中且 RVA 相同**。

命中点前 8 字节是 `CC CC CC CC CC CC CC CC`（int3 填充）——真实函数入口的形态，这是
「签名指向函数开头而不是函数中间的某段字节」的独立佐证。

### 锚点：GUObjectArray 与名称池

拿到 `StaticConstructObject_Internal` 之后，按专栏第 08 章的**路径 1** 继续走：该函数内部
会引用 `GUObjectArray`，所以从它的指令流里就能把这个全局量捞出来——不必再为
`GUObjectArray` 写一条特征码，也就不必赌它的布局（而布局恰恰是逐游戏会变的那部分）。

实现用 MinHook 自带的 HDE64 做线性扫描（`src/disasm.h`），收集所有 `lea reg,[rip+disp]` 与
`mov reg,[rip+disp]` 的目标，再逐个校验候选。校验用的是「错候选不可能同时满足」的一组约束：

| 校验项 | 约束 |
|---|---|
| `NumElements` | 1,000 ~ 20,000,000 |
| `NumChunks` | 必须等于 `ceil(NumElements / 65536)`（允许 +1） |
| `MaxChunks` / `MaxElements` | 不得小于当前值 |
| 第一个 chunk 的第一个槽 | 必须是一个可读的 `UObject` |

名称池没法这样走——手上没有「必然引用它」的函数。改用**结构特征**：`Blocks` 是 8192 个指针，
只有用到的块非空，所以数组尾部是**几千个连续零 qword**（几十 KB）。先找这个零串，再往回数
非空指针，就得到数组起点。最后用一条不可能被误判的校验收口：

> **条目 0 必须解码成 `"None"`。** `NAME_None` 在所有 UE 构建里都是索引 0，字符串就是 `None`。

实测结果：

```
GUObjectArray=0x7FF63BBC4050 (RVA 0x91F4050)  elements=96984  chunks=2
NamePool.blocks=0x7FF63BAE0550 (RVA 0x9110550)  layout=legacy
```

- `0x7FF63BBC4050` 与 UE4SS 日志里的 `GUObjectArray: 0x7ff63bbc4050` **完全一致**——两条
  完全独立的路径（这里的反汇编 vs UE4SS 的内置签名）落到同一个地址
- `chunks=2 = ceil(96984 / 65536)`，自洽
- 名称池布局探测结果是 `legacy`（`bIsWide:1, ProbeHashBits:5, Len:10`），说明这个构建
  **没有**启用大小写保留的 FName

锚点拿到之后，端到端验证是枚举 `UWorld` 实例（专栏第 02 章末尾的用法）：

```
UWorld instances=4
  Default__World  @00007FF431063500
  StartingLevel   @0000026804D20150
  Login           @00000268041D48A0
  Home            @000002680AED52D0
most common classes:
   28783  Function
    6327  Package
    5349  ScriptStruct
    4355  Class
    2208  BlueprintGeneratedClass
    2116  OverlaySlot
    2110  VerticalBoxSlot
    1875  Enum
    1715  MovieSceneBuiltInEasingFunction
    1645  Texture2D
```

这一条同时证明了整条链路：分块数组遍历、`UObject` 的 `ClassPrivate` / `NamePrivate` 偏移、
FName 解码——任何一环错了，这里都只会输出空或乱码。类名分布也是教科书式的：`Function`
最多（每个 `UFunction` 都是一个对象），`Package` / `ScriptStruct` / `Class` 紧随其后；
`Default__World` 的 `Default__` 前缀正是类默认对象（CDO）的标准命名。

---

## 二、目录结构

```
ue5-minhook-example/
├─ build.bat                  一键构建（vswhere 定位 VS + cmake NMake）
├─ CMakeLists.txt
├─ src/
│  ├─ dllmain.cpp             ★ 主示例：定位 → hook → 锚点发现 → 记录 → 卸载
│  ├─ scan.h                  PE 节遍历 + AOB 扫描
│  ├─ disasm.h                HDE64 线性扫描，从函数里捞出全局量
│  ├─ ue.h                    ★ 锚点发现与校验、FName 解码、对象枚举
│  ├─ async_log.h             无锁日志环（Vyukov MPMC）+ 消费线程 + 类名缓存
│  └─ injector.cpp            最小注入器（LoadLibrary / FreeLibrary）
├─ tests/
│  └─ selftest.cpp            验证签名定位与 MinHook 往返
├─ tools/
│  ├─ aobscan.mjs             离线扫描器（文件偏移 → RVA）
│  └─ sections.mjs            打印 PE 节大小，用来给扫描耗时定量
└─ third_party/minhook/       git clone，commit 8af6b4a
```

## 三、构建

```bat
build.bat
```

产出 `build\bin\ue5hook.dll`、`build\bin\injector.exe`、`build\bin\selftest.exe`。

两点环境事实（本机实测）：

- **用 NMake 而不是 `-G "Visual Studio 18 2026"`**。本机 CMake 4.0.2 没有 VS 18 生成器，
  实测报 `Could not create named generator Visual Studio 18 2026`。NMake 用同一套 MSVC，
  只要 vcvars 激活即可。
- **DLL 用静态 CRT（`/MT`）**。实测 `dumpbin /dependents` 显示只依赖 `KERNEL32.dll`，
  没有 vcruntime——注入的 DLL 不该给目标进程引入一个额外的运行时版本依赖。

`build.bat` 用 `vswhere` 自动定位 Visual Studio（VS 2017+ 自带），不写死安装路径；
只需要装了「使用 C++ 的桌面开发」工作负载。MinHook 缺失时会自动 `git clone` 到
`third_party/minhook`。

## 四、自检

```bat
build\bin\selftest.exe
```

会做两件事：把游戏 exe 按 PE 结构手工映射进内存（不执行），跑 DLL 里同一份 `scan.h`
断言命中数与 RVA；再在 RWX 内存里造一个合成函数，走一遍 MinHook 的
create → queue-enable → call → disable → remove → uninitialize。

> **编译通过不等于 hook 正确。** 自检第一次运行时就抓到了一个真 bug，见下面第六节。

## 五、使用

### 方式 A：注入器（调试用，最快）

> 装了 UE4SS 的游戏里，注入器**必须在 UE4SS 完成 hook 之前**进场，否则主签名已被覆写。
> 本 DLL 有位移备选签名兜底，晚注入也能用，但日志头会标 `via=fallback`。想抓启动期的
> 对象构造，只能走方式 B 或尽早注入。

```bat
build\bin\injector.exe kards-Win64-Shipping.exe build\bin\ue5hook.dll
```

卸载：

```bat
build\bin\injector.exe kards-Win64-Shipping.exe ue5hook.dll --eject
```

### 方式 B：代理 DLL（推荐）

把 `ue5hook.dll` 改名成游戏会加载的系统库名放进 exe 同目录。这个目录里已经有一个
`dwmapi.dll`（71 KB），说明这条路线你已经在了。

代理 DLL 的优点不只是「不用注入器」：它在进程启动早期就被加载，**早于引擎构造第一个
对象**，所以启动期的对象构造也能被记录到。注入器做不到这一点。

代价是代理 DLL 必须转发原 DLL 的全部导出。`dwmapi.dll` 的导出集很小，可行；换成
`version.dll`、`winmm.dll` 同理。

### 环境变量

| 变量 | 默认值 | 作用 |
|---|---|---|
| `UE5HOOK_MODULE` | 主模块 | 要扫描的模块名；目标在别的 DLL 里时用 |
| `UE5HOOK_LOG` | DLL 同目录 `ue5hook.log` | 日志路径 |
| `UE5HOOK_LIMIT` | `0`（不限） | 最多记录多少次调用，之后只计数 |

### 日志格式

启动时先写三行头部，记录定位到的地址（RVA 便于跨运行对比）：

```
# ue5hook  module=<exe>  RVA=0x15C6C80  section=.text  via=fallback (...)
  GUObjectArray=0x7FF63BBC4050 (RVA 0x91F4050)  elements=96984  chunks=2
  NamePool.blocks=0x7FF63BAE0550 (RVA 0x9110550)  layout=legacy
  UWorld instances=4
    Default__World  @00007FF431063500
    ...
  most common classes:
     28783  Function
     ...
```

随后是每次调用的记录：

```
seq=1234 tid=5678 params=000001F2... class=000001F2... outer=000001F2... name=0000000A0000002F flags70=00000000 result=000001F2... ret=00007FF6... classname=TextBlock
```

`class` / `outer` / `name` / `flags70` 都是从 `params` 里按偏移读出来的原始值；
`classname` 是**消费线程**用名称池解出来的可读类名，在热路径之外完成，并按类指针做了缓存
（只有约 2,000 个不同的类，所以每个指针只解一次）。

同目录还会生成 `ue5hook.trace`——启动期的阶段面包屑。它和日志分开，是为了在 worker
卡住、日志根本没建起来时仍能定位问题（本次开发中它两次直接指出了卡住的位置）。

## 六、实测踩到的五个坑

网上和专栏第 09 章都这么写卸载：

```cpp
MH_DisableHook(MH_ALL_HOOKS);
MH_RemoveHook(MH_ALL_HOOKS);   // ← 这一行什么也没做
MH_Uninitialize();
```

**`MH_RemoveHook` 不支持 `MH_ALL_HOOKS`。** `MH_EnableHook` 和 `MH_DisableHook` 都有
`pTarget == MH_ALL_HOOKS` 的分支，`MH_RemoveHook` 没有（`third_party/minhook/src/hook.c:677`），
它直接调 `FindHookEntry(pTarget)`，而后者是拿参数和每个 hook 的 `pTarget` 逐项比地址。
`MH_ALL_HOOKS` 就是 `NULL`，于是它去找「target 为 NULL 的 hook」，找不到，返回
`MH_ERROR_NOT_CREATED`。**静默空操作，返回值通常还被忽略。**

后果：整体卸载时基本无害（`MH_Uninitialize` 会 `EnableAllHooksLL(FALSE)` 并释放
trampoline），但「只想摘掉一个 hook、保留 MinHook 初始化」的场景会真的漏。

本项目的写法是传真实地址，自检里还专门断言了这个错误返回值，防止坑再溜回来：

```cpp
if (g_target != nullptr) {
    MH_DisableHook(g_target);
    MH_RemoveHook(g_target);   // 必须传地址
}
MH_Uninitialize();
```

### 坑 2：UE4SS 会覆写函数序言，把特征码本身破坏掉

这个游戏装了 UE4SS（`dwmapi.dll` 代理）。UE4SS 的 `Waiting for object construction...`
就是它 hook `StaticConstructObject_Internal` 之后的等待——**它和我们挂的是同一个函数**。

UE4SS 的 x64 hook 在函数入口写一条 14 字节绝对跳转，正好覆盖本签名的前 14 字节：

```
4C 8B DC 55 53 41 56 49 8D AB 28 FE FF FF   ← 被跳转覆盖，签名失效
```

实测对比：

| 注入时机 | 主签名扫描结果 |
|---|---|
| 进程启动后 0.55 秒 | 找到，RVA `0x15C6C80` |
| 进程启动后 30 秒 | **`signature not found`**，而函数明明就在那里 |

这不是签名写错了，是**别人先动了手**。专栏第 09 章说的「所有结论都要用第二个独立证据
交叉验证」，在这里表现为：晚注入失败时必须先怀疑特征码被覆写，而不是怀疑地址算错。

**解决办法是加一条位移备选签名**：从入口往后 14 字节开始匹配，命中后减掉 14 就是入口。

```
48 81 EC C0 02 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 A0 01 00 00 8B 41 70 33 DB 49 89 73 10
```

已实测在四个 exe 上同样唯一，落在 RVA `0x015C6C8E` = `0x015C6C80 + 14`。现在晚注入的
日志头会写 `via=fallback (entry overwritten by another hook)`。

代价说清楚：这条签名锚在函数体内，所以**如果别人 hook 得更深**（不止 14 字节），它同样
会失效。两条签名覆盖现实中的常见情况，加第三条就是猜了。

### 坑 3：宽字符 `printf` 里 `%s` 期望 `wchar_t*`

日志头一度输出 `section=琮硥t`，而扫描本身没错（RVA 是对的）。原因：

```cpp
_snwprintf_s(header, ..., L"... section=%s", hits[0].section.c_str());  // ← 错
```

`section` 是 `std::string`（窄字符）。宽字符 `printf` 的 `%s` 按 `wchar_t*` 解释，
于是字节 `.text\0` 被读成 UTF-16 码元：`0x742E`='琮'、`0x7865`='硥'、`0x0074`='t'。

正确写法是 `%hs`（MSVC 里表示窄字符串）。`DebugPrint` 那处也犯了同样的错。

### 附：日志文件默认独占，游戏运行时读不到

`_wfopen_s` 默认独占打开，日志在游戏运行期间被锁住——恰好是你最想 tail 它的时候。
改用 `_wfsopen(path, mode, _SH_DENYNO)` 允许共享读。实测现在可以在游戏运行时
`Get-Content` 日志。

### 坑 4：`VirtualQuery` 比想象中贵得多

第一版 `readable()` 每次访问都调 `VirtualQuery`。在这台目标上**单次约 65µs**——进程有 94
个线程、VAD 树很大——而遍历 96,984 个对象每个要 6 次检查，于是光枚举就要 **37 秒**。

改成**一次性快照整个地址空间的可读区**（`ue::buildRegionMap()`，几千次 `VirtualQuery`），
之后每次检查是二分查找。整个发现 + 枚举降到约 350ms。

代价说清楚：快照会过期，发现过程中新映射的内存看不到。对一次性启动扫描这是对的取舍——
对象数组的 chunk 在注入之前早就映射好了。

### 坑 5：暴力扫描 `Blocks` 数组慢了 90 倍

名称池的第一版实现是「遍历 `.data` 的每个 qword，凡是长得像指针的就校验」。逻辑没错，但
**约每 80 字节就有一个像指针的值**，5.4 MB 的 `.data` 意味着约 67,000 次校验，实测要
**约 90 秒**。

换成结构特征后是线性的：先找「几千个连续零 qword」的零串，再往回数非空指针。候选从
67,000 降到个位数，耗时降到毫秒级。

**教训**：一个「看起来对」的算法在 5 MB 输入上可能慢到不可用。而加进度埋点（每 1 MB 打
一行）比盯着代码猜快得多——正是这个埋点让我看出它不是死循环，是慢。

## 七、已验证 / 未验证

### 已验证

**离线与静态：**

- 主签名与位移备选签名在四个 exe 上**都是唯一命中**，RVA 分别是 `0x015C6C80` 与 `0x015C6C8E`
- 命中点前 8 字节是 int3 填充，落点是真实函数入口
- `scan.h` 的扫描逻辑与离线 `aobscan.mjs` 结论一致
- MinHook create / queue-enable / apply / call / disable / remove / uninitialize 全链路
- detour 正确回链到原函数（合成目标上 `42 → 142`）
- `injector.exe` 真实注入：目标不崩、eject 成功、失败面包屑正确落盘
- DLL 只依赖 `KERNEL32.dll`

**真机运行（`CMTEST测卡服.exe`，UE 5.6）：**

- 三方独立确认同一个 RVA：离线 `aobscan.mjs` → `0x015C6C80`；UE4SS 运行时日志
  `StaticConstructObject_Internal address: 0x7ff633f96c80`（模块基址 `0x7FF6329D0000`
  + `0x15C6C80`）；本 DLL 在游戏进程内扫描 → `0x015C6C80`
- 单次运行抓到 **72,423 条**调用记录
- `class` 字段在 **72,423 / 72,423 条里全部非空**，共 **2,360 个不同的类指针**
- `name` 字段 67,037 条非零，形态符合 FName（低位是名称池索引，高位是小整数 Number，
  例如 `0000000100024AD3` 即 Number=1）
- `outer`、`result` 均为合法指针，`ret` 全部落在游戏模块内
- 晚注入（35 秒，UE4SS 已 hook）走位移备选签名成功，RVA 仍是 `0x15C6C80`
- **`GUObjectArray` 发现结果 `0x7FF63BBC4050` 与 UE4SS 日志的 `0x7ff63bbc4050` 完全一致**
- 名称池发现成功，条目 0 解码为 `None`；布局探测判定为 `legacy`（非大小写保留）
- 遍历 96,984 个对象，枚举出 4 个 `UWorld` 实例（含 CDO `Default__World`，以及
  `StartingLevel` / `Login` / `Home` 三个真实地图），并产出合理的类名分布
- 日志中的 `classname=` 输出为真实类名（`Image`、`TextBlock`、`HorizontalBoxSlot`、
  `NotifyTextWidget_C` …）

### 未验证

- **`rcx` 确实是 `&FStaticConstructObjectParameters`：已强证据支持，但仍非逐字节证明。**
  现在证据比之前强得多：`params+0x00` 取出的指针喂给名称池能解出 `Image`、`TextBlock`、
  `HorizontalBoxSlot` 这类真实类名，说明它确实是 `const UClass*`。这是「解出来的东西对」，
  而不是「用调试器确认过结构体声明」。
- **字段偏移 `0x08`（Outer）的语义未直接验证。** `0x00`（Class）和 `0x10`（Name）现在
  都有了解码结果作证，`0x08` 只验证了「是个可读指针」，没验证「是 outer」。
- 极少数记录（约 1/72423）的 `name` 高位出现异常大值，可能是走了不同的调用路径，未追查。
- **`FUObjectArray` 只实现了默认布局。** 专栏列出的另外三种（UE5.8 dev、Back4Blood、
  Multiversus）没有对应分支；校验失败时会报告未找到，而不是按错的布局读下去。

**下一步**：`.usmap`（本例是 UE 5.6 的映射文件）可以确认 `FStaticConstructObjectParameters`
与 `UObject` 的逐字段布局，把上面两条从「形态吻合」升级成「已确认」。另一个方向是把
`GWorld` / `GEngine` 也接上，以及按专栏第 08 章的路径 7 走玩家链
（`UWorld → OwningGameInstance → LocalPlayers[0] → PlayerController`）——那些偏移在
dump 出来的 SDK 里都有，不用扫特征码。

## 八、设计取舍（每条都对应一个会踩的坑）

| 做法 | 不这么做会怎样 |
|---|---|
| `DllMain` 里只 `CreateThread` | loader lock 下做实事：CRT 可能未初始化，阻塞调用可能死锁整个进程 |
| 签名必须唯一命中，否则拒绝 | 命中两处时 hook 到哪个由链接器决定，跨构建是抛硬币 |
| detour 里零 I/O、零锁、零分配 | `StaticConstructObject` 启动期调用数千次，`printf` 会让游戏卡顿 |
| 用 `MH_QueueEnableHook` + `MH_ApplyQueued` | 每次 `MH_EnableHook` 都挂起并恢复所有线程；挂 10 个 hook 就是 10 次全局停顿 |
| 卸载顺序 Disable → Remove → Uninitialize | 顺序错了退出时崩，极易误判成「hook 写错了」 |
| 只在 `reserved == nullptr` 时清理 | 进程退出时在 loader lock 下停线程会挂死 |
| 失败也写日志 | 注入到错误进程时完全无声，和「注入器失败了」无法区分 |

## 九、排查

| 症状 | 先看什么 |
|---|---|
| 日志都没有 | 注入是否成功？`injector.exe` 的返回；换代理 DLL 路线试试 |
| 日志写 `signature not found`（晚注入） | **先怀疑 UE4SS 已 hook 覆写了序言**，而不是签名写错。看日志头有没有 `via=fallback` |
| 日志写 `signature not found`（两条签名都 miss） | 游戏更新了，或注入了错误的进程。用 `aobscan.mjs` 重新扫，对比 RVA |
| 日志写 `signature is not unique` | 特征码太短。把通配符外的字节加长，或加一段第二特征码交叉验证 |
| 一注入就崩 | `UE5HOOK_MODULE` 指错了模块；或 DLL 与目标位数不符（本 DLL 是 x64） |
| 游戏卡顿 | 设 `UE5HOOK_LIMIT`，先抓几千条看形状 |
| 退出时崩 | 卸载顺序；或 hook 还挂着但 DLL 已被卸载 |
| 想边玩边看日志 | 已支持：日志以 `_SH_DENYNO` 打开，游戏运行时可 `Get-Content` |

---

## 许可

`third_party/minhook` 为 BSD 2-Clause，见其 `LICENSE.txt`。其余代码随你处置。
