# Rust CPG Generator 输出格式文档

## 1. 概述

本项目生成的 CPG (Code Property Graph) 采用标准的 JSON 格式输出。该格式包含图的两个核心组成部分：**节点 (Nodes)** 和 **边 (Edges)**。这种格式旨在易于序列化、传输以及被其他图数据库（如 Neo4j）或分析工具加载。

输出的根对象是一个包含 `nodes` 和 `edges` 数组的 JSON 对象。

## 2. JSON 结构总览

```json
{
  "nodes": [
    {
      "label": "METHOD",
      "id": 100,
      "name": "main",
      ...
    },
    ...
  ],
  "edges": [
    {
      "src": 100,
      "dst": 101,
      "label": "AST",
      "properties": {}
    },
    ...
  ]
}
```

## 3. 节点 (Nodes) 定义

每个节点都有一个 `label` 字段用于区分类型，以及一个唯一的 `id`。以下是所有支持的节点类型及其属性说明：

### 3.1 核心代码结构

| 节点类型 (Label) | 描述 | 关键属性 |
| :--- | :--- | :--- |
| **METHOD** | 函数或方法定义 | `name`, `signature`, `filename`, `is_external` |
| **METHOD_PARAMETER_IN** | 函数输入参数 | `name`, `type_full_name`, `order` |
| **METHOD_RETURN** | 函数返回点 | `type_full_name` |
| **TYPE_DECL** | 类型声明 (Struct/Enum) | `name`, `full_name`, `filename` |
| **MEMBER** | 类型成员 (字段) | `name`, `type_full_name` |

### 3.2 语句与表达式

| 节点类型 (Label) | 描述 | 关键属性 |
| :--- | :--- | :--- |
| **BLOCK** | 代码块 `{ ... }` | `is_unsafe` (是否 unsafe 块), `is_cleanup` |
| **CALL** | 函数调用 | `method_full_name`, `dispatch_type`, `is_ffi` |
| **LOCAL** | 局部变量声明 | `name`, `type_full_name` |
| **CONTROL_STRUCTURE** | 控制流结构 (if/loop) | `control_structure_type` (IF, WHILE...) |
| **RETURN** | Return 语句 | `code` |
| **LITERAL** | 字面量值 | `type_full_name`, `code` |
| **IDENTIFIER** | 标识符引用 | `name`, `type_full_name` |
| **UNKNOWN** | 未知/未解析节点 | `parser_type_name` |

## 4. 边 (Edges) 定义

边表示节点之间的关系。

- **src**: 源节点 ID (`i64`)
- **dst**: 目标节点 ID (`i64`)
- **label**: 关系类型 (`String`)
- **properties**: 边的属性 (`Map`)

### 常见边类型 (Label)

- **AST**: 抽象语法树层级关系 (包含关系)
- **CFG**: 控制流图关系 (执行顺序)
- **CFG_UNWIND**: 异常控制流关系 (如 Panic, Drop 清理路径)
- **CALL**: 调用边 (从 Call 节点指向被调用的 Method 节点)
- **ARGUMENT**: 参数边 (连接 Call 节点与其参数/操作数)
- **DDG**: 数据依赖图 (Data Dependency Graph, 连接定义与使用)

## 5. Rust 特有扩展字段

为了更好地支持 Rust 语言特性，我们在标准 CPG 基础上增加了以下字段：

- **BLOCK 节点**:
    - `is_unsafe`: 标记该块是否为 `unsafe { ... }` 块。
    - `is_cleanup`: 标记该块是否涉及清理逻辑 (Drop)。
- **CALL 节点**:
    - `is_ffi`: 标记该调用是否为外部函数接口 (FFI) 调用。
    - `dispatch_type`: 标记调用类型 (`STATIC_DISPATCH`, `DYNAMIC_DISPATCH`).

## 6. 使用示例

如果您需要解析此 JSON：
1. 读取 `nodes` 数组，根据 `id` 建立索引。
2. 读取 `edges` 数组，根据 `src` 和 `dst` ID 将节点连接起来。
3. 根据 `label` 字段处理不同类型的节点逻辑。

详细的 Schema 定义可参考同目录下的 `cpg_schema.json` 文件。
