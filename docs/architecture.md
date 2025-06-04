## 安合盾（AnheGuard）项目总体架构设计

### 1. 引言

“安合盾（AnheGuard）”是一个弹性安全与合规订阅服务平台，旨在为企业客户提供一站式的安全与合规咨询、监控及专家服务。本架构设计文档将详细阐述项目的整体设计、核心模块、数据流、部署模式以及代码实现蓝图，以指导后续的开发工作，确保项目的高质量、可扩展性和可维护性。

### 2. 核心架构原则

在设计 AnheGuard 项目时，我们遵循以下核心原则，以确保其先进性、健壮性与易于维护性：

1.  **分层与模块化设计（Layered & Modular Design）**：
    *   采用清晰的多层架构，例如展现层（Presentation Layer）、应用层（Application Layer）、领域层（Domain Layer）和基础设施层（Infrastructure Layer）。
    *   设计灵活的“胶水逻辑”或适配器层，确保各组件（模块）易于独立开发、测试、接入和替换。
    *   模块间应保持高内聚、低耦合，通过清晰的接口进行通信。
2.  **借鉴与创新（Leverage & Innovate）**：
    *   充分吸收并整合如 OpenSCAP、Wazuh、TheHive、Grafana 等开源项目中的实用特性和优秀设计思想。
    *   在此基础上进行优化和创新，使项目的组织更合理、功能更强大，特别是在多租户、弹性订阅和专家服务集成方面。
3.  **端到端价值导向（End-to-End Value Driven）**：
    *   优先通过清晰的技术语言（如接口定义、核心数据结构、交互流程）来明确和阐述整体需求，确保设计能够直接映射到最终用户价值和预期效果。
4.  **可测试性（Testability）**：
    *   架构设计应高度关注可测试性，确保各模块及整体系统易于进行单元测试、集成测试和端到端测试。
5.  **可观测性（Observability）**：
    *   内建日志（Logs）、指标（Metrics）和追踪（Tracing）机制，提供统一的日志对象（Logger）。这将帮助开发人员和运维人员实时监控系统行为、诊断问题并优化性能。
6.  **可靠性与容错性（Reliability & Fault Tolerance）**：
    *   考虑全面的错误处理机制，集中定义错误类型和常量。
    *   关键服务节点采用双活或多活模式，保证服务的高可用性。
7.  **高性能与可伸缩性（High Performance & Scalability）**：
    *   架构应支持水平扩展，尤其是合规扫描和安全监控模块，以处理大规模任务并发。
    *   优化数据处理和存储，确保系统在高负载下的响应速度。
8.  **安全性（Security）**：
    *   从设计之初就考虑安全因素，遵循安全编码规范，如输入验证、身份认证、授权机制、数据加密（如 TLS 加密通信）。
    *   采用多租户隔离，确保客户数据安全。
9.  **代码质量与可维护性（Code Quality & Maintainability）**：
    *   遵循 Clean Code 原则，确保代码清晰、易懂、易维护。
    *   集中定义可枚举类型，提高代码可读性和一致性。

### 3. 项目总体架构（Overall Architecture）

AnheGuard 采用微服务与模块化相结合的架构风格，部署在云端，支持多租户。核心功能围绕“合规扫描”、“安全监控”、“专家服务”和“订阅管理”四大业务模块展开。

#### 3.1 架构总览图（Architecture Overview Diagram）

```mermaid
graph TD
    %% 架构总览图
    subgraph PZ[展现层（Presentation Layer）]
        UI[用户界面（User Interface）]
    end

    subgraph FW[应用层（Application Layer）]
        API_GW[API 网关（API Gateway）] --> AU[认证授权服务（Auth & Authz Service）]
        AU --> BL[业务逻辑服务（Business Logic Service）]
        BL --> CS[合规扫描服务（Compliance Scan Service）]
        BL --> SM[安全监控服务（Security Monitoring Service）]
        BL --> ES[专家服务（Expert Service）]
        BL --> SS[订阅管理服务（Subscription Service）]
    end

    subgraph DC[数据采集层（Data Collection Layer）]
        AGT[Agent/探测器（Agent/Probes）] --> CA[采集器（Collector）]
        CA --> SIEM_ETL[SIEM 数据处理（SIEM ETL）]
    end

    subgraph IS[基础设施层（Infrastructure Layer）]
        DB[关系型数据库（Relational DB）<br/>PostgreSQL]
        ES_CL[非关系型数据库（NoSQL DB）<br/>Elasticsearch Cluster]
        MQ[消息队列（Message Queue）<br/>Kafka/RabbitMQ]
        OBS[对象存储（Object Storage）<br/>S3-compatible]
    end

    subgraph TH[第三方集成（Third-party Integrations）]
        EXT_CI[外部情报源（External Threat Intelligence）]
        EXT_ITS[外部ITSM/工单系统（External ITSM）]
        EXT_NTF[外部通知服务（External Notification）]
    end

    UI --> API_GW
    API_GW --> BL
    AGT --> CA
    CA --> MQ
    MQ --> SIEM_ETL
    SIEM_ETL --> ES_CL
    BL --> DB
    BL --> ES_CL
    BL --> MQ
    BL --> OBS
    BL --> EXT_CI
    BL --> EXT_ITS
    BL --> EXT_NTF
    ES --> EXT_ITS
    ES --> EXT_NTF
````

上图展示了AnheGuard的整体架构，分为展现层、应用层、数据采集层和基础设施层。用户通过展现层与API网关交互，业务逻辑服务处理核心业务，并与合规扫描、安全监控、专家服务和订阅管理等子服务进行通信。Agent负责数据采集，并通过消息队列将数据送入SIEM进行处理和存储。所有服务都依赖于统一的基础设施层，并与第三方系统集成。

#### 3.2 核心模块（Core Modules）

1. **展现层（Presentation Layer）**：

   * **用户界面（User Interface）**：为企业客户和AnheGuard运营人员提供统一的Web控制台，用于订阅管理、合规报告查看、风险仪表盘、专家服务请求等。
2. **应用层（Application Layer）**：

   * **API 网关（API Gateway）**：作为所有外部请求的统一入口，负责请求路由、负载均衡、认证和限流等。
   * **认证授权服务（Auth & Authorization Service）**：负责用户身份认证（如OAuth2/JWT）、权限管理（RBAC），确保多租户环境下的数据隔离和访问安全。
   * **业务逻辑服务（Business Logic Service）**：协调各子服务，处理高层次的业务流程，如订阅流程、专家服务调度、报告生成调度等。
   * **合规扫描服务（Compliance Scan Service）**：

     * **扫描引擎（Scanner Engine）**：基于 OpenSCAP \[1]、Lynis \[2] 或自研模块，对资产（OS、网络设备、安全设备）进行基线合规检查和漏洞扫描。
     * **报告生成器（Reporter）**：将扫描结果汇总，生成符合等保 2.0、GDPR 等标准的合规报告（PDF/DOCX）。
   * **安全监控服务（Security Monitoring Service）**：

     * **数据分析器（Analyzer）**：实时处理 SIEM 数据，应用规则引擎和行为分析模型，检测异常和安全事件。
     * **告警管理器（Alert Manager）**：根据风险评分和阈值触发告警，并通过多种渠道通知相关人员。
   * **专家服务（Expert Service）**：

     * **工单系统（Ticketing System）**：管理客户提交的专家服务请求，支持工单的创建、分配、流转和状态更新。可借鉴 Zammad \[3] 或 Redmine \[4] 的设计思想。
     * **排班系统（Scheduler）**：管理专家资源，根据 SLA（Service Level Agreement）和事件优先级智能调度专家。
     * **远程协作模块（Remote Collaboration）**：提供安全的远程桌面/VNC隧道服务，记录专家操作日志，确保透明合规。
   * **订阅管理服务（Subscription Service）**：

     * **计划管理（Plan Management）**：定义和管理不同等级的订阅套餐、服务清单和定价策略。
     * **计费系统（Billing System）**：根据订阅计划和实际服务消耗（如专家服务时长）进行计费。
     * **发票管理（Invoicing）**：生成、管理和查询电子发票。
3. **数据采集层（Data Collection Layer）**：

   * **Agent/探测器（Agent/Probes）**：轻量级客户端程序，部署在客户的服务器、网络设备或终端上，实时收集日志、配置信息和系统状态。可借鉴 Wazuh Agent \[5] 和 osquery \[6] 的设计。
   * **采集器（Collector）**：接收来自 Agent 的数据，进行初步清洗和格式转换，然后将其发送到消息队列。
4. **基础设施层（Infrastructure Layer）**：

   * **关系型数据库（Relational Database）**：PostgreSQL，用于存储用户账户、订阅信息、服务配置、元数据、工单信息和审计日志等结构化数据。
   * **非关系型数据库（NoSQL Database）**：Elasticsearch 集群，用于存储海量的安全日志、扫描结果和风险事件，支持快速检索和聚合分析。可借鉴 Security Onion \[7] 的 ELK Stack 应用。
   * **消息队列（Message Queue）**：Kafka 或 RabbitMQ，用于异步通信、解耦服务、削峰填谷，确保数据传输的可靠性和可伸缩性。
   * **对象存储（Object Storage）**：兼容 S3 协议的存储，用于存储生成的合规报告、大文件日志、备份等。
5. **第三方集成（Third-party Integrations）**：

   * **外部情报源（External Threat Intelligence）**：如 CVE 数据库（Common Vulnerabilities and Exposures）、NVD（National Vulnerability Database）等，用于丰富风险评估的上下文。
   * **外部 ITSM/工单系统（External ITSM）**：如 Jira、ServiceNow，支持与客户现有 IT 服务管理系统的集成，实现工单的自动同步和流转。
   * **外部通知服务（External Notification）**：邮件（SMTP）、短信网关、企业微信、钉钉等，用于告警和通知推送。
   * **可视化工具（Visualization Tools）**：Grafana \[8] 可用于构建丰富的风险仪表盘和合规趋势图。

#### 3.3 部署示意图（Deployment Diagram）

```mermaid
graph TD
    %% 部署示意图
    subgraph CLD[云服务提供商（Cloud Provider）]
        subgraph REGION_A[区域 A（Region A）]
            subgraph K8S_CLT_A[Kubernetes 集群 A（Kubernetes Cluster A）]
                LB_A[负载均衡器（Load Balancer）] --> API_GW_PODS_A[API 网关 Pods A（API Gateway Pods A）]
                API_GW_PODS_A --> SVC_PODS_A[业务服务 Pods A（Service Pods A）<br/>合规扫描、监控、专家、订阅]
                SVC_PODS_A --> DB_A[关系型数据库主节点（Relational DB Master Node）]
                SVC_PODS_A --> ES_CL_A[Elasticsearch 集群节点 A（ES Cluster Node A）]
                SVC_PODS_A --> MQ_BR_A[消息队列 Broker A（MQ Broker A）]
            end
        end

        subgraph REGION_B[区域 B（Region B）]
            subgraph K8S_CLT_B[Kubernetes 集群 B（Kubernetes Cluster B）]
                LB_B[负载均衡器（Load Balancer）] --> API_GW_PODS_B[API 网关 Pods B（API Gateway Pods B）]
                API_GW_PODS_B --> SVC_PODS_B[业务服务 Pods B（Service Pods B）<br/>合规扫描、监控、专家、订阅]
                SVC_PODS_B --> DB_B[关系型数据库从节点（Relational DB Slave Node）]
                SVC_PODS_B --> ES_CL_B[Elasticsearch 集群节点 B（ES Cluster Node B）]
                SVC_PODS_B --> MQ_BR_B[消息队列 Broker B（MQ Broker B）]
            end
        end

        DB_A <--> DB_B 
        %% 数据同步（Data Sync）
        ES_CL_A <--> ES_CL_B 
        %% 数据同步（Data Sync）
        MQ_BR_A <--> MQ_BR_B 
        %% 消息同步（Message Sync）
    end

    subgraph CUST_DC[企业客户数据中心/环境（Customer Data Center/Environment）]
        AGT_INST[Agent 实例（Agent Instances）<br/>部署在客户资产上] --> FW_CUST[客户防火墙（Customer Firewall）]
        FW_CUST --> LB_A
        FW_CUST --> LB_B
    end

    USR[用户（User）] --> LB_A
    USR --> LB_B
    OPS_TS[运维工具/第三方系统（Ops Tools/Third-party Systems）] --> API_GW_PODS_A
    OPS_TS --> API_GW_PODS_B
```

上图描绘了AnheGuard在高可用性下的多区域部署策略。核心服务部署在两个独立的Kubernetes集群（区域A和区域B）中，通过负载均衡器对外提供服务。关系型数据库、Elasticsearch和消息队列也进行跨区域的数据同步，实现双活或多活模式。客户环境中的Agent通过防火墙安全地连接到云平台，而用户和运维工具则直接访问负载均衡器。

### 4. 核心数据结构与接口定义

以下是 AnheGuard 项目中部分核心数据结构和接口的初步设计，它们将定义模块间的契约。

#### 4.1 数据结构示例（Data Structure Examples）

```go
// internal/compliance/types/scan_result.go
// ComplianceScanResult represents the result of a compliance scan for a specific asset.
// 合规扫描结果：表示针对特定资产的合规扫描结果。
type ComplianceScanResult struct {
    ID          string    `json:"id"`           // Unique identifier for the scan result / 扫描结果唯一标识符
    AssetID     string    `json:"asset_id"`     // ID of the asset being scanned / 被扫描资产的ID
    StandardID  string    `json:"standard_id"`  // Compliance standard ID (e.g., "MLPS2.0", "GDPR") / 合规标准ID（例如：“等保2.0”，“GDPR”）
    ScanTime    time.Time `json:"scan_time"`    // Timestamp of when the scan was performed / 扫描执行时间戳
    Status      string    `json:"status"`       // Overall status of the scan (e.g., "completed", "failed", "in_progress") / 扫描的总体状态（例如：“已完成”，“失败”，“进行中”）
    Score       float64   `json:"score"`        // Compliance score (e.g., 0-100) / 合规评分（例如：0-100）
    ReportLink  string    `json:"report_link"`  // Link to the generated detailed report (PDF/DOCX) / 生成的详细报告链接（PDF/DOCX）
    Details     string    `json:"details"`      // A summary of the scan findings / 扫描结果摘要
    Issues      []ScanIssue `json:"issues"`     // List of specific compliance issues found / 发现的特定合规问题列表
}

// internal/compliance/types/scan_issue.go
// ScanIssue represents a specific compliance issue identified during a scan.
// 扫描问题：表示在扫描过程中发现的特定合规问题。
type ScanIssue struct {
    ID              string `json:"id"`               // Unique identifier for the issue / 问题的唯一标识符
    RuleID          string `json:"rule_id"`          // ID of the compliance rule violated / 违反的合规规则ID
    Description     string `json:"description"`      // Detailed description of the issue / 问题的详细描述
    Severity        string `json:"severity"`         // Severity level (e.g., "Critical", "High", "Medium", "Low") / 严重等级（例如：“关键”，“高”，“中”，“低”）
    Remediation     string `json:"remediation"`      // Suggested steps for remediation / 建议的补救措施
    Status          string `json:"status"`           // Status of the issue (e.g., "open", "fixed", "ignored") / 问题的状态（例如：“开放”，“已修复”，“已忽略”）
    DetectedValue   string `json:"detected_value"`   // The actual configuration/value detected / 检测到的实际配置/值
    ExpectedValue   string `json:"expected_value"`   // The expected compliant configuration/value / 预期的合规配置/值
    Reference       string `json:"reference"`        // Reference to relevant standard section or CVE / 相关标准章节或CVE的引用
}

// internal/expert/types/service_request.go
// ServiceRequest represents a customer's request for expert service.
// 服务请求：表示客户提交的专家服务请求。
type ServiceRequest struct {
    ID          string    `json:"id"`           // Unique identifier for the service request / 服务请求唯一标识符
    CustomerID  string    `json:"customer_id"`  // ID of the customer who made the request / 发起请求的客户ID
    RequestType string    `json:"request_type"` // Type of request (e.g., "PolicyOptimization", "IncidentResponse") / 请求类型（例如：“策略优化”，“事件响应”）
    Title       string    `json:"title"`        // Title of the request / 请求标题
    Description string    `json:"description"`  // Detailed description of the request / 请求的详细描述
    Status      string    `json:"status"`       // Current status (e.g., "pending", "assigned", "in_progress", "resolved") / 当前状态（例如：“待处理”，“已分配”，“进行中”，“已解决”）
    Priority    string    `json:"priority"`     // Priority level (e.g., "Urgent", "High", "Normal", "Low") / 优先级（例如：“紧急”，“高”，“普通”，“低”）
    AssignedExpert string `json:"assigned_expert"` // ID of the expert assigned to this request / 分配给此请求的专家ID
    CreatedAt   time.Time `json:"created_at"`   // Timestamp of when the request was created / 请求创建时间戳
    ResolvedAt  *time.Time `json:"resolved_at"` // Timestamp of when the request was resolved / 请求解决时间戳
    Attachments []string  `json:"attachments"`  // List of attachment links / 附件链接列表
    Messages    []Message `json:"messages"`     // Communication messages related to this request / 与此请求相关的通信消息
}

// internal/expert/types/message.go
// Message represents a message exchanged within a service request.
// 消息：表示服务请求中交换的消息。
type Message struct {
    SenderID    string    `json:"sender_id"`    // ID of the sender (customer or expert) / 发送者ID（客户或专家）
    SenderRole  string    `json:"sender_role"`  // Role of the sender (e.g., "customer", "expert") / 发送者角色（例如：“客户”，“专家”）
    Content     string    `json:"content"`      // Content of the message / 消息内容
    Timestamp   time.Time `json:"timestamp"`    // Timestamp of the message / 消息时间戳
}
```

#### 4.2 接口定义示例（Interface Definition Examples）

```go
// internal/pkg/notification/notifier.go
// Notifier defines the interface for sending various types of notifications.
// 通知接口：定义了发送各种类型通知的接口。
type Notifier interface {
    // SendEmailNotification sends an email notification to the specified recipient.
    // 发送邮件通知：向指定收件人发送邮件通知。
    SendEmailNotification(to string, subject string, body string) error

    // SendSMSNotification sends an SMS notification to the specified phone number.
    // 发送短信通知：向指定手机号发送短信通知。
    SendSMSNotification(phoneNumber string, message string) error

    // SendMobilePushNotification sends a push notification to a mobile device.
    // 发送移动推送通知：向移动设备发送推送通知。
    SendMobilePushNotification(userID string, title string, body string, payload map[string]interface{}) error

    // SendEnterpriseWeChatNotification sends a notification via Enterprise WeChat.
    // 发送企业微信通知：通过企业微信发送通知。
    SendEnterpriseWeChatNotification(agentID int, toUsers []string, toParties []string, message string) error
    // ... potentially other notification methods
}

// internal/compliance/scanner/scanner.go
// Scanner defines the interface for compliance scanning engines.
// 扫描器接口：定义了合规扫描引擎的接口。
type Scanner interface {
    // ScanAsset performs a compliance scan on a given asset with specific standards.
    // 扫描资产：根据特定合规标准对给定资产执行合规扫描。
    ScanAsset(assetID string, standards []string, config map[string]string) (*ComplianceScanResult, error)

    // GetSupportedStandards returns a list of compliance standards supported by the scanner.
    // 获取支持的标准：返回扫描器支持的合规标准列表。
    GetSupportedStandards() ([]string, error)

    // GetScanProgress returns the current progress of a running scan.
    // 获取扫描进度：返回正在运行扫描的当前进度。
    GetScanProgress(scanID string) (float64, string, error)
}
```

### 5. 日志与错误处理机制

* **日志管理（Logging Management）**：

  * 统一使用 `internal/core/logger/` 模块提供的接口进行日志记录。
  * 支持多级别日志（DEBUG, INFO, WARN, ERROR, FATAL）和结构化日志输出（JSON格式）。
  * 可配置日志输出目标（控制台、文件、远程日志服务如 Elasticsearch）。
  * 日志上下文（Trace ID、Span ID）的传递，方便分布式追踪。
* **错误处理（Error Handling）**：

  * 所有业务错误将集中在 `internal/core/errors/` 模块中定义，采用自定义错误类型（例如：`ErrNotFound`、`ErrInvalidParameter`、`ErrPermissionDenied` 等）。
  * 错误码（Error Code）和错误消息（Error Message）的统一管理，便于前端国际化和后端问题定位。
  * 错误栈追踪，方便调试。在对外暴露错误时，应转换成通用错误格式，避免泄露内部实现细节。

### 6. 项目目录结构规划与文件生成蓝图

AnheGuard 项目将遵循标准的 Golang 项目结构，并进行模块化细分，以确保清晰的职责划分和良好的可维护性。

```bash
anheguard/
├── cmd/                           # 应用程序启动入口（Application Entrypoints）
│   ├── anheguard-server/          # 后端服务启动入口（Backend Server Entrypoint）
│   │   └── main.go                # 服务器主函数（Server main function）
│   └── anheguard-agent/           # Agent 启动入口（Agent Entrypoint）
│       └── main.go                # Agent 主函数（Agent main function）
├── configs/                       # 配置文件（Configuration Files）
│   ├── server.yaml                # 服务器配置（Server configuration）
│   └── agent.yaml                 # Agent 配置（Agent configuration）
├── internal/                      # 内部实现，私有应用程序代码（Internal Application Code, Private to this project）
│   ├── adapter/                   # 适配器层，处理外部系统集成（Adapter Layer, Handles external system integrations）
│   │   ├── notification/          # 通知服务适配器（Notification service adapters）
│   │   │   ├── email/             # 邮件通知适配器（Email notification adapter）
│   │   │   │   └── smtp_adapter.go
│   │   │   ├── sms/               # 短信通知适配器（SMS notification adapter）
│   │   │   │   └── twilio_adapter.go # Example: Twilio
│   │   │   └── wechat/            # 企业微信通知适配器（Enterprise WeChat notification adapter）
│   │   │       └── wechat_work_adapter.go
│   │   ├── storage/               # 存储适配器（Storage adapters）
│   │   │   ├── postgres/          # PostgreSQL 适配器（PostgreSQL adapter）
│   │   │   │   └── postgres_client.go
│   │   │   ├── elasticsearch/     # Elasticsearch 适配器（Elasticsearch adapter）
│   │   │   │   └── es_client.go
│   │   │   └── s3/                # S3 兼容对象存储适配器（S3 compatible object storage adapter）
│   │   │       └── s3_client.go
│   │   └── thirdparty/            # 第三方服务适配器（Third-party service adapters）
│   │       ├── itsm/              # ITSM 系统适配器（ITSM system adapter）
│   │       │   └── jira_adapter.go # Example: Jira
│   │       └── threatintel/       # 威胁情报适配器（Threat intelligence adapter）
│   │           └── cve_nvd_adapter.go
│   ├── app/                       # 应用程序服务层（Application Service Layer）
│   │   ├── api/                   # API 接口定义和处理（API interface definition and handling）
│   │   │   ├── http/              # HTTP API 服务（HTTP API service）
│   │   │   │   ├── router.go      # 路由配置（Router configuration）
│   │   │   │   ├── middleware.go  # 中间件（Middleware）
│   │   │   │   └── v1/            # API 版本 v1（API version v1）
│   │   │   │       ├── auth_handler.go
│   │   │   │       ├── compliance_handler.go
│   │   │   │       ├── monitoring_handler.go
│   │   │   │       ├── expert_handler.go
│   │   │   │       └── subscription_handler.go
│   │   │   └── grpc/              # gRPC API 服务（gRPC API service）
│   │   │       └── server.go
│   │   ├── service/               # 业务逻辑服务（Business Logic Services）
│   │   │   ├── auth/              # 认证授权服务（Auth & Authorization Service）
│   │   │   │   └── auth_service.go
│   │   │   ├── compliance/        # 合规服务（Compliance Service）
│   │   │   │   └── compliance_service.go
│   │   │   ├── monitoring/        # 监控服务（Monitoring Service）
│   │   │   │   └── monitoring_service.go
│   │   │   ├── expert/            # 专家服务（Expert Service）
│   │   │   │   └── expert_service.go
│   │   │   └── subscription/      # 订阅服务（Subscription Service）
│   │   │       └── subscription_service.go
│   │   └── worker/                # 后台工作者/消费者（Background Workers/Consumers）
│   │       ├── task_scheduler.go  # 任务调度器（Task scheduler）
│   │       └── event_consumer.go  # 事件消费者（Event consumer）
│   ├── core/                      # 核心通用模块（Core Common Modules）
│   │   ├── config/                # 配置管理（Configuration Management）
│   │   │   └── config.go          # 配置加载与解析（Config loading and parsing）
│   │   ├── logger/                # 日志管理（Logging Management）
│   │   │   ├── logger.go          # 日志接口与实现（Logger interface and implementation）
│   │   │   └── zap_logger.go      # Zap 日志库实现（Zap logger library implementation）
│   │   ├── errors/                # 错误处理（Error Handling）
│   │   │   └── errors.go          # 集中错误定义（Centralized error definitions）
│   │   ├── constants/             # 常量定义（Constants Definitions）
│   │   │   └── constants.go       # 全局常量（Global constants）
│   │   ├── enums/                 # 枚举类型（Enum Types）
│   │   │   └── enums.go           # 全局枚举类型（Global enum types）
│   │   ├── types/                 # 基础类型定义（Base Type Definitions）
│   │   │   └── common.go          # 通用类型（Common types）
│   │   └── utils/                 # 工具函数（Utility Functions）
│   │       └── utils.go           # 常用工具函数（Common utility functions）
│   ├── domain/                    # 领域层（Domain Layer）
│   │   ├── model/                 # 领域模型（Domain Models）
│   │   │   ├── asset.go           # 资产模型（Asset model）
│   │   │   ├── compliance.go      # 合规模型（Compliance model）
│   │   │   ├── incident.go        # 事件模型（Incident model）
│   │   │   ├── user.go            # 用户模型（User model）
│   │   │   └── subscription.go    # 订阅模型（Subscription model）
│   │   ├── repository/            # 仓储接口（Repository Interfaces）
│   │   │   ├── asset_repo.go
│   │   │   ├── compliance_repo.go
│   │   │   ├── incident_repo.go
│   │   │   ├── user_repo.go
│   │   │   └── subscription_repo.go
│   │   └── service/               # 领域服务（Domain Services）
│   │       ├── compliance_domain_service.go
│   │       └── expert_domain_service.go
│   └── agent/                     # Agent 内部实现（Agent Internal Implementation）
│       ├── collector/             # 数据采集模块（Data Collection Module）
│       │   ├── os_collector.go    # 操作系统数据采集器（OS data collector）
│       │   ├── log_collector.go   # 日志采集器（Log collector）
│       │   └── network_collector.go # 网络数据采集器（Network data collector）
│       ├── transporter/           # 数据传输模块（Data Transport Module）
│       │   └── transporter.go     # 数据传输逻辑（Data transport logic）
│       └── processor/             # Agent 端数据预处理（Agent-side Data Preprocessing）
│           └── processor.go
├── pkg/                           # 公共库，可被其他项目引用（Public Library, can be imported by other projects）
│   ├── api/                       # API 定义，如 Protobuf 文件（API definitions, e.g., Protobuf files）
│   │   └── anheguard.proto
│   ├── storage/                   # 存储通用接口和类型（Generic storage interfaces and types）
│   │   └── interface.go
│   └── notification/              # 通知通用接口和类型（Generic notification interfaces and types）
│       └── interface.go
├── scripts/                       # 脚本工具（Scripting Tools）
│   ├── migrations/                # 数据库迁移脚本（Database migration scripts）
│   │   └── 001_initial_schema.up.sql
│   │   └── 001_initial_schema.down.sql
│   └── setup/                     # 环境搭建脚本（Environment setup scripts）
│       └── setup_dev_env.sh
├── test/                          # 集成测试和端到端测试（Integration and End-to-End Tests）
│   └── e2e/
│       └── smoke_test.go
├── go.mod                         # Go 模块定义（Go module definition）
├── go.sum                         # Go 模块校验和（Go module checksums）
└── README.md                      # 项目说明（Project README）
└── CONTRIBUTING.md                # 贡献指南（Contribution Guide）
```

### 7. 参考资料（References）

1. OpenSCAP: [https://www.open-scap.org/](https://www.open-scap.org/)
2. Lynis: [https://github.com/CISOfy/lynis](https://github.com/CISOfy/lynis)
3. Zammad: [https://github.com/zammad/zammad](https://github.com/zammad/zammad)
4. Redmine: [https://github.com/redmine/redmine](https://github.com/redmine/redmine)
5. Wazuh: [https://github.com/wazuh/wazuh](https://github.com/wazuh/wazuh)
6. osquery: [https://github.com/osquery/osquery](https://github.com/osquery/osquery)
7. Security Onion: [https://github.com/Security-Onion-Solutions/security-onion](https://github.com/Security-Onion-Solutions/security-onion)
8. Grafana: [https://grafana.com/](https://grafana.com/)