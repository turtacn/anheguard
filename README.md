# AnheGuard: Enterprise Compliance & Security Subscription Platform

## Project Introduction

AnheGuard (formerly known as "安合盾") is an innovative, cloud-native platform designed to provide enterprises with a flexible, subscription-based suite of security and compliance services. It addresses the growing need for continuous compliance monitoring, expert security consultation, and incident response, particularly for small and medium-sized enterprises (SMEs) that often lack dedicated security teams and substantial security budgets. AnheGuard aims to democratize enterprise-grade security and compliance by offering an accessible, scalable, and cost-effective solution.

## Customer Pain Points and Value Proposition

**Pain Points:**

1.  **Insufficient Continuous Compliance Monitoring and Risk Assessment:** Many enterprises struggle with ad-hoc compliance checks, leading to delayed discovery and remediation of security vulnerabilities and non-compliance issues. Generating comprehensive compliance reports is often a manual, time-consuming process.
2.  **Lack of Professional Security Expertise:** SMEs typically cannot afford to hire full-time, specialized security experts. They resort to external services only during major security incidents, leading to reactive rather than proactive security postures.
3.  **High and Unpredictable Security Investment:** Traditional security solutions involve high upfront costs for hardware, software, and consulting services, making ROI difficult to predict and manage.

**Value Proposition:**

1.  **Continuous Compliance Monitoring:** AnheGuard provides automated baseline checks against industry standards (e.g., ISO 27001, GDPR, PCI-DSS, local regulations like China's Cybersecurity Law and MLPS 2.0). It leverages existing security product logs and configurations to identify vulnerabilities and deviations. Regular, actionable compliance reports (PDF/DOCX) are automatically generated, offering risk alerts and remediation suggestions, empowering clients to track their compliance posture and remediation progress.
2.  **On-Demand Expert Services:** The platform offers flexible access to remote security experts for online consultations, policy evaluation, optimization, and incident response guidance. This includes proactive advice and urgent support for critical incidents (e.g., ransomware outbreaks), providing peace of mind without the overhead of a full-time security team. Services can be consumed on a "whitelist time" (pre-paid hourly/monthly) or "pay-per-use" basis.
3.  **Flexible Subscription Model:** AnheGuard offers tiered subscription plans (Basic, Standard, Premium) covering a spectrum of services from cloud-based security device management and compliance monitoring to threat intelligence and expert support. This model allows customers to adjust their subscription level based on business growth and evolving needs, with transparent monthly/annual billing and real-time cost adjustments.

## Key Functional Features

*   **Automated Compliance Scanning & Reporting:**
    *   Automated checks of operating systems, network devices, and security appliances against various compliance benchmarks.
    *   Monthly generation of compliance reports in PDF/DOCX format, adhering to standards like MLPS 2.0 and GDPR.
*   **Real-time Risk Alerting & Monitoring:**
    *   Continuous collection and analysis of security logs and events.
    *   Rule-based and behavioral anomaly detection (e.g., brute-force attacks, lateral movement, data exfiltration).
    *   Multi-dimensional risk trend dashboards and instant notifications via email, SMS, or mobile push.
*   **On-Demand Remote Expert Services:**
    *   Integrated IM chat for submitting security requests (policy optimization, incident response, patching).
    *   Secure remote desktop/VNC tunnel for expert assistance with transparent operation logging.
    *   SLA-driven expert scheduling with options for urgent response and flexible billing for exceeding pre-allocated hours.
*   **Flexible Billing & Value-added Services:**
    *   Self-service subscription management, including plan upgrades/downgrades and online renewals.
    *   Optional add-on services: Threat Intelligence subscriptions, deep penetration testing, compliance training.
*   **Multi-tenant Architecture & Cloud Deployment:**
    *   Data, configuration, and policies are completely isolated between enterprise clients.
    *   Deployable on public, private, or hybrid cloud environments with elastic scalability and high availability.
*   **Comprehensive Data Collection:**
    *   Lightweight agents for real-time log collection (OS, security devices, applications) with TLS encryption and offline caching.
    *   Integration with open-source scanning engines like OpenSCAP and Lynis.
*   **Intuitive User Interface & Role-Based Access Control:**
    *   Hierarchical roles (e.g., Enterprise Admin, Security Lead, IT Ops, Compliance Auditor) with fine-grained permissions.
    *   Centralized dashboard displaying risk trends, compliance progress, expert service usage, and billing history.

## Architecture Overview

AnheGuard adopts a modular, multi-layered architecture designed for scalability, reliability, and security. It leverages distributed components for compliance scanning, real-time monitoring, and expert service delivery. The core backend services are built with Go, ensuring high performance and efficient resource utilization. Data storage is primarily handled by Elasticsearch for logs and scan results, and PostgreSQL for metadata and configuration. The platform integrates with various communication channels for alerting and expert interaction.

For a detailed architecture blueprint, please refer to: [docs/architecture.md](docs/architecture.md)

## Building and Running

(Placeholder for future detailed instructions)

To build and run AnheGuard, you will need Go 1.20.2+ installed.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/turtacn/anheguard.git
    cd anheguard
    ```
2.  **Build the backend server:**
    ```bash
    go build -o bin/anheguard-server cmd/anheguard-server/main.go
    ```
3.  **Build the agent:**
    ```bash
    go build -o bin/anheguard-agent cmd/anheguard-agent/main.go
    ```
4.  **Configuration:**
    Configure the `config.yaml` file located in `configs/` directory.
5.  **Run:**
    ```bash
    ./bin/anheguard-server
    ```
    For production deployments, consider using Docker/Kubernetes for containerization and orchestration.

## Contribution Guide

We welcome contributions from the community! If you're interested in contributing, please refer to our `CONTRIBUTING.md` (to be created) for guidelines on setting up your development environment, submitting pull requests, and coding standards.