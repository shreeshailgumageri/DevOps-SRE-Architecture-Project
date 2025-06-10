# DevOps / SRE Engineer Blueprint

A reference implementation designed for high-impact DevOps / Site Reliability Engineers (SREs) working on Identity and Access Management platforms. 
This repository demonstrates 

## 📚 Architectural Docs

- [CI/CD Best Practices](docs/Architectural-Docs/01_CICD_BEST_PRACTICES.md)
https://github.com/shreeshailgumgeri/DevOps-SRE-Architecture-Project/blob/main/docs/Architectural-Docs/01_CICD_BEST_PRACTICES.md
https://github.com/shreeshailgumgeri/DevOps-SRE-Architecture-Project/blob/main/docs/Architecural-Docs/01_CICD_BEST_PRACTICES.md
- [AWS Cloud Best Practices](docs/Architectural-Docs/02_AWS_Cloud_Best_Practices.md)
- [Security Best Practices](docs/Architectural-Docs/03_Security_Best_Practices.md)
- [Automation Best Practices](docs/Architectural-Docs/04_Automation_Best_Practices.md)
- [Kubernetes Architecture](docs/Architectural-Docs/05_Kubernetes_Architecture.md)
- [Observability Architecture](docs/Architectural-Docs/06_Observability_Architecture.md)
- [High Availability Architecture](docs/Architectural-Docs/07_High_Availability_Architecture.md)
- [IAM Architecture](docs/Architectural-Docs/08_IAM%20Architecture.md)
- [GitOps Practices](docs/Architectural-Docs/09_GitOps_Practices.md)
- [Disaster Recovery Practices](docs/Architectural-Docs/10_Disaster_recovery_practices.md)
- [Architecture Overview](docs/Architectural-Docs/ARCHITECTURE.md)

---


## 🧩 Core Responsibilities

### ✅ Ownership & Leadership
This project emphasizes leading IAM-related reliability engineering initiatives with autonomy. It includes:
- Modular ownership boundaries for IAM subsystems.
- GitOps-driven architecture for change control.
- Reliability scorecard templates.

### 🩺 Platform Health
Designed to enhance the **availability, performance, and reliability** of critical IAM systems:
- Health checks for authentication, authorization, and entitlements services.
- Service-level indicators (SLIs) and objectives (SLOs) with Alertmanager configs.
- Fault-injection and chaos engineering practices.

### 🤖 Automation First
Reduce operational toil through:
- Automated incident response runbooks.
- Terraform modules to manage IAM roles, policies, and service accounts.
- GitHub Actions for validating security group updates.

### 🤝 Collaboration
Blueprints and code are structured for cross-functional extensibility:
- Clear README per component.
- API documentation for inter-team consumption.
- Collaboration templates for RFCs and design reviews.

---

## 🚀 Strategic Impact

### 🧑‍🏫 Mentorship
- Templates for onboarding new SREs.
- Contribution guidelines and internal wikis for engineering best practices.

### 🌍 Open Source Culture
- Modular, reusable, and PR-reviewed IaC modules.
- Encouragement for upstream contributions to shared tooling (e.g., Fluent Bit, Loki).
- Maintainer guide to foster transparent review cycles.

---

## 📁 Repository Structure

<details>
<summary>📂 Directory Structure</summary>

```
├── README.md
├── automation
│   └── incident-runbooks
│       ├── README.md
│       └── auth-failure.md
├── docs
│   ├── Architecural-Docs
│   │   ├── 01_CICD_BEST_PRACTICES.md
│   │   ├── 02_AWS_Cloud_Best_Practices.md
│   │   ├── 03_Security_Best_Practices.md
│   │   ├── 04_Automation_Best_Practices.md
│   │   ├── 05_Kubernetes_Architecture.md
│   │   ├── 06_Observability_Architecture.md
│   │   ├── 07_High_Availability_Architecture.md
│   │   ├── 08_IAM Architecture.md
│   │   ├── 09_GitOps_Practices.md
│   │   ├── 10_Disaster_recovery_practices.md
│   │   └── ARCHITECTURE.md
│   ├── DESIGN_PRINCIPLES.md
│   ├── README.md
│   └── RFC_TEMPLATE.md
├── kubernetes
│   ├── helm-charts
│   │   ├── README.md
│   │   └── chart.yaml
│   └── kustomize-overlays
│       └── README.md
├── observability
│   ├── alerting-rules
│   │   ├── README.md
│   │   └── iam-alert.yaml
│   └── slos
│       ├── README.md
│       └── login-latency.yaml
├── scripts
│   ├── fault-injection
│   │   └── inject_latency.sh
│   └── health-check
│       └── check_auth.sh
└── terraform-modules
    ├── access-boundaries
    │   ├── README.md
    │   └── main.tf
    ├── audit-logging
    │   ├── README.md
    │   └── main.tf
    └── iam-roles
        ├── README.md
        ├── main.tf
        └── variables.tf
```
</details>

---