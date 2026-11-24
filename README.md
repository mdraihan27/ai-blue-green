# AI Red Team–Driven Security Validation for Blue-Green Deployment of Autonomous AI Agents

A production-grade, object-oriented terminal application implementing the full architecture from the research proposal **"AI Red Team–Driven Security Validation for Blue-Green Deployment of Autonomous AI Agents"**.

---

## Key Features

1. **One-Time Local Folder Security Test (`test-folder`):**
   - Takes the file or directory path of any target AI agent.
   - Automatically introspects its Python AST, system prompt, registered tools, memory stores, and security guardrails.
   - Deploys the agent into an isolated **Green Sandbox** with tool and memory interceptors.
   - Runs context-aware attacks across all **6 Proposal Threat Categories**:
     1. **Prompt Injection** (Direct override, Delimiter escape, Indirect RAG injection)
     2. **Tool Abuse** (Malicious argument injection, destructive shell/file parameters, chained exfiltration)
     3. **Memory Poisoning** (Multi-turn persistent rule corruption, RAG knowledge poisoning)
     4. **Sensitive Data Leakage** (Verbatim system prompt extraction, hardcoded API key probing, cross-tenant PII dump)
     5. **Jailbreak** (DAN/Developer Mode persona framing, Base64/obfuscated policy bypass)
     6. **Privilege Escalation** (Admin identity spoofing, spoofed header RBAC bypass)
   - Calculates all **6 Proposal Evaluation Metrics**:
     - *Attack Success Rate (ASR %)*
     - *Policy Violation Rate (PVR %)*
     - *Tool Misuse Rate (TMR %)*
     - *Sensitive Data Leakage Rate (SDLR %)*
     - *Task Completion Success (TCS %)*
     - *Response Time (RT ms)*
   - Outputs a **0.00% – 100.00% Overall Security Validation Score** and **Weighted Risk Score (%)**, and automatically promotes **Green $\rightarrow$ Blue** or triggers **Auto-Rollback to Blue**.

2. **One-Time GitHub Repository Clone & Security Test (`test-github`):**
   - Takes a GitHub repository URL (HTTPS, SSH, or local git repo path), clones it into an isolated workspace with timeout protection, tests the agent in Green, and outputs the percentage score and JSON report.

3. **Continuous GitHub Push Watcher (`watch-github`):**
   - Continuously monitors a GitHub repository for new pushes/commits (`git ls-remote`).
   - Whenever a new push arrives, automatically fetches the latest commit into the **Green** environment, executes the AI Red Team suite, computes the percentage score, and either promotes the new version to **Blue** or rolls back automatically.

4. **Blue-Green Traffic Controller & Comparative Benchmark (`status`, `rollback`, `benchmark`):**
   - Tracks active **Blue** (Production) and **Green** (Staging) slots, exports Prometheus metrics, and includes an experimental comparative benchmark (`benchmark`) comparing Traditional Deployment vs. Proposed AI Red Team Blue-Green Deployment.

---

## Quick Start (Terminal Usage)

### Installation
```bash
pip install -e .
```
*(Or run directly with `PYTHONPATH=src python3 -m agent_bg_sec.main ...`)*

### 1. One-Time Test of a Local Agent Folder
```bash
# Test a hardened safe agent (Scores 100.00% -> Promoted from Green to Blue)
agent-sec test-folder examples/safe_banking_agent

# Test a vulnerable agent (Low Security Score -> Auto-Rollback to stable Blue)
agent-sec test-folder examples/vulnerable_devops_agent

# Test a partially guarded agent without changing deployment state
agent-sec test-folder examples/healthcare_rag_agent --no-deploy
```

### 2. One-Time Test of a GitHub Repository
```bash
agent-sec test-github https://github.com/<owner>/<repo>.git --branch main
```

### 3. Continuous Automated Testing of a GitHub Repository (On Every Push)
```bash
agent-sec watch-github https://github.com/<owner>/<repo>.git --branch main --interval 30
```

### 4. View Blue-Green Environment Status or Trigger Manual Rollback
```bash
agent-sec status
agent-sec rollback --reason "Emergency rollback to previous stable Blue release"
```

### 5. Run Comparative Experimental Evaluation (Proposal Section 7e & C4)
```bash
agent-sec benchmark
```

