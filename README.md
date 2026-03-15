# ⬡ SecurityDoS: Infrastructure Resilience & Red Team Platform

**SecurityDoS** is a professional-grade infrastructure resilience testing framework built in Go. Designed for Red Team operations and SRE (Site Reliability Engineering) teams, it provides deep insights into how your systems behave under extreme load.

Unlike traditional stress testing tools, **SecurityDoS** combines a high-performance concurrent engine with real-time analytics and an intelligent "Observation" system that automatically identifies technical breaking points and security triggers.

---

## 🚀 Key Features

- **High-Performance Load Engine**: Built with Go goroutines for massive concurrency, supporting HTTP/1.1 and HTTP/2.
- **Interactive Live Dashboard**: Real-time monitoring via WebSockets, featuring dynamic charts for RPS, TPS, Latency (p95, p99), and HTTP Status distribution.
- **Batch Testing Mode**: Automates testing across multiple URLs sequentially with configurable cooldown periods.
- **WAF & DDoS Evasion**: Advanced bypass techniques including dynamic User-Agent rotation, IP spoofing (XFF), Referer randomization, and unique `X-Device-ID` headers.
- **Adaptive TPS Feedback**: Automatically adjusts request pressure based on the target's actual success rate (Transactions Per Second).
- **Intelligent Reporting**: Generates detailed JSON and Markdown reports with automated security analysis and operational observations.
- **Report History Browser**: Dedicated UI to browse, filter, and review past test results.
- **Emergency Kill Switch**: High-priority safety mechanism to instantly abort all testing activity across the platform.

---

## ⚡ Emergency Kill Switch

The **Kill Switch** is a critical safety feature designed as an "Emergency Brake" for authorized testing.

- **Instant Termination**: Unlike a graceful stop, the Kill Switch terminates all active load-generation goroutines in **< 1 second**.
- **System Locking**: Once activated, the system enters a "Locked" state (`Kill Switch Active`). New tests cannot be started until the lock is explicitly reset.
- **Easy Reset**: In the dashboard, simply click the (now red) Kill Switch button to reset the state and resume testing operations.

---

## 🧠 Analysis Intelligence

The platform utilizes automated analysis algorithms to detect the target system's technical operational limits:

### 1. Breaking Point Detection
The system identifies structural failures when the **Error Rate exceeds 5%** (configurable) consistently for 3 seconds. This typically indicates resource exhaustion (CPU/RAM) or database connection pool limits.

### 2. Latency Degradation
Monitors performance availability. When average latency exceeds your configured threshold (e.g., **2000ms**), it identifies a significant service degradation point, which often leads to cascading failures.

### 3. Security Interception
Detects active defensive measures. If more than **15%** of traffic is met with HTTP **429 (Too Many Requests)** or **403 (Forbidden)**, the tool concludes that a Rate Limiter, WAF, or DDoS protection layer is actively mitigating the load.

---

## 🛠️ Installation & Build

### Prerequisites
- [Go](https://go.dev/dl/) v1.21 or higher.

### Build from Source

1. **Cloning & Preparation**:
   ```bash
   # Clone the repository and enter the directory
   git clone https://github.com/qyzan/Security_DoS.git
   cd Security_DoS

   # Tidy and download dependencies (Universal for all OS)
   go mod tidy
   ```

2. **Compile for your Platform**:

#### 🪟 Windows
```powershell
go build -o security-dos.exe .
```

#### 🐧 Linux (64-bit)
```bash
GOOS=linux GOARCH=amd64 go build -o security-dos-linux .
chmod +x security-dos-linux
```

#### 🍎 macOS (Intel & Apple Silicon)
- **Apple Silicon (M1/M2/M3):**
  ```bash
  GOOS=darwin GOARCH=arm64 go build -o security-dos-mac-arm .
  chmod +x security-dos-mac-arm
  ```
- **Intel Mac:**
  ```bash
  GOOS=darwin GOARCH=amd64 go build -o security-dos-mac-intel .
  chmod +x security-dos-mac-intel
  ```

---

## ⚙️ Configuration

Customization is handled via `configs/config.yaml`. No source code modification is required for standard operational changes.

```yaml
server:
  addr: ":8090" # Port for the Dashboard

safety:
  allowed_targets: # Domain allowlist for security
    - "api.test.internal"
  max_rps: 50000

analysis:
  breaking_point_rate: 0.05
  latency_threshold_ms: 2000.0
  security_trigger_rate: 0.15
```

### 📂 Custom Scenarios
Add `scenario_*.yaml` to `configs/` for automatic detection.

### 📝 Headers & User-Agent
- **Header Merging**: UI input overrides profile defaults for matching keys.
- **User-Agent Prefix**: 
  - *Empty*: Uses a random pool of real browser strings.
  - *Custom*: Uses your string. If **Evasion** is ON, a random suffix is added (e.g., `MyBot-a8f1`) to prevent fingerprinting.

---

## 🛡️ Safety Guard (Opt-in)

By default, **SecurityDoS** runs in **Unrestricted Mode** for maximum flexibility during local development or authorized laboratory testing. To enforce strict corporate policies defined in `config.yaml`, use the `--guard` flag.

- **Unrestricted Mode (Default)**: Ignores `allowed_targets`, `max_rps`, and `auth_tokens`.
- **Protected Mode (`--guard`)**: Enforces all safety policies, blocks unauthorized targets, and requires valid API tokens.

---

## 📖 Usage Guide

1. **Start the Platform**:
   - **Default (Unrestricted):**
     ```powershell
     .\security-dos.exe -config configs/config.yaml
     ```
   - **Safe Mode (Enforced):**
     ```powershell
     .\security-dos.exe -config configs/config.yaml --guard
     ```

   - **Using Docker (Safe Mode by Default):**
     ```bash
     # Build and run with one command
     docker-compose up -d --build
     ```
     *Note: Docker runs with `--guard` active by default. To disable it, modify `docker-compose.yml` manually (Use at your own risk!).*

2. **Access the UI**: Open your browser at `http://localhost:8090` (or the port defined in your config).
3. **Setup Test**: 
   - Enter your target URL (or multiple URLs for Batch Mode).
   - Configure Load (RPS) and Duration.
   - Enable **WAF Evasion** if testing against protected endpoints.
4. **Monitor & Analyze**: Watch the live metrics. Use the **Kill Switch** if the target system becomes unresponsive.
5. **Review Reports**: Once finished, click **View Report** or browse the **Report History** page.

---

## ⚠️ Ethical Disclaimer

**SecurityDoS is for authorized security testing only.** 
Unauthorized use of this tool against targets you do not own or have explicit permission to test is strictly prohibited and may be illegal. The developers assume no liability for misuse or damage caused by this platform.

---

**Red Team Platform v1.0** | *Built for Resilience.*
