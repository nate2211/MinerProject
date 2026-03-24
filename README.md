# 🧠 MinerProject

A high-performance, modular Monero mining framework with broker-based job distribution, parallel CPU/GPU execution, and advanced share validation + optimization pipeline.

Built for flexibility, scalability, and experimentation with modern mining techniques.

---

## 🚀 Features

### ⚡ High Performance Mining
- Parallel CPU hashing via ParallelPython DLL  
- GPU candidate scanning (OpenCL-based)  
- Hybrid CPU + GPU pipeline  
- Batch hashing + verification support  

### 🔗 Broker-Based Architecture
- Centralized job distribution (`/v1/monero_rpc`)  
- Global job snapshot system  
- Long-poll job feed with instant updates  
- Nonce leasing system to prevent duplicate work  

### 🧮 Advanced Share Handling
- Exact RandomX verification (local or relay)  
- Duplicate share filtering  
- Share quality + ranking metrics:
  - assigned_work  
  - actual_work  
  - credited_work  
  - rank_score  
- Stale/invalid rejection handling  

### 📊 Intelligent Pipeline
- Adaptive workload throttling  
- Queue-aware candidate filtering  
- Dynamic scan tuning based on:
  - Job age  
  - Queue pressure  
  - Stale risk  

### 🖥️ GUI + Monitoring
- PyQt5-based miner dashboard  
- Real-time stats:
  - Hashrate  
  - Accepted/rejected shares  
  - Job status  
- Live log streaming  

### 🌐 Multi-Backend Support
- Monero RPC (solo mining)  
- P2Pool / Stratum compatibility  
- Custom broker integration  

---

## 🏗️ Architecture Overview

```
           ┌────────────────────┐
           │   Job Source       │
           │ (monerod/stratum) │
           └─────────┬──────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │ Monero RPC Broker       │
        │ /v1/monero_rpc          │
        └─────────┬───────────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
 ┌──────────────┐   ┌──────────────┐
 │ GPU Scanner  │   │ CPU Workers  │
 │ (OpenCL)     │   │ ParallelPython│
 └──────┬───────┘   └──────┬───────┘
        │                  │
        ▼                  ▼
        ┌──────────────────────┐
        │ Candidate Queue      │
        └─────────┬────────────┘
                  ▼
        ┌──────────────────────┐
        │ Verification Engine  │
        │ (RandomX)            │
        └─────────┬────────────┘
                  ▼
        ┌──────────────────────┐
        │ Share Submission     │
        └──────────────────────┘
```

---

## 📦 Project Structure

```
minerproject/
├── gui.py                     # PyQt5 GUI
├── miner_core.py              # Main mining pipeline
├── parallel_python_worker.py  # CPU worker (ParallelPython)
├── cpu_verifier.py            # RandomX verification
├── monero_rpc_client.py       # Broker + RPC interface
├── opencl_gpu_scanner.py      # GPU scanning engine
├── config.py                  # Configuration
├── utils/                     # Helpers
└── logs/                      # Runtime logs
```

---

## ⚙️ Installation

### Requirements
- Python 3.10+
- Windows (recommended)
- OpenCL-compatible GPU (optional)
- RandomX DLL
- ParallelPython DLL

### Setup

```bash
git clone https://github.com/nate2211/minerproject.git
cd minerproject

pip install -r requirements.txt
```

---

## 🔧 Configuration

Edit your configuration (example):

```python
MONERO_RPC_URL = "http://127.0.0.1:18081"
BROKER_URL = "http://127.0.0.1:8080"

THREADS = 8
ENABLE_GPU = True
ENABLE_CPU_VERIFY = True
```

---

## ▶️ Running the Miner

### Start GUI
```bash
python gui.py
```

### Run headless
```bash
python miner_core.py
```

---

## 🔌 API Endpoints (Broker)

| Endpoint | Description |
|----------|------------|
| `/v1/monero_rpc/job/current` | Get current mining job |
| `/v1/monero_rpc/job/push` | Push new job |
| `/v1/monero_rpc/feed/poll` | Long-poll job updates |
| `/v1/monero_rpc/lease/alloc` | Allocate nonce range |
| `/v1/monero_rpc/submit/share` | Submit share |

---

## 🧪 Advanced Features

### 🔁 Nonce Leasing
Prevents duplicate work across miners by allocating unique nonce ranges.

### 📉 Adaptive Throttling
Automatically adjusts workload based on:
- Queue size
- System performance
- Network latency

### 🧠 Smart Candidate Filtering
Ranks candidates before verification to reduce CPU load.

### ⚡ Batch Processing
- Batch hashing
- Batch verification
- Vectorized operations

---

## ⚠️ Disclaimer

This project is for **educational and experimental purposes**.  
Mining cryptocurrency may consume significant resources and electricity.

---

## 📄 License

MIT License

---

## ⭐ Contributing

Pull requests are welcome.  
For major changes, open an issue first to discuss what you'd like to change.
