
<img width="479" height="557" alt="natesmonerominer" src="https://github.com/user-attachments/assets/125a3a08-4c95-4243-810f-88a19ece3b21" />

🧠 MinerProject

A high-performance, modular Monero mining framework with broker-based job distribution, parallel CPU/GPU execution, and advanced share validation + optimization pipeline.

Built for flexibility, scalability, and experimentation with modern mining techniques.

🚀 Features
⚡ High Performance Mining
Parallel CPU hashing via ParallelPython DLL
GPU candidate scanning (OpenCL-based)
Hybrid CPU + GPU pipeline
Batch hashing + verification support
🔗 Broker-Based Architecture
Centralized job distribution (/v1/monero_rpc)
Global job snapshot system
Long-poll job feed with instant updates
Nonce leasing system to prevent duplicate work
🧮 Advanced Share Handling
Exact RandomX verification (local or relay)
Duplicate share filtering
Share quality + ranking metrics:
assigned_work
actual_work
credited_work
rank_score
Stale/invalid rejection handling
📊 Intelligent Pipeline
Adaptive workload throttling
Queue-aware candidate filtering
Dynamic scan tuning based on:
Job age
Queue pressure
Stale risk
🖥️ GUI + Monitoring
PyQt5-based miner dashboard
Real-time stats:
Hashrate
Accepted/rejected shares
Job status
Live log streaming
🌐 Multi-Backend Support
Monero RPC (solo mining)
P2Pool / Stratum compatibility
Custom broker integration
🏗️ Architecture Overview
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
📦 Project Structure
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
⚙️ Installation
Requirements
Python 3.10+
Windows (recommended)
OpenCL-compatible GPU (optional)
RandomX DLL
ParallelPython DLL
Setup
git clone https://github.com/nate2211/minerproject.git
cd minerproject

pip install -r requirements.txt
🔧 Configuration

Edit your configuration (example):

MONERO_RPC_URL = "http://127.0.0.1:18081"
BROKER_URL = "http://127.0.0.1:8080"

THREADS = 8
ENABLE_GPU = True
ENABLE_CPU_VERIFY = True
▶️ Running the Miner
Start GUI
python gui.py
Run headless
python miner_core.py
