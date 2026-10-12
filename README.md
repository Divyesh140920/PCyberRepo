# PCyberRepo

A collection of small, self-contained **cybersecurity and Python security
tooling** projects, built for learning and to demonstrate hands-on skills
across cryptography, network analysis, and defensive security.

> **Ethics & scope.** Everything here is for **education and authorized use
> only**. The network tools must be pointed only at systems you own or have
> explicit written permission to test. Do not use any code here for
> unauthorized or illegal activity.

Maintained by **Divyesh Sai Gutta** — MS, Information Technology & Management.

## Projects

| Project | What it demonstrates | Key tech |
|---------|----------------------|----------|
| [Crypto Algorithms](./Crypto_Algorithms) | Symmetric & public-key crypto done correctly (AES-GCM, RSA-OAEP, Caesar) | `pycryptodome` |
| [Encrypted Chat Application (AES)](./Encrypted%20Chat%20Application%20with%20AES) | Authenticated encryption over TCP with message framing | sockets, AES-GCM |
| [Password Strength Checker](./Password%20Strength%20Checker) | Heuristic password scoring, CLI + Flask UI | `flask` |
| [Automated Log File Analyzer](./Automated%20Log%20File%20Analyzer) | Pattern-based log triage with severities and JSON output | stdlib |
| [Firewall Rule Visualizer](./Firewall%20Rule%20Visualizer%20and%20Generator) | Rule parsing, conflict detection, graph rendering | `networkx`, `matplotlib` |
| [Phishing Email Detection](./Phishing%20Email%20Detection) | TF-IDF + Random Forest classifier with train/predict | `scikit-learn`, `nltk` |
| [Basic Network Scanner](./Basic%20Network%20Vulnerability%20Scanner%20in%20Python) | Multithreaded TCP port scanning | stdlib |
| [Port Scanner with Banner Grabbing](./Port%20Scanner%20with%20Banner%20Grabbing) | Port scan + service banner identification | stdlib |
| [Python Packet Sniffer](./Python_Packet_Sniffer) | Live packet capture and summarization | `scapy` |
| [Network Traffic Analyzer](./Network%20Traffic%20Analyzer) | Protocol breakdown + top talkers | `scapy` |

> The `Keylogger/` directory is an early learning artifact and is **left
> unmodified**; it is kept for reference only and is not part of the rebuilt,
> maintained tooling above.

## Conventions

Every maintained project follows the same shape:

- A **command-line interface** with `--help` (no hard-coded targets or paths).
- A **`requirements.txt`** where third-party packages are needed (several use
  only the standard library).
- Its own **`readme.md`** with setup, usage, and notes on what changed.
- Clear **error handling** and meaningful **exit codes**.

## Getting started

Each project is independent. Enter a project directory, install its
requirements if it has any, and run it:

```bash
cd "Crypto_Algorithms"
pip install -r requirements.txt     # if present
python aes_cipher.py --help
```

Using a virtual environment is recommended:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

## License

Released under the [MIT License](./LICENSE) for educational use.
