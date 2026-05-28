<h1 align="center">IoT Honeypot</h1>

---

> [!WARNING]
> **Analysis Honeypot**: This system is designed to attract and observe real attackers.
> It is **not** a production security product. Deploy only on isolated infrastructure
> with appropriate institutional and legal approvals.

---

## Why ZeroTrace?

Today's IoT forensics captures network logs but rarely kernel-level activity. When an attacker pivots between containers, drops a binary in `/tmp`, or injects code into a running process, traditional tools miss it entirely.

ZeroTrace solves this by placing four [Cilium Tetragon](https://github.com/cilium/tetragon) eBPF kprobes at the kernel level inside an IoT honeypot that emulates a **Hikvision DS-2CD2183G2 IP camera**. Every kernel event is tagged with a UUID per attacker, then sealed into a tamper-evident evidence chain (SHA-256, [OpenTimestamps](https://opentimestamps.org/) Bitcoin anchor, MinIO WORM).
<p align="center">
  <img width="1672" height="941" alt="why zerotrace" src="https://github.com/user-attachments/assets/a611f390-e0aa-4aad-b399-54de84e4faab" />
</p>
