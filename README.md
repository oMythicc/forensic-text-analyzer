# Forensic Text Analyzer

A Python command-line tool for **triaging text evidence** such as chat exports, emails (`.eml`), server and firewall logs, notes, and CSV/JSON exports. Point it at a folder and it pulls out what an investigator needs first:

- 🧭 **Indicators of compromise (IOCs):** IP addresses, URLs, domains, email addresses, MD5/SHA-1/SHA-256 hashes, Bitcoin and Ethereum addresses, CVE IDs
- 🔎 **Watchlist keyword hits**, each shown **in context** with its file and line number
- 📊 **Word and phrase frequencies** (common words removed), so you can see what the evidence is about
- 🔐 **A SHA-256 hash of every evidence file** for chain of custody

**No dependencies.** It uses only the Python standard library, so it runs on locked-down forensic workstations with no `pip install`.

---

## The scenario

HR forwards a folder from a suspected insider case: a chat export, a phishing email the employee received, a firewall log and some notes. The analyst needs to know quickly:

- **Which indicators appear?** These IPs, domains and hashes can be blocked, hunted in the SIEM or checked against threat intel.
- **Where does suspicious language show up?** Words like "password," "delete," "clear logs," "wallet," "don't tell."
- **What connects the files?** In the sample below, the IP that relayed the phishing email (`203.0.113.45`) is the **same IP** receiving 100 MB of outbound traffic in the firewall log. One cross-file IOC ties two pieces of evidence together.

Reading every line by hand takes hours. This tool produces a first-pass report in seconds.

---

## Features

| | |
|---|---|
| **IOC extraction** | IPv4 (labeled public / private / documentation), URLs, domains, emails, MD5 / SHA-1 / SHA-256, Bitcoin (legacy + bech32), Ethereum, CVE IDs |
| **Refanging** | Catches IOCs written "defanged" for safe sharing, e.g. `hxxps://evil[.]com` or `user[at]domain[.]com` |
| **Safe output** | IOCs are **defanged** in reports by default so nobody accidentally clicks a malicious link (`--no-defang` to turn off) |
| **Keyword watchlist** | 50+ built-in investigative terms (credentials, money, evasion, exfiltration, social engineering) or your own list. Matches whole words and ignores case |
| **Context (concordance)** | Every hit shows the words around it with the match marked `>>like this<<` |
| **Email parsing** | `.eml` files are parsed into headers (`From`, `Reply-To`, `Received`, `X-Originating-IP`…) plus body text |
| **Cross-file correlation** | Each IOC records how many times it appeared, where it was first seen, and every file it appeared in |
| **Chain of custody** | SHA-256 of each evidence file is recorded in the report |
| **Reports** | `report.md` (readable case summary), `report.json`, `iocs.csv`, `keyword_hits.csv` |
| **Search mode** | `-s TERM` prints every occurrence of a word across all files, in context |
| **Safe with binaries** | Binary files are detected and skipped instead of crashing the run |

---

## Installation

```bash
git clone https://github.com/oMythicc/forensic-text-analyzer.git
cd forensic-text-analyzer
python forensic_text_analyzer.py --help
```

Requires Python 3.8+. Nothing to install.

---

## Usage

```bash
# Analyze a folder of evidence
python forensic_text_analyzer.py ./case_0042

# Try it on the included fictional sample case
python forensic_text_analyzer.py sample_evidence

# Use your own watchlist (one keyword or phrase per line)
python forensic_text_analyzer.py ./case_0042 -k watchlist_example.txt

# Add a few case-specific terms to the default list
python forensic_text_analyzer.py ./case_0042 --add-keyword payroll --add-keyword "project falcon"

# Find every mention of a person or term, in context
python forensic_text_analyzer.py ./case_0042 -s dkline

# Include internal IPs (10.x, 192.168.x, …) and read every file type
python forensic_text_analyzer.py ./case_0042 --private-ips --all-files
```

| Option | Default | Description |
|---|---|---|
| `target` | (required) | Evidence file or folder |
| `-k, --keywords FILE` | built-in list | Watchlist file (replaces the default list) |
| `--add-keyword WORD` | | Add a term to the watchlist (repeatable) |
| `-s, --search TERM` | | Only print every occurrence of TERM in context |
| `--private-ips` | off | Also report private/internal IPs |
| `--all-files` | off | Read every file, not just text extensions |
| `--no-defang` | off | Show IOCs live instead of defanged |
| `--width` | 40 | Characters of context around each hit |
| `--top` | 25 | Number of top words/phrases to keep |
| `--max-hits` | 15 | Keyword hits printed on screen (all go in the CSV) |
| `-o, --out` | `analysis_<timestamp>` | Output folder |

---

## Example output

Running against the fictional case in [`sample_evidence/`](sample_evidence). The full generated report is in [`sample_report/report.md`](sample_report/report.md).

```
======================================================================
 FORENSIC TEXT ANALYSIS  sample_evidence
======================================================================
 Files analyzed : 4  (31 lines)

 INDICATORS OF COMPROMISE
  IP addresses (3)
     - 203[.]0[.]113[.]45 [documentation]  x3  (firewall.log:1)
     - 192[.]0[.]2[.]200 [documentation]  x1  (firewall.log:3)
     - 198[.]51[.]100[.]77 [documentation]  x1  (suspicious_email.eml:6)
  URLs (2)
     - hxxps://files-share[.]example-drop[.]net/u/8812/q1  x1  (chat_export.txt:5)
     - hxxps://secure-login-portal[.]test/acme/verify?id=55120  x1  (suspicious_email.eml:10)
  Email addresses (3)
     - dkline@acme-corp[.]test  x1  (suspicious_email.eml:2)
     - harvest@mailbox-relay[.]test  x1  (suspicious_email.eml:3)
     - it-helpdesk@secure-login-portal[.]test  x1  (suspicious_email.eml:1)
  SHA-256 hashes (1)
     - 9f2b8c1e4a7d6f3b0e5c2a1d8f7e6b5a4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f  x1  (firewall.log:4)
  Bitcoin addresses (1)
     - 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  x1  (chat_export.txt:7)
  CVE IDs (1)
     - CVE-2024-3400  x1  (firewall.log:5)

 KEYWORD HITS (25)
  password x4, payment x2, login x2, urgent x2, admin x1, dont tell x1, upload x1, dropbox x1, ...
     chat_export.txt:3  …:15] dkline: yeah its in the notes app. >>dont tell<< anyone
     chat_export.txt:4  … Q1 payroll export and upload it to the >>dropbox<< link I sent
     chat_export.txt:7  …1] mark_r: good. send the payment to my >>wallet<< 1A1zP1eP5QGefi2DMPTfTL5SLm…
     chat_export.txt:9  [2026-03-03 08:05] mark_r: also >>clear logs<< on the file server before monday
     firewall.log:3  …0.4.17:51602 -> 192.0.2.200:9001 reason=>>tor<<-exit-blocklist
     … more in keyword_hits.csv

 TOP WORDS   : dkline, mark, password, export, payroll, tcp, chat, still, notes, payment, file, allow
 TOP PHRASES : payroll export, allow tcp, tcp bytes, bytes user, user dkline, alert edr
======================================================================
```

Notice that the obfuscated link `hxxps://files-share[.]example-drop[.]net` in the chat was still caught, and `203.0.113.45` shows up in **two different files** (the email headers and the firewall log).

> All names, domains, IPs and hashes in the sample are fictional. IPs use the RFC 5737 documentation ranges, and domains use reserved `.test` / `.example` TLDs. The Bitcoin address is the well-known "genesis block" address, used only as an example of the format.

---

## How it works

1. **Collect:** walks the folder, keeps text-type files (or all files with `--all-files`), skips binaries, and hashes each file with SHA-256.
2. **Normalize:** `.eml` files are parsed into headers and body. Each line is **refanged** (`hxxp` → `http`, `[.]` → `.`) so obfuscated IOCs still match.
3. **Extract:** regular expressions find each IOC type. Hashes are matched first and masked out, so a SHA-256 isn't also read as an MD5 or a wallet address. IPs are validated and labeled with Python's `ipaddress` module.
4. **Flag:** each watchlist term is matched as a whole word, ignoring case, and saved with its file, line and surrounding text.
5. **Summarize:** remaining words are tokenized, common stopwords removed, and the top words and two-word phrases counted.
6. **Report:** results are written as Markdown, JSON and CSV, with IOCs defanged for safe sharing.

---

## Limitations

- Pattern-based extraction can produce **false positives** (any 32-character hex string looks like an MD5). Always verify before acting.
- Bitcoin addresses are matched by format, not validated by checksum.
- IPv6 isn't extracted yet.
- Reads text-based formats only. Convert PDFs and Office documents to text first.

## Possible next steps

- IPv6 support and Bitcoin checksum validation
- Export IOCs as STIX 2.1 for sharing with threat-intel platforms
- Pipe extracted hashes straight into my [File Hash Threat Scanner](https://github.com/oMythicc/file-hash-scanner)
- A timeline view that orders events from timestamps in the logs and chats

---

## Background

This project was inspired by an NLTK text-analysis exercise in a Python course for my Cyber Operations degree at the University of Arizona (2024). That exercise used a provided template to count words, find concordances and measure vocabulary in a text corpus. I wanted to use the same ideas on a real investigative problem, so I wrote this tool from scratch with a forensics focus: IOC extraction, keyword watchlists with context, email parsing and chain-of-custody hashing.

## License

MIT, see [LICENSE](LICENSE).
