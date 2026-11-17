# Forensic Text Analysis Report

- **Evidence:** `sample_evidence`
- **Analyzed:** 2026-11-17T06:57:23+00:00
- **Files analyzed:** 4 (skipped 0)

## Evidence files (chain of custody)

| File | SHA-256 | Bytes |
|---|---|---|
| chat_export.txt | `5d935ca6cddde2248f1be4136a193073f55516839ab9690876da2e6c564ab080` | 760 |
| firewall.log | `819961df57c14fa2ecbe7156e27b47fe96d0fa65dad79b4dba8fbaaca539ba48` | 568 |
| notes.txt | `c920f4e7ad0d1e1c23e5e8cb43128c40aa886d4db7ac43a1c7ec5e42f7750994` | 252 |
| suspicious_email.eml | `cb8a6dc67082026f815b8fc813b5457c1a9353fdf724e51fa4f9c73f89f828d0` | 582 |

## Indicators of compromise

### IP addresses (3)

| Value | Count | First seen |
|---|---|---|
| `203[.]0[.]113[.]45` _(documentation)_ | 3 | firewall.log:1 |
| `192[.]0[.]2[.]200` _(documentation)_ | 1 | firewall.log:3 |
| `198[.]51[.]100[.]77` _(documentation)_ | 1 | suspicious_email.eml:6 |

### URLs (2)

| Value | Count | First seen |
|---|---|---|
| `hxxps://files-share[.]example-drop[.]net/u/8812/q1` | 1 | chat_export.txt:5 |
| `hxxps://secure-login-portal[.]test/acme/verify?id=55120` | 1 | suspicious_email.eml:10 |

### Domains (7)

| Value | Count | First seen |
|---|---|---|
| `secure-login-portal[.]test` | 2 | suspicious_email.eml:1 |
| `acme-corp[.]test` | 1 | suspicious_email.eml:2 |
| `contoso[.]example` | 1 | notes.txt:4 |
| `files-share[.]example-drop[.]net` | 1 | chat_export.txt:5 |
| `mailbox-relay[.]test` | 1 | suspicious_email.eml:3 |
| `mx1[.]acme-corp[.]test` | 1 | suspicious_email.eml:7 |
| `relay7[.]mailbox-relay[.]test` | 1 | suspicious_email.eml:7 |

### Email addresses (3)

| Value | Count | First seen |
|---|---|---|
| `dkline@acme-corp[.]test` | 1 | suspicious_email.eml:2 |
| `harvest@mailbox-relay[.]test` | 1 | suspicious_email.eml:3 |
| `it-helpdesk@secure-login-portal[.]test` | 1 | suspicious_email.eml:1 |

### SHA-256 hashes (1)

| Value | Count | First seen |
|---|---|---|
| `9f2b8c1e4a7d6f3b0e5c2a1d8f7e6b5a4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f` | 1 | firewall.log:4 |

### MD5 hashes (1)

| Value | Count | First seen |
|---|---|---|
| `5d41402abc4b2a76b9719d911017c592` | 1 | firewall.log:5 |

### Bitcoin addresses (1)

| Value | Count | First seen |
|---|---|---|
| `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | 1 | chat_export.txt:7 |

### CVE IDs (1)

| Value | Count | First seen |
|---|---|---|
| `CVE-2024-3400` | 1 | firewall.log:5 |

## Keyword hits

| Keyword | Hits |
|---|---|
| password | 4 |
| payment | 2 |
| login | 2 |
| urgent | 2 |
| admin | 1 |
| dont tell | 1 |
| upload | 1 |
| dropbox | 1 |
| usb | 1 |
| wallet | 1 |
| delete | 1 |
| vpn | 1 |
| clear logs | 1 |
| tor | 1 |
| bank | 1 |
| wire transfer | 1 |
| invoice | 1 |
| credentials | 1 |
| confidential | 1 |

| Location | Context |
|---|---|
| chat_export.txt:2 | …22:14] mark_r: you still have the admin >>password<< for the finance share? |
| chat_export.txt:2 | …03-02 22:14] mark_r: you still have the >>admin<< password for the finance share? |
| chat_export.txt:3 | …:15] dkline: yeah its in the notes app. >>dont tell<< anyone |
| chat_export.txt:4 | …k_r: ok. pull the Q1 payroll export and >>upload<< it to the dropbox link I sent |
| chat_export.txt:4 | … Q1 payroll export and upload it to the >>dropbox<< link I sent |
| chat_export.txt:6 | … 22:20] dkline: done. its big, used the >>usb<< as backup too |
| chat_export.txt:7 | …1] mark_r: good. send the payment to my >>wallet<< 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa |
| chat_export.txt:7 | …026-03-02 22:31] mark_r: good. send the >>payment<< to my wallet 1A1zP1eP5QGefi2DMPTfTL5SLm… |
| chat_export.txt:8 | …-03-02 22:32] dkline: and make sure you >>delete<< this chat after. use the vpn from now o… |
| chat_export.txt:8 | …ure you delete this chat after. use the >>vpn<< from now on |
| chat_export.txt:9 | [2026-03-03 08:05] mark_r: also >>clear logs<< on the file server before monday |
| firewall.log:3 | …0.4.17:51602 -> 192.0.2.200:9001 reason=>>tor<<-exit-blocklist |
| notes.txt:2 | Payroll export totals look normal. >>Bank<< reconciliation pending. |
| notes.txt:3 | Reminder: rotate the service account >>password<< after the audit. |
| notes.txt:4 | …ntoso.example still unpaid; payment via >>wire transfer<< next week. |
| notes.txt:4 | Contractor >>invoice<< from contoso.example still unpaid; paym… |
| notes.txt:4 | …oice from contoso.example still unpaid; >>payment<< via wire transfer next week. |
| suspicious_email.eml:1 | From: IT Support <it-helpdesk@secure->>login<<-portal.test> |
| suspicious_email.eml:5 | Subject: URGENT: >>Password<< expires today |
| suspicious_email.eml:5 | Subject: >>URGENT<<: Password expires today |
| suspicious_email.eml:9 | Your >>password<< will expire in 2 hours. To keep access,… |
| suspicious_email.eml:9 | …in 2 hours. To keep access, verify your >>credentials<< here: |
| suspicious_email.eml:10 | https://secure->>login<<-portal.test/acme/verify?id=55120 |
| suspicious_email.eml:12 | This is >>URGENT<< and confidential. Do not forward this m… |
| suspicious_email.eml:12 | This is URGENT and >>confidential<<. Do not forward this message. |

## What the evidence talks about

**Top words:** dkline (6), mark (5), password (4), export (3), payroll (3), tcp (3), chat (2), still (2), notes (2), payment (2), file (2), allow (2), bytes (2), user (2), alert (2), edr (2), audit (2), support (2), urgent (2), fictional (1)

**Top phrases:** payroll export (2), allow tcp (2), tcp bytes (2), bytes user (2), user dkline (2), alert edr (2)
