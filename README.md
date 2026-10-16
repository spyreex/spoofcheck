# spoofcheck

A Python tool that checks whether a domain can be **spoofed in emails**, i.e. whether an attacker could send a fake email that appears to come from `someone@thatdomain.com`.

It reads the domain's public **SPF** and **DMARC** DNS records, grades them, and gives a clear verdict.

## Why this matters

Email has no built-in sender verification. Anyone can write `From: ceo@company.com` in an email. Domains protect themselves with two DNS records:

- **SPF** (`v=spf1 ...` TXT record): lists which servers are allowed to send mail for the domain.
- **DMARC** (`v=DMARC1 ...` TXT record on `_dmarc.domain`): tells receiving servers what to do when an email fails the checks: deliver it, send it to spam, or reject it.

A domain without DMARC, or with a weak policy, can be impersonated in phishing emails.

## Example output

<!-- Replace this block with a screenshot of your own run -->
```
Enter a domain: example.com
========================================
Email spoofing check: example.com
========================================
SPF record:   v=spf1 -all
SPF grade:    STRONG
DMARC record: v=DMARC1; p=reject
DMARC grade:  STRONG
Spoofable:    NO
========================================
Save a JSON report? (y/n): y
Report saved to report_example.com.json
```

In the terminal, grades and verdicts are colored (green = safe, yellow = partial, red = spoofable).

## Installation

```bash
git clone https://github.com/spyreex/spoofcheck.git
cd spoofcheck
pip install -r requirements.txt
```

On Windows, use `py -m pip install -r requirements.txt` if `pip` isn't recognized.

## Usage

```bash
python spoofcheck.py
```

Enter a domain when asked. Optionally save the result as a JSON report.

## How the grading works

### SPF (based on the `all` mechanism)

| Ending | Meaning | Grade |
|---|---|---|
| `-all` | reject unauthorized senders | STRONG |
| `~all` | mark them as suspicious (softfail) | MEDIUM |
| `?all` or no `all` | neutral, no opinion | WEAK |
| `+all` | allow **any** server to send | DANGEROUS |
| no SPF record | — | MISSING |

### DMARC (based on the `p=` policy tag)

| Policy | Meaning | Grade |
|---|---|---|
| `p=reject` | spoofed emails are blocked | STRONG |
| `p=quarantine` | spoofed emails go to spam | MEDIUM |
| `p=none` / missing policy | monitoring only, nothing blocked | WEAK |
| no DMARC record | no protection | DANGEROUS |

The record is split into tags before checking, so a subdomain policy like `sp=reject` is never mistaken for the main policy `p=reject`.

### Final verdict

DMARC decides, because it is the only record that tells receivers to block fake mail. SPF alone only checks the hidden envelope sender, not the `From:` address the victim sees.

| Situation | Spoofable? |
|---|---|
| DMARC missing or `p=none` | YES |
| SPF uses `+all` (any server passes SPF, so DMARC can't help) | YES |
| DMARC `p=quarantine` | PARTIALLY |
| DMARC `p=reject` | NO |

## Error handling

- Domain doesn't exist → clear error message, exit code 1
- Domain exists but has no TXT records → treated as "no SPF" (a real finding)
- DNS timeout → error and exit, instead of reporting a vulnerability that was never confirmed (avoids false positives)

## Limitations

- **DKIM is not checked.** DKIM keys are published under selector names (e.g. `selector1._domainkey.domain.com`) that can't be discovered from DNS alone.
- SPF `include:` and `redirect=` mechanisms are not followed recursively; the grade is based on the top-level record only.
- Only one domain per run for now.

## Roadmap

- [ ] Command-line arguments with `argparse` (`python spoofcheck.py google.com`)
- [ ] Check a list of domains from a file (`-f domains.txt`)
- [ ] MX record check (does the domain receive mail at all?)
- [ ] Automated tests with `pytest`

## Ethics

This tool only reads **public DNS records**. It sends no emails and does not interact with the target's mail servers. Use the results responsibly; if you find a misconfigured domain, report it to its owner rather than exploiting it.

## What I learned

Built while learning Python, coming from a networking background: DNS record types (TXT, SPF, DMARC), string parsing, functions and return values, error handling with `try/except`, dictionaries, JSON export, and colored terminal output.
