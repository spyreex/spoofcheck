"""
spoofcheck - Email spoofing checker

Checks a domain's SPF and DMARC DNS records and tells you how easy it
would be for an attacker to send fake emails pretending to be that domain.
"""

import json
import sys

import dns.resolver
from colorama import Fore, Style, just_fix_windows_console


# Colors for the terminal report (never written to the JSON file)
GRADE_COLORS = {
    "STRONG": Fore.GREEN,
    "MEDIUM": Fore.YELLOW,
    "WEAK": Fore.RED,
    "DANGEROUS": Fore.RED,
    "MISSING": Fore.RED,
}

VERDICT_COLORS = {
    "NO": Fore.GREEN,
    "PARTIALLY": Fore.YELLOW,
    "YES": Fore.RED,
}


def get_txt_records(domain):
    """Return all TXT records of a domain. Stops the script if the domain doesn't exist."""
    try:
        records = dns.resolver.resolve(domain, "TXT")
    except dns.resolver.NXDOMAIN:
        print(f"Error: {domain} does not exist")
        sys.exit(1)
    except dns.resolver.NoAnswer:
        records = []
    except dns.resolver.LifetimeTimeout:
        print(f"Error: DNS lookup timed out for {domain}")
        sys.exit(1)
    return records


def find_spf(records):
    """Return the SPF record from a list of TXT records, or None if there is none."""
    spf_record = None
    for record in records:
        text = str(record).strip('"')
        if text.startswith("v=spf1"):
            spf_record = text
    return spf_record


def grade_spf(spf_record):
    """Grade an SPF record based on its 'all' ending."""
    if spf_record is None:
        return "MISSING"
    if "-all" in spf_record:
        return "STRONG"
    elif "~all" in spf_record:
        return "MEDIUM"
    elif "?all" in spf_record:
        return "WEAK"
    elif "+all" in spf_record:
        return "DANGEROUS"
    else:
        return "WEAK"


def find_dmarc(domain):
    """Look up the DMARC record at _dmarc.<domain>. Return it, or None if there is none."""
    dmarc_domain = f"_dmarc.{domain}"
    try:
        dmarc_result = dns.resolver.resolve(dmarc_domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        dmarc_result = []
    except dns.resolver.LifetimeTimeout:
        # A timeout means "unknown", not "missing": stop instead of reporting a false positive
        print(f"Error: DMARC lookup timed out for {domain}")
        sys.exit(1)

    dmarc_record = None
    for record in dmarc_result:
        text = str(record).strip('"')
        if text.startswith("v=DMARC1"):
            dmarc_record = text
    return dmarc_record


def grade_dmarc(dmarc_record):
    """Grade a DMARC record based on its p= (policy) tag."""
    if dmarc_record is None:
        return "DANGEROUS"

    # Split into tags so that "sp=reject" is not mistaken for "p=reject"
    policy = None
    for part in dmarc_record.split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part

    if policy == "p=reject":
        return "STRONG"
    elif policy == "p=quarantine":
        return "MEDIUM"
    else:
        return "WEAK"   # p=none, or policy missing/invalid


def get_verdict(spf_grade, dmarc_grade):
    """Combine both grades into one answer: can this domain be spoofed?"""
    if dmarc_grade in ("WEAK", "DANGEROUS"):
        return "YES"
    if spf_grade == "DANGEROUS":   # +all lets any server pass SPF, so DMARC can't help
        return "YES"
    if dmarc_grade == "MEDIUM":
        return "PARTIALLY"
    return "NO"


def colored(text, color_table):
    """Return text wrapped in its color from the given table."""
    color = color_table.get(text, "")
    return f"{color}{text}{Style.RESET_ALL}"


def save_json(report, filename):
    """Save the report dictionary as a JSON file."""
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)


def main():
    just_fix_windows_console()

    domain = input("Enter a domain: ").strip()

    records = get_txt_records(domain)
    spf_record = find_spf(records)
    spf_grade = grade_spf(spf_record)

    dmarc_record = find_dmarc(domain)
    dmarc_grade = grade_dmarc(dmarc_record)

    verdict = get_verdict(spf_grade, dmarc_grade)

    print("=" * 40)
    print(f"Email spoofing check: {domain}")
    print("=" * 40)
    print(f"SPF record:   {spf_record}")
    print(f"SPF grade:    {colored(spf_grade, GRADE_COLORS)}")
    print(f"DMARC record: {dmarc_record}")
    print(f"DMARC grade:  {colored(dmarc_grade, GRADE_COLORS)}")
    print(f"Spoofable:    {colored(verdict, VERDICT_COLORS)}")
    print("=" * 40)

    report = {
        "domain": domain,
        "spf_record": spf_record,
        "spf_grade": spf_grade,
        "dmarc_record": dmarc_record,
        "dmarc_grade": dmarc_grade,
        "verdict": verdict,
    }

    answer = input("Save a JSON report? (y/n): ").strip().lower()
    if answer == "y":
        filename = f"report_{domain}.json"
        save_json(report, filename)
        print(f"Report saved to {filename}")


if __name__ == "__main__":
    main()
