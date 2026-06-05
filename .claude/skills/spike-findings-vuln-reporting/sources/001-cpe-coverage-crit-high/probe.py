"""
Spike 001 — depth probe.

measure.py showed 99.2% CPE-prefix coverage but two surprises:
  - Hardware ~empty
  - 6.4% mixed {a,o}, all routed to Application by a>o>h precedence

Real question for a *team-ownership* metric: does "CPE part = a" actually mean
"App Support team owns it"? Linux distro package CVEs (openssl, kernel, glibc)
carry cpe:/a: but are remediated by the OS/Operations team via OS patching.
This probe breaks the Application bucket and the mixed set down by plugin_family
to see how much "Application" is really OS-team distro-patching work.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from config import vpr_to_severity  # noqa: E402

PARQUET = "data/cache/2026-06-02/vulns_all.parquet"
_CPE_PART = re.compile(r"cpe:(?:2\.3:|/)([aoh])[:/]", re.IGNORECASE)

# plugin_family substrings that mean "OS-team distro/platform patching" despite an app CPE.
OS_DISTRO_FAMILIES = re.compile(
    r"local security checks|red hat|centos|oracle linux|ubuntu|debian|suse|"
    r"amazon linux|rocky|alma|fedora|gentoo|f5 networks|solaris|aix|hp-ux|macos x local",
    re.IGNORECASE,
)


def parts(s):
    return {m.lower() for m in _CPE_PART.findall(s)} if isinstance(s, str) and s else set()


df = pd.read_parquet(PARQUET)
df = df.assign(
    derived_sev=df.apply(
        lambda r: vpr_to_severity(r.get("vpr_score"), fallback=str(r.get("severity") or "info").lower()),
        axis=1,
    )
)
ch = df[df["derived_sev"].isin(["critical", "high"])].assign(parts=lambda d: d["cpe"].apply(parts))
ch = ch.assign(
    has_a=ch["parts"].apply(lambda p: "a" in p),
    has_o=ch["parts"].apply(lambda p: "o" in p),
    has_h=ch["parts"].apply(lambda p: "h" in p),
)
n = len(ch)

print("=" * 70)
print("DEPTH PROBE — does CPE part 'a' == App Support team ownership?")
print("=" * 70)

# Application-by-precedence = any finding with 'a' (a>o>h means any 'a' wins).
app = ch[ch["has_a"]]
print(f"\nApplication bucket (any cpe:/a) : {len(app):,}  ({100*len(app)/n:.1f}% of Crit+High)")
print("Top 18 plugin_family within Application bucket:")
fam = app["plugin_family"].fillna("(none)").value_counts().head(18)
os_in_app = 0
for f, c in fam.items():
    tag = "  <-- OS-TEAM distro patching" if OS_DISTRO_FAMILIES.search(str(f)) else ""
    print(f"  {c:>6,}  ({100*c/len(app):4.1f}%)  {f}{tag}")
# total OS-distro share inside the Application bucket
app_os = app[app["plugin_family"].fillna("").apply(lambda f: bool(OS_DISTRO_FAMILIES.search(f)))]
print(f"\n  OS-distro-family findings sitting INSIDE Application bucket: "
      f"{len(app_os):,}  ({100*len(app_os)/len(app):.1f}% of Application, {100*len(app_os)/n:.1f}% of Crit+High)")

# The mixed {a,o} set specifically.
mixed = ch[ch["has_a"] & ch["has_o"]]
print(f"\nMixed {{a,o}} set                 : {len(mixed):,}  ({100*len(mixed)/n:.1f}% of Crit+High)")
print("Top 12 plugin_family within mixed {a,o}:")
for f, c in mixed["plugin_family"].fillna("(none)").value_counts().head(12).items():
    tag = "  <-- OS-TEAM" if OS_DISTRO_FAMILIES.search(str(f)) else ""
    print(f"  {c:>6,}  ({100*c/len(mixed):4.1f}%)  {f}{tag}")

# What if we classify by a plugin_family OS override FIRST, then CPE?
print("\n" + "=" * 70)
print("ALTERNATIVE: plugin_family OS-override FIRST, then CPE prefix")
print("=" * 70)
def bucket_family_first(row):
    fam = str(row["plugin_family"] or "")
    if OS_DISTRO_FAMILIES.search(fam):
        return "OS"
    p = row["parts"]
    if "a" in p:
        return "Application"
    if "o" in p:
        return "OS"
    if "h" in p:
        return "Hardware"
    return "Unclassified"

ch2 = ch.assign(bucket=ch.apply(bucket_family_first, axis=1))
print("Distribution under family-first rule:")
for b, c in ch2["bucket"].value_counts().items():
    print(f"  {b:<12}: {c:,}  ({100*c/n:.1f}%)")

print("\nvs CPE-prefix-only (a>o>h):")
def bucket_cpe(p):
    if "a" in p: return "Application"
    if "o" in p: return "OS"
    if "h" in p: return "Hardware"
    return "Unclassified"
ch3 = ch.assign(bucket=ch["parts"].apply(bucket_cpe))
for b, c in ch3["bucket"].value_counts().items():
    print(f"  {b:<12}: {c:,}  ({100*c/n:.1f}%)")
