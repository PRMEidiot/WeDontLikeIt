"""Rules for malicious scripts and commands (shell, PowerShell, PHP, Python, VBS, AppleScript...).

The rules also run over strings found in executables, .lnk shortcuts and documents,
including UTF-16 text (common on Windows).

Speed: the text is lowercased once and every regex has literal keywords; the regex
only runs when one of its keywords is present (a plain ``in`` check, which is very fast).

Note: the odd parentheses in the middle of words, as in ``invoke-(expression)``, are
on purpose. They keep this file's own source from matching its rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .heuristics import Finding

TEXT_LIMIT = 4 << 20  # look at no more than 4 MB of text per file
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


@dataclass(frozen=True)
class Check:
    keywords: tuple[bytes, ...]  # at least one must appear (lowercase text)
    regex: re.Pattern

    def search(self, text: bytes) -> bool:
        return any(k in text for k in self.keywords) and self.regex.search(text) is not None


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    any_of: tuple[Check, ...] = ()
    all_of: tuple[Check, ...] = ()

    def matches(self, text: bytes) -> bool:
        if self.any_of and not any(c.search(text) for c in self.any_of):
            return False
        return all(c.search(text) for c in self.all_of)


def C(keywords, pattern: bytes, flags: int = 0) -> Check:
    if isinstance(keywords, bytes):
        keywords = (keywords,)
    return Check(tuple(keywords), re.compile(pattern, flags))


S = re.S  # "." also matches newlines

RULES: tuple[Rule, ...] = (
    Rule("Script.ReverseShell", "medium", any_of=(
        C(b"/dev/tcp/", rb"bash\s+-i\s*[>&]+\s*/dev/tcp/"),
        C(b"/dev/udp/", rb"bash\s+-i\s*[>&]+\s*/dev/udp/"),
        C((b"/bin/sh", b"/bin/bash", b"cmd", b"powershell"),
          rb"\bnc(at)?(\.exe)?\s[^\n]{0,100}?\s-[a-z]*e\s+\S*(/bin/(ba|z|da)?sh|cmd(\.exe)?|powershell)"),
        C(b".connect(", rb"\bsocket\.socket\(.{0,400}?\.connect\(.{0,400}?(os\.dup2\(|pty\.spawn\(|subprocess\.)", S),
        C(b"fsockopen", rb"\bfsockopen\(.{0,200}?\b(exec|shell_exec|system|passthru|proc_open)\s*\(", S),
    )),
    Rule("Script.WebShell", "medium", any_of=(
        C(b"$_", rb"\b(eval|assert|system|passthru|shell_exec)\s*\(\s*\$_(get|post|request|cookie)\b"),
    )),
    Rule("Script.DownloadAndRun", "medium", any_of=(
        C((b"curl", b"wget"), rb"\b(curl|wget)\s[^\n|;]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
        C((b"/tmp/", b"/dev/shm/"),
          rb"\b(curl|wget)\s[^\n]{0,300}(/tmp/|/dev/shm/)[^\n]{0,200}(&&|;)\s*(chmod\s+\+x|\./|sh\s)"),
    )),
    # download and run on the same PowerShell line
    Rule("PowerShell.DownloadCradle", "medium", any_of=(
        C((b"webclient", b"webrequest", b"restmethod", b"iwr", b"irm", b"download"),
          rb"(net\.web(client)|invoke-(webrequest)|invoke-(restmethod)|\bi(wr)\s|\bi(rm)\s|\.download(string|data)\s*\()"
          rb"[^\n\x00]{0,300}?(\|\s*i(ex)\b|\|\s*invoke-(expression)|\bi(ex)\s*\(|invoke-(expression)\s*\()"),
        C((b"iex", b"expression"),
          rb"(\bi(ex)|invoke-(expression))\s*[\(\s][^\n\x00]{0,300}?(net\.web(client)|\.download(string|data)\s*\()"),
    )),
    Rule("PowerShell.EncodedCommand", "medium", any_of=(
        C(b"powershell", rb"powershell(\.exe)?\s([^\n]{0,200}?\s)?-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{40,}"),
    )),
    Rule("PowerShell.HiddenWindow", "low", any_of=(
        C(b"powershell", rb"powershell(\.exe)?\s([^\n]{0,200}?\s)?-w(indowstyle)?\s+h(idden)?\b"),
    )),
    Rule("Evasion.DisableAntivirus", "medium", any_of=(
        C(b"set-mppreference",
          rb"set-mppreference\s[^\n]{0,100}-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning)\s+\$?(true|1)\b"),
        C(b"add-mppreference", rb"add-mppreference\s[^\n]{0,50}-exclusionpath\s"),
        C(b"windefend", rb"\bsc(\.exe)?\s+(stop|config)\s+windefend\b"),
    )),
    Rule("Ransomware.DeleteBackups", "medium", any_of=(
        C(b"vssadmin", rb"vssadmin(\.exe)?\s+delete\s+shadows"),
        C(b"shadowcopy", rb"wmic(\.exe)?\s+shadowcopy\s+delete"),
        C(b"recoveryenabled", rb"bcdedit(\.exe)?\s+/set\s+\{?default\}?\s+recoveryenabled\s+no"),
        C(b"wbadmin", rb"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)"),
        C(b"tmutil", rb"tmutil\s+(delete|disable)\b"),
    )),
    Rule("Ransomware.RansomNote", "medium", all_of=(
        C(b"encrypted", rb"(your|all)\s+(important\s+)?files\s+(have\s+been|are|were)\s+encrypted"),
        C((b"bitcoin", b"btc", b"monero", b"xmr", b"tor", b".onion"),
          rb"\b(bit(coin)|btc|mon(ero)|xmr|tor\s+browser|\.onion)\b"),
    )),
    Rule("LOLBin.Download", "medium", any_of=(
        C(b"urlcache", rb"certutil(\.exe)?\s[^\n]{0,100}-urlcache\s[^\n]{0,100}https?://"),
        C(b"/transfer", rb"bitsadmin(\.exe)?\s[^\n]{0,100}/transfer\s[^\n]{0,200}https?://"),
        C(b"mshta", rb"mshta(\.exe)?\s+[\"']?(https?|vbscript|javascript):"),
        C(b"/i:", rb"regsvr32(\.exe)?\s[^\n]{0,100}/i:\s*https?://"),
        C(b"rundll32", rb"rundll32(\.exe)?\s[^\n]{0,50}javascript:"),
    )),
    Rule("Script.Obfuscated", "medium", any_of=(
        C((b"base64_decode", b"gzinflate", b"gzuncompress", b"str_rot13"),
          rb"\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\("),
        C(b"atob", rb"\beval\s*\(\s*atob\s*\("),
        C((b"b64decode", b"decompress", b"marshal", b"fromhex"),
          rb"\bexec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)\s*\("),
        C(b"base64string", rb"from(base64string)\s*\([^\n]{0,500}?(\bi(ex)\b|invoke-(expression))"),
    )),
    Rule("Miner.Crypto", "medium", any_of=(
        C(b"stratum", rb"stratum\+(tcp|ssl|tls)://"),
        C(b"donate-level", rb"--donate-level\s*=?\s*\d"),
    )),
    Rule("VBScript.ShellExec", "low", all_of=(
        C(b"wscript", rb"createobject\s*\(\s*[\"']wscript\.(shell)[\"']\s*\)"),
        C((b".run", b".exec"), rb"\.(run|exec)\s*[\( ]"),
    )),
    Rule("Persistence.Windows", "low", any_of=(
        C(b"currentversion",
          rb"hk(cu|lm|ey_current_user|ey_local_machine)\\software\\microsoft\\windows\\currentversion\\(run|runonce)\b"),
        C(b"schtasks", rb"schtasks(\.exe)?\s+/create\s[^\n]{0,300}/sc\s+(onlogon|onstart|minute)"),
    )),
    Rule("Persistence.Unix", "low", any_of=(
        C(b"cron", rb"(crontab\s|/etc/cron\.)[^\n]{0,200}\b(curl|wget)\s"),
        C(b"runatload", rb"<key>\s*runatload\s*</key>\s*<true\s*/>.{0,2000}?(/tmp/|/private/tmp/|/users/shared/|curl\s)", S),
    )),
    Rule("MacOS.PasswordPrompt", "medium", any_of=(
        C(b"hidden answer", rb"display\s+dialog[^\n]{0,400}hidden\s+answer\s+true"),
    )),
    Rule("Stealer.BrowserOrWallet", "low", all_of=(
        # partial keywords so this file (and its .pyc) don't match the rule
        C((b"login", b"cookies", b"wallet", b"local"),
          rb"(login\s?data|cookies\.sqlite|logins\.json|wallet\.dat|local\s+state)"),
        C((b"webhook", b"telegram", b"ftp:"),
          rb"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|\bftp://)"),
    )),
)


def _texts(data: bytes) -> bytes:
    data = data[:TEXT_LIMIT]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):  # UTF-16 with BOM (scripts saved on Windows)
        try:
            return data.decode("utf-16").encode("utf-8", "replace").lower()
        except UnicodeDecodeError:
            pass
    if b"\x00" in data:
        wide = b"\n".join(m.replace(b"\x00", b"") for m in _WIDE.findall(data))
        if wide:
            data = data + b"\n" + wide
    return data.lower()


def analyze(data: bytes) -> list[Finding]:
    if not data:
        return []
    text = _texts(data)
    return [Finding(rule.name, rule.severity) for rule in RULES if rule.matches(text)]
