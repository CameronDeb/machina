"""Regexes and filters used to discover identities inside file contents."""
import re

# Windows / unix home folders: the folder name is a user identity
USER_DIR8 = re.compile(
    rb"(?i)(?:[a-z]:[\\/]+(?:users|documents and settings|docume~1|dokumente und einstellungen)[\\/]+|"
    rb"/home/|/users/)([^\\/:*?\"<>|\x00-\x1f%$]{2,40}?)(?=[\\/])"
)
USER_DIR16 = re.compile(
    rb"(?i)(?:[a-z]\x00:\x00(?:[\\/]\x00)+(?:u\x00s\x00e\x00r\x00s\x00|d\x00o\x00c\x00u\x00m\x00e\x00~\x001\x00|"
    rb"d\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00s\x00 \x00a\x00n\x00d\x00 \x00s\x00e\x00t\x00t\x00i\x00n\x00g\x00s\x00)"
    rb"(?:[\\/]\x00)+)((?:[^\\/:*?\"<>|\x00-\x1f%$]\x00){2,40}?)(?=[\\/]\x00)"
)
EMAIL8 = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,12}")
EMAIL16 = re.compile(
    rb"(?:[A-Za-z0-9._%+-]\x00){1,64}@\x00(?:[A-Za-z0-9-]\x00){1,63}(?:\.\x00(?:[A-Za-z0-9-]\x00){1,63})*"
)

GENERIC_USERS = {
    "public", "default", "default user", "all users", "administrator", "admin", "user", "users", "owner",
    "localservice", "networkservice", "username", "user name", "your_name", "yourname", "name", "guest",
    "appdata", "desktop", "documents", "shared", "defaultapppool", "runner", "builder", "build",
    "root", "ubuntu", "pi", "vagrant", "docker", "jenkins", "travis", "circleci", "share", "lib", "bin",
    "local", "src", "opt", "home", "tmp", "temp", "x", "me", "you", "operator", "language",
    "admini~1", "admini~2", "defaul~1", "alluse~1", "public~1", "student", "students", "pc", "dell", "hp",
}

GENERIC_VALUES = {
    "china", "usa", "germany", "japan", "india", "france", "italy", "spain", "uk", "biology", "physics",
    "engineering", "mechanical", "student", "students", "teacher", "operator", "personal", "private",
    "home", "office", "lab", "laboratory", "workshop", "design", "cad", "drafting", "standard",
    "", "-", "--", "n/a", "na", "none", "null", "unknown", "unspecified", "anonymous", "user", "admin",
    "administrator", "owner", "author", "designer", "default", "test", "tbd", "x", "xx", "xxx", "?",
    "$", "*", "name", "your name", "company", "company name", "organization", "organisation",
    "draftsman", "engineer", "drawn", "checked", "approved", "0", "1",
}

SOFTWARE = {
    "microsoft", "microsoft corporation", "windows user", "solidworks", "dassault systemes",
    "dassault systèmes", "autodesk", "autodesk, inc.", "ptc", "siemens", "freecad", "onshape",
    "spatial", "open cascade", "opencascade", "adobe", "hp", "hp inc.", "dell", "lenovo", "acer",
    "asus", "pc", "home",
}

EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", "icloud.com",
    "me.com", "aol.com", "gmx.de", "gmx.net", "web.de", "qq.com", "163.com", "126.com", "protonmail.com",
    "proton.me", "mail.ru", "yandex.ru", "msn.com", "example.com", "example.org", "users.noreply.github.com",
}

# email-like strings that are really format tokens
EMAIL_FALSE = re.compile(rb"(?i)@(?:\d|2x\.|3x\.|media\.|import|charset|font-face|page)")


def clean_value(v):
    v = v.strip().strip("\x00").strip()
    return v


DOMAIN_USER = re.compile(r"^\s*([^\\/\s]+)\\([^()]+?)\s*\(([^()]+)\)\s*$")


def split_saved_by(v):
    """'DOMAIN\\user (MACHINE)' -> [DOMAIN, user, MACHINE]."""
    m = DOMAIN_USER.match(v)
    if not m:
        return []
    return [x.strip() for x in m.groups() if x.strip()]


def is_generic(v):
    t = v.strip().lower()
    if t in GENERIC_VALUES or t in SOFTWARE:
        return True
    if not any(c.isalpha() for c in t):
        return True
    return False


def strong(v):
    """Worth replacing everywhere (not just in the field it came from)."""
    t = v.strip()
    if is_generic(t):
        return False
    letters = sum(c.isalpha() for c in t)
    if not t.isascii():
        return letters >= 2
    return letters >= 4 and len(t) >= 5


def find_users(data):
    out = set()
    for m in USER_DIR8.finditer(data):
        out.add(m.group(1).decode("utf-8", "replace"))
    if b"\x00" in data:
        for m in USER_DIR16.finditer(data):
            out.add(m.group(1).decode("utf-16-le", "replace"))
    return {u.strip() for u in out if u.strip() and u.strip().lower() not in GENERIC_USERS and not u.strip().startswith(".")}


def _email_windows(data):
    i = data.find(b"@")
    last = -1
    while i >= 0:
        a = max(i - 70, last)
        yield data[a:i + 260]
        last = i + 260
        i = data.find(b"@", i + 1)
        if i >= 0 and i < last:
            i = data.find(b"@", last)


def find_emails(data):
    out = set()
    if b"@" not in data:
        return out
    for win in _email_windows(data):
        for m in EMAIL8.finditer(win):
            s = m.group(0)
            if EMAIL_FALSE.search(s):
                continue
            out.add(s.decode("ascii", "replace"))
    if b"@\x00" in data:
        for m in EMAIL16.finditer(data):
            out.add(m.group(0).decode("utf-16-le", "replace"))
    good = set()
    for e in out:
        e = e.strip(".")
        local, _, dom = e.partition("@")
        if "." not in dom or len(local) < 2:
            continue
        labels = dom.split(".")
        tld = labels[-1]
        if tld != tld.lower() or tld not in TLDS or len(labels[0]) < 2:
            continue
        if e.lower() in ("example@email.com", "name@example.com", "user@example.com", "your@email.com"):
            continue
        good.add(e)
    return good


TLDS = set("""com org net edu gov mil int de uk fr it es nl jp cn ch at eu us ca au co ac mx ar tr in io ru br
kr se no dk fi pl cz be pt gr il sg hk tw nz za ie hu ro sk si hr info biz me tv cc ai app dev tech xyz lu ee
lt lv ua by kz th my id ph vn sa ae ir pk bd eg ng ke cl pe ve uy ec bo is""".split())


# property / field names that hold a person or organisation
PEOPLE_FIELD = re.compile(
    r"(?i)^\s*(author|authors|sw-author|sw-last saved by|last ?saved ?by|last ?modified ?by|lastauthor|creator|"
    r"created ?by|createdby|drawn|drawn ?by|drawnby|draftsman|drafter|designer|designed ?by|engineer|"
    r"checked|checked ?by|checker|approved|approved ?by|approver|reviewed ?by|reviewer|modified ?by|"
    r"manager|company|organization|organisation|department|customer|client|contact|e-?mail|phone|"
    r"telephone|tel|fax|address|owner|responsible|zeichner|gezeichnet|gepr[uü]ft|bearbeiter|"
    r"konstrukteur|ersteller|firma|norm|dessinateur|dessin[eé] par|auteur|v[eé]rifi[eé]|autor|"
    r"dibujado|dibujó|revisado|aprobado|disegnato|controllato|approvato|projeto|desenhista|"
    r"mfg ?appr|eng ?appr|qa|cad ?operator|operator|student|student name|teacher|instructor|"
    r"made ?by|prepared ?by|issued ?by|vendor|supplier|manufacturer|copyright|rights|designer name|"
    r"authority|cost center|project ?manager|engineer name)\s*:?\s*$"
)
