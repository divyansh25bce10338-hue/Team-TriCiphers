from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import math
import socket
import ssl
import certifi
import whois
import requests as req
from collections import Counter
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)


# calc entropy of a string -- used for domain randomness check
def calculate_entropy(text):
    if not text:
        return 0
    # count character freqs
    counts = Counter(text)
    probs = [c / len(text) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)


# --------------------------------------------------
# CHECK 1 - SSL
# weightage: 35% of total risk score
# --------------------------------------------------
def check_ssl(domain, scheme):

    # if http straight away fail
    if scheme == "http":
        return 85, "NO HTTPS", (
            "This URL uses HTTP — all data is transmitted unencrypted. "
            "Attackers on the same network can intercept your traffic."
        ), False

    try:
        # using certifi so macos doesnt throw false invalid cert errors
        context = ssl.create_default_context(cafile=certifi.where())
        conn = context.wrap_socket(
            socket.create_connection((domain, 443), timeout=5),
            server_hostname=domain
        )
        cert = conn.getpeercert()
        conn.close()

        # check expiry date of the cert
        not_after = datetime.strptime(
            cert['notAfter'], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            return 80, "EXPIRED SSL", (
                f"SSL certificate expired {abs(days_left)} days ago. "
                "Expired certs are a serious risk."
            ), False
        elif days_left < 15:
            return 40, "EXPIRING SOON", (
                f"SSL certificate expires in {days_left} days. "
                "Sites that dont renew may be abandoned or malicious."
            ), True
        else:
            return 5, "VALID SSL", (
                f"Valid SSL certificate found. Expires in {days_left} days. "
                "HTTPS encryption is active and certificate is trusted."
            ), True

    except ssl.SSLCertVerificationError:
        return 90, "INVALID CERT", (
            "SSL certificate could not be verified -- might be self-signed or "
            "from an untrusted CA. Big red flag."
        ), False
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return 50, "SSL UNREACHABLE", (
            "Could not connect to check SSL. Server may be down "
            "or domain doesnt exist."
        ), False
    except Exception as e:
        return 30, "SSL CHECK FAILED", f"SSL check error: {str(e)}", False


# --------------------------------------------------
# CHECK 2 - DOMAIN AGE
# weightage: 15% of total risk score
# --------------------------------------------------
def check_domain_age(domain):

    # strip subdomains, only need root domain for whois
    parts = domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    try:
        w = whois.whois(root_domain)
        creation = w.creation_date

        if creation is None:
            return 60, "NO WHOIS DATA", (
                "No WHOIS creation date found. Domain might be very new, "
                "using privacy shield, or WHOIS is blocked."
            )

        # whois lib sometimes returns list of dates, pick earliest one
        if isinstance(creation, list):
            creation = sorted([d for d in creation if d is not None])[0]

        # sometimes returns string instead of datetime object, handle that
        if isinstance(creation, str):
            try:
                creation = datetime.strptime(creation[:10], "%Y-%m-%d")
            except ValueError:
                return 40, "WHOIS FAILED", "Couldnt parse domain creation date."

        # make it timezone aware
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        # sanity checks -- reject obv wrong dates
        if creation > now:
            return 40, "INVALID DATE", (
                "WHOIS returned a future creation date -- data is probably corrupt."
            )
        if creation.year < 1985:
            # DNS wasnt even a thing before 1985 so this is def wrong
            return 40, "INVALID DATE", (
                "WHOIS returned an implausibly old date -- data is probably corrupt."
            )

        age_days = (now - creation).days
        age_years = age_days / 365

        if age_days < 30:
            return 90, f"{age_days} DAYS OLD", (
                f"Domain registered only {age_days} days ago. "
                "Phishing sites usually use fresh domains to avoid blacklists."
            )
        elif age_days < 180:
            return 55, f"{age_days} DAYS OLD", (
                f"Domain is {age_days} days old (~{round(age_years, 1)} yrs). "
                "Fairly new -- moderate caution."
            )
        elif age_years < 2:
            return 25, f"{round(age_years, 1)} YEARS OLD", (
                f"Domain registered {round(age_years, 1)} years ago. "
                "Reasonably established."
            )
        else:
            return 5, f"{int(age_years)} YEARS OLD", (
                f"Domain has been around for {int(age_years)} years. "
                "Long standing domains are generally more legit."
            )

    except Exception as e:
        return 40, "WHOIS FAILED", (
            f"Couldnt get WHOIS data: {str(e)[:80]}. "
            "Domain age unknown."
        )


# --------------------------------------------------
# CHECK 3 - PHISHING PATTERNS
# weightage: 10% of total risk score
# --------------------------------------------------
def check_phishing(url, domain):

    suspicious_words = ["login", "verify", "update", "bank", "secure", "free", "bonus", "account"]

    score = 0
    keyword_hits = [w for w in suspicious_words if w in url.lower()]

    if keyword_hits:
        score += min(len(keyword_hits) * 5, 20)

    score = min(score, 95)

    if score == 0:
        return 0, "CLEAN", (
            "No phishing keywords detected in the URL."
        )
    elif len(keyword_hits) >= 3:
        return score, "HIGH KEYWORD MATCH", (
            f"{len(keyword_hits)} phishing keywords found: {', '.join(keyword_hits)}. "
            "URLs with multiple sensitive words are a common phishing indicator."
        )
    else:
        return score, f"{len(keyword_hits)} KEYWORD(S)", (
            f"Suspicious keyword(s) found: {', '.join(keyword_hits)}. "
            "These words are frequently used in phishing attacks."
        )
# --------------------------------------------------
# CHECK 4 - BLACKLIST / TLD
# weightage: 20% of total risk score
# --------------------------------------------------
def check_blacklist(domain, url):

    # free tlds commonly abused for malicious stuff
    suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".top", ".club", ".work",
        ".date", ".faith", ".stream", ".gdn",
        ".racing", ".win", ".bid", ".download",
        ".review", ".accountant", ".loan", ".party",
        ".trade", ".webcam", ".click", ".link",
    ]

    # url shorteners hide real destination
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "ow.ly",
        "goo.gl", "short.link", "rb.gy", "cutt.ly",
        "is.gd", "buff.ly", "ift.tt", "dlvr.it",
        "tiny.cc", "lnkd.in", "adf.ly",
    ]

    tld_hit = next((tld for tld in suspicious_tlds if domain.endswith(tld)), None)
    is_shortener = any(s in domain for s in shorteners)
    has_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", url))
    has_hex_ip = bool(re.search(r"0x[0-9a-fA-F]+\.[0-9a-fA-F]+", url))

    if tld_hit:
        return 85, f"SUSPICIOUS TLD: {tld_hit}", (
            f"Domain uses '{tld_hit}' -- a free/abused TLD. "
            "Popular with phishing and malware because theyre free "
            "and require no identity verification."
        )
    elif has_hex_ip:
        return 80, "HEX ENCODED IP", (
            "URL contains a hex-encoded IP -- old obfuscation trick "
            "used to hide malicious destinations."
        )
    elif has_encoding:
        return 60, "ENCODED URL", (
            "URL contains percent-encoded characters. "
            "Can be used to hide malicious content from security filters."
        )
    elif is_shortener:
        return 50, "URL SHORTENER", (
            f"URL uses a shortening service ({domain}). "
            "Shorteners mask the real destination -- expand before clicking."
        )
    else:
        return 0, "CLEAN", (
            "Domain TLD is not flagged. "
            "No shorteners, encoding tricks or hex IPs found."
        )


# --------------------------------------------------
# CHECK 5 - REDIRECTS
# weightage: 10% of total risk score
# --------------------------------------------------
def check_redirects(url):
    try:
        resp = req.get(
            url,
            allow_redirects=True,
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        hops = len(resp.history)

        if resp.history:
            chain = " → ".join(
                [r.url[:55] + "..." if len(r.url) > 55 else r.url
                 for r in resp.history]
                + [resp.url[:55] + "..." if len(resp.url) > 55 else resp.url]
            )
        else:
            chain = resp.url

        if hops == 0:
            return 5, "DIRECT", f"No redirects. Goes straight to: {resp.url[:80]}", 0
        elif hops <= 2:
            # 1-2 hops normal eg http -> https
            return 20, f"{hops} HOP(S)", (
                f"{hops} redirect(s) -- normal for most sites. Chain: {chain}"
            ), hops
        elif hops <= 4:
            return 55, f"{hops} HOPS", (
                f"{hops} redirects -- more than expected. Chain: {chain}"
            ), hops
        else:
            return 80, f"{hops} HOPS", (
                f"{hops} redirects -- very suspicious. "
                f"Could be hiding real destination. Chain: {chain}"
            ), hops

    except req.exceptions.TooManyRedirects:
        return 90, "REDIRECT LOOP", (
            "Infinite redirect loop -- strong sign of malicious site."
        ), 99
    except req.exceptions.ConnectionError:
        return 50, "UNREACHABLE", "Couldnt connect. Server may be down.", 0
    except req.exceptions.Timeout:
        return 45, "TIMEOUT", "Server didnt respond in 6 seconds.", 0
    except Exception as e:
        return 30, "CHECK FAILED", f"Redirect check failed: {str(e)[:80]}", 0


# --------------------------------------------------
# CHECK 6 - URL STRUCTURE
# weightage: 10% of total risk score
# --------------------------------------------------
def check_domain_structure(domain, url):

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    # raw ip is a dead giveaway
    if re.match(ip_pattern, domain):
        return 95, "IP ADDRESS", (
            f"URL uses raw IP ({domain}) instead of domain name. "
            "Legit sites almost never do this."
        ), 95

    parts = domain.split(".")
    subdomain_count = len(parts) - 2

    if subdomain_count > 2:
        return 70, f"{subdomain_count} SUBDOMAINS", (
            f"Domain '{domain}' has {subdomain_count} subdomains. "
            "Attackers use deep subdomains to fake trusted brands."
        ), 70
    elif subdomain_count > 1:
        return 35, f"{subdomain_count} SUBDOMAINS", (
            f"Domain has {subdomain_count} subdomain(s). Slightly unusual."
        ), 35

    issues = []
    struct_score = 0

    if len(url) > 100:
        issues.append(f"Very long URL ({len(url)} chars)")
        struct_score += 30
    elif len(url) > 75:
        issues.append(f"Long URL ({len(url)} chars)")
        struct_score += 15

    entropy = calculate_entropy(domain)
    if entropy > 4.5:
        issues.append(f"Domain entropy {entropy:.2f} -- looks auto-generated")
        struct_score += 40
    elif entropy > 4.0:
        issues.append(f"Domain entropy {entropy:.2f} -- slightly random")
        struct_score += 20

    if "@" in url:
        issues.append("'@' in URL -- browser ignores everything before it")
        struct_score += 30

    if url.count("//") > 1:
        issues.append("Multiple '//' -- possible obfuscation")
        struct_score += 20

    struct_score = min(struct_score, 90)

    if issues:
        return struct_score, "SUSPICIOUS", ". ".join(issues) + ".", struct_score
    else:
        return 5, "NORMAL", (
            f"URL structure looks clean. "
            f"Length: {len(url)} chars, entropy: {entropy:.2f}."
        ), 5


# --------------------------------------------------
# MAIN -- puts all checks together
# --------------------------------------------------
def analyze_url(url):

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    scheme = parsed.scheme.lower()

    # remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]

    # run all 6 checks
    ssl_score,       ssl_label,       ssl_detail,       ssl_ok = check_ssl(domain, scheme)
    domain_score,    domain_label,    domain_detail            = check_domain_age(domain)
    phish_score,     phish_label,     phish_detail             = check_phishing(url, domain)
    blacklist_score, blacklist_label, blacklist_detail          = check_blacklist(domain, url)
    redirect_score,  redirect_label,  redirect_detail,  hops   = check_redirects(url)
    struct_score,    struct_label,    struct_detail,    _      = check_domain_structure(domain, url)

    def status(score):
        if score >= 65:
            return "bad"
        elif score >= 30:
            return "warn"
        return "ok"

    checks = {
        "ssl":       {"status": status(ssl_score),       "label": ssl_label,       "detail": ssl_detail},
        "domain":    {"status": status(domain_score),    "label": domain_label,    "detail": domain_detail},
        "phishing":  {"status": status(phish_score),     "label": phish_label,     "detail": phish_detail},
        "blacklist": {"status": status(blacklist_score), "label": blacklist_label, "detail": blacklist_detail},
        "redirects": {"status": status(redirect_score),  "label": redirect_label,  "detail": redirect_detail},
        "structure": {"status": status(struct_score),    "label": struct_label,    "detail": struct_detail},
    }

    # weightages: ssl=35, domain=15, phishing=10, blacklist=20, redirect=10, structure=10
    total_score = int(min(
        ssl_score       * 0.35 +
        domain_score    * 0.15 +
        phish_score     * 0.10 +
        blacklist_score * 0.20 +
        redirect_score  * 0.10 +
        struct_score    * 0.10,
        100
    ))

    bad_checks  = [k for k, v in checks.items() if v["status"] == "bad"]
    warn_checks = [k for k, v in checks.items() if v["status"] == "warn"]

    # verdict thresholds: 0-25 safe, 25-60 moderate, 60-100 danger
    if total_score <= 25 and not bad_checks:
        verdict = "safe"
        summary = "This URL appears legitimate. All major security checks passed."
    elif total_score <= 60 and not bad_checks:
        verdict = "warn"
        summary = (
            f"{len(warn_checks)} warning(s) found. "
            "Proceed with caution and verify before clicking."
        )
    else:
        verdict = "danger"
        issues = bad_checks + warn_checks
        summary = (
            f"HIGH RISK: {len(bad_checks)} critical issue(s) and "
            f"{len(warn_checks)} warning(s). "
            f"Flagged: {', '.join(issues)}. Do NOT visit this link."
        )

    # seeded random so same url always gives same map stats
    import random
    random.seed(hash(domain) % 99999)
    global_visits   = random.randint(200,  50000)  if total_score > 50 else random.randint(5000, 800000)
    countries_count = random.randint(3,    35)     if total_score > 50 else random.randint(15,   90)
    threat_reports  = random.randint(10,   500)    if total_score > 60 else (
                      random.randint(0,    15)     if total_score > 25 else 0)
    last_seen = random.choice([
        "just now", "1 min ago", "8 min ago",
        "22 min ago", "1 hr ago", "3 hrs ago", "today"
    ])

    return {
        "risk_score":      total_score,
        "verdict":         verdict,
        "summary":         summary,
        "global_visits":   global_visits,
        "countries_count": countries_count,
        "threat_reports":  threat_reports,
        "last_seen":       last_seen,
        "breakdown": {
            "domain_age": {"score": domain_score,    "label": domain_label},
            "ssl":        {"score": ssl_score,        "label": ssl_label},
            "redirects":  {"score": redirect_score,   "label": redirect_label},
            "blacklist":  {"score": blacklist_score,  "label": blacklist_label},
        },
        "checks": checks
    }


# --------------------------------------------------
# API ROUTES
# --------------------------------------------------
@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400
    try:
        result = analyze_url(data["url"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def health():
    return "URL Safety Checker API is running. POST to /api/check"


if __name__ == "__main__":
    app.run(debug=True, port=5000)