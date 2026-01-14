#!/usr/bin/env python3
import argparse
import requests
import random
import string
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

requests.packages.urllib3.disable_warnings()

UA = "Reflekt/1.0"
TIMEOUT = 10  # Default timeout

# -------------------------
# Progress Counter
# -------------------------
class Counter:
    def __init__(self, total, progress_every=10):
        self.total = total
        self.current = 0
        self.found = 0
        self.lock = threading.Lock()
        self.progress_every = progress_every

    def update(self, url, found_count=0):
        with self.lock:
            self.current += 1
            self.found += found_count
            # Show progress every N URLs or on first/last
            if self.current == 1 or self.current % self.progress_every == 0 or self.current == self.total:
                sys.stderr.write(f"\r[{self.current}/{self.total}] Found: {self.found}")
                sys.stderr.flush()

    def finish(self):
        sys.stderr.write(f"\r[{self.current}/{self.total}] Total findings: {self.found}\n")
        sys.stderr.flush()

counter = None

# -------------------------
# Canary (NO underscore)
# -------------------------
def gen_canary(i):
    rand = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    return f"buggedout{i}{rand}"

# -------------------------
# Args
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Reflekt - Smart Reflected XSS Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reflekt.py -u "http://target.com/page?id=1"
  reflekt.py -l urls.txt -t 10 -o results.txt
  reflekt.py -l urls.txt --timeout 20 -t 5
        """
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="Single URL")
    g.add_argument("-l", "--list", help="File with URLs")
    p.add_argument("-o", "--output", help="Output file for results")
    p.add_argument("-t", "--threads", type=int, default=1, help="Number of concurrent threads (default: 1)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    return p.parse_args()

# -------------------------
# Output handling
# -------------------------
output_file = None
output_lock = threading.Lock()

def output(line):
    """Print to stdout and optionally write to file (thread-safe)"""
    with output_lock:
        print(line)
        if output_file:
            try:
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass

# -------------------------
# Load targets
# -------------------------
def load_targets(args):
    if args.url:
        return [args.url.strip()]
    with open(args.list, "r", encoding="utf-8", errors="ignore") as f:
        return [x.strip() for x in f if x.strip()]

# -------------------------
# Inject canaries
# -------------------------
def inject_canaries(url):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)

    if not qs:
        return None, None

    cmap = {}
    new_qs = {}

    for i, param in enumerate(qs, 1):
        c = gen_canary(i)
        cmap[param] = c
        new_qs[param] = c

    q = urlencode(new_qs, doseq=True)
    return urlunparse(p._replace(query=q)), cmap

# -------------------------
# HTTP
# -------------------------
def fetch(url):
    try:
        r = requests.get(
            url,
            headers={"User-Agent": UA},
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        return r.text
    except Exception:
        return None

# -------------------------
# Find reflections
# -------------------------
def find_reflections(html, cmap):
    refs = []
    for param, canary in cmap.items():
        for m in re.finditer(re.escape(canary), html):
            refs.append({
                "param": param,
                "canary": canary,
                "pos": m.start()
            })
    return refs

# -------------------------
# Check for special DOM sink attributes
# -------------------------
def check_dom_sinks(html, pos, canary):
    """Check for DOM XSS patterns like data-* → innerHTML, srcdoc, href javascript:, etc."""
    before = html[:pos]

    # Check if in srcdoc attribute (decodes HTML entities)
    srcdoc_match = re.search(r'<iframe[^>]*\ssrcdoc\s*=\s*["\'][^"\']*$', before, re.IGNORECASE)
    if srcdoc_match:
        return {"type": "srcdoc", "note": "entities decoded"}

    # Check if in data-* attribute that feeds innerHTML
    data_attr_match = re.search(r'<[^>]+\sdata-\w+\s*=\s*["\'][^"\']*$', before, re.IGNORECASE)
    if data_attr_match:
        # Check if innerHTML/dataset pattern exists in page
        if re.search(r'innerHTML\s*=.*dataset', html, re.IGNORECASE):
            return {"type": "dom_sink", "note": "innerHTML+dataset"}

    return None

# -------------------------
# Context detection (ROBUST)
# -------------------------
def detect_context(html, pos):
    before = html[:pos]

    # ---- CHECK DOM SINKS FIRST ----
    # (These are special cases that override normal context)

    # ---- SCRIPT ----
    if before.rfind("<script") > before.rfind("</script>"):
        # Find the quote that actually encloses this value
        # Look backwards from canary position to find opening quote
        script_start = before.rfind("<script")
        script_content = before[script_start:pos]

        # Find last unmatched quote before canary
        last_single = script_content.rfind("'")
        last_double = script_content.rfind('"')
        last_backtick = script_content.rfind('`')

        # The quote closest to canary (and unclosed) is likely the one wrapping it
        quotes = [(last_single, "'"), (last_double, '"'), (last_backtick, '`')]
        quotes = [(p, q) for p, q in quotes if p != -1]

        if quotes:
            # Get the quote type that appears last (closest to canary)
            closest = max(quotes, key=lambda x: x[0])
            q = closest[1]
        else:
            q = "raw"
        return {"type": "script", "quote": q}

    # ---- HTML COMMENT ----
    # Check if inside <!-- ... -->
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open != -1 and last_comment_open > last_comment_close:
        return {"type": "comment"}

    # ---- ATTRIBUTE ----
    tag_start = before.rfind("<")
    if tag_start != -1:
        chunk = before[tag_start:pos+1]

        # Must have valid tag name after <, not just any <
        # Avoid false positives from <pre> containing text with quotes
        if not re.match(r'<[a-zA-Z][a-zA-Z0-9]*\s', chunk):
            # Not a valid tag with attributes, skip attribute detection
            pass
        else:
            # Check for attribute patterns: must have = before the opening quote
            # Look for pattern like: attr="value or attr='value
            if chunk.count('"') % 2 == 1:
                # Verify there's an = before the last unmatched "
                last_quote = chunk.rfind('"')
                before_quote = chunk[:last_quote]
                if re.search(r'=\s*$', before_quote):
                    return {"type": "attribute", "quote": '"'}

            if chunk.count("'") % 2 == 1:
                # Verify there's an = before the last unmatched '
                last_quote = chunk.rfind("'")
                before_quote = chunk[:last_quote]
                if re.search(r'=\s*$', before_quote):
                    return {"type": "attribute", "quote": "'"}

            if re.search(r'=\s*[^"\'>\s]+$', chunk):
                return {"type": "attribute", "quote": "unquoted"}

    # ---- HTML BODY ----
    return {"type": "html"}

# -------------------------
# Build minimal probe + verification pattern
# -------------------------
def build_probe(canary, ctx):
    # Add suffix after special char to avoid false positives from HTML tags
    suffix = "x7"

    if ctx["type"] == "attribute":
        if ctx["quote"] == '"':
            # Probe: canary"x7
            # Verify: look for "x7 followed by space or attribute char (proves quote broke out)
            return canary + '"' + suffix, rf'{re.escape(canary)}"{suffix}\s*\w*='
        if ctx["quote"] == "'":
            return canary + "'" + suffix, rf"{re.escape(canary)}'{suffix}\s*\w*="
        # Unquoted attribute - > closes tag
        return canary + ">" + suffix, rf'{re.escape(canary)}>{suffix}'

    if ctx["type"] == "html":
        # For HTML body, verify < creates a tag-like structure
        return canary + "<" + suffix, rf'{re.escape(canary)}<{suffix}'

    if ctx["type"] == "script":
        q = ctx["quote"]
        if q in ['"', "'", "`"]:
            # For JS strings: need quote to break + // to comment rest
            # Probe: canary';//x7  (quote + semicolon + comment + suffix)
            return f"{canary}{q};//{suffix}", None
        # Raw JS context (not in string)
        return f"{canary};//{suffix}", None

    if ctx["type"] == "script_html":
        # Fallback: try closing tag to break out via HTML
        # Use </canary> instead of </script> to bypass WAF
        # If </canary> passes, </script> likely works too
        return f"{canary}</{canary}><{suffix}", None

    if ctx["type"] == "comment":
        # HTML comments are not exploitable - skip
        return None, None

    if ctx["type"] == "srcdoc":
        # srcdoc decodes HTML entities - test with encoded payload
        # Even if < is encoded to &lt;, it will be decoded in srcdoc
        return canary + "<" + suffix, None

    if ctx["type"] == "dom_sink":
        # DOM sink like innerHTML - entities get decoded
        return canary + "<" + suffix, None

    return None, None

# -------------------------
# Send probe
# -------------------------
def send_probe(base_url, param, probe):
    p = urlparse(base_url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = probe
    q = urlencode(qs, doseq=True)
    test_url = urlunparse(p._replace(query=q))
    return test_url, fetch(test_url)

# -------------------------
# Verify probe in correct context
# -------------------------
def verify_probe(test_html, probe, ctx):
    """Verify probe appears in the expected context, not just anywhere."""
    if ctx["type"] == "attribute":
        # For attribute breakout, verify the quote actually closed the attribute
        # Must check that quote is NOT HTML encoded (&#039; &#34; &quot; &apos;)
        if ctx["quote"] == '"':
            # Check probe followed by literal " (not &quot; or &#34;)
            pattern = rf'{re.escape(probe)}"'
            if not re.search(pattern, test_html):
                return False
            # Verify it's not HTML encoded - check probe is not followed by encoded quote
            encoded_pattern = rf'{re.escape(probe)}(&quot;|&#34;|&#x22;)'
            if re.search(encoded_pattern, test_html, re.IGNORECASE):
                return False
            return True
        if ctx["quote"] == "'":
            pattern = rf"{re.escape(probe)}'"
            if not re.search(pattern, test_html):
                return False
            # Verify not HTML encoded
            encoded_pattern = rf"{re.escape(probe)}(&apos;|&#39;|&#x27;)"
            if re.search(encoded_pattern, test_html, re.IGNORECASE):
                return False
            return True
        # Unquoted: check probe followed by > or space
        pattern = rf'{re.escape(probe)}[\s>]'
        return bool(re.search(pattern, test_html))

    if ctx["type"] == "html":
        # For HTML injection, verify the < appears in HTML body, not inside script
        if probe not in test_html:
            return False
        # Make sure probe is NOT only inside script blocks
        # Remove all script blocks and check if probe still exists
        html_without_scripts = re.sub(r'<script[^>]*>.*?</script>', '', test_html, flags=re.DOTALL | re.IGNORECASE)
        return probe in html_without_scripts

    if ctx["type"] == "script":
        # Verify quote + ;// passed through AND quote is not escaped in script
        # False positive: script has \' but HTML body has ' unescaped
        if probe not in test_html:
            return False

        q = ctx.get("quote", "'")
        escaped_probe = probe.replace(q, "\\" + q)

        # Extract all script blocks and check if UNESCAPED probe is inside any
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', test_html, re.DOTALL | re.IGNORECASE)

        for block in script_blocks:
            # Check if unescaped probe is in this script block
            if probe in block:
                # Also verify escaped version is NOT in this same block
                # (if escaped version is there, the quote was escaped)
                if escaped_probe not in block:
                    return True

        # Probe not found unescaped in any script block
        return False

    if ctx["type"] == "srcdoc":
        # srcdoc decodes entities - check if our payload (or its encoded form) is in srcdoc
        # The canary<x7 might appear as canary&lt;x7 in the HTML but will decode in browser
        encoded_probe = probe.replace("<", "&lt;").replace(">", "&gt;")
        # Check if srcdoc contains our probe (encoded or raw)
        srcdoc_match = re.search(r'srcdoc\s*=\s*["\']([^"\']*)["\']', test_html, re.IGNORECASE)
        if srcdoc_match:
            srcdoc_content = srcdoc_match.group(1)
            if probe in srcdoc_content or encoded_probe in srcdoc_content:
                return True
        return False

    if ctx["type"] == "dom_sink":
        # DOM sink - entities get decoded by innerHTML
        # Check if probe (or encoded) is in a data-* attribute
        encoded_probe = probe.replace("<", "&lt;").replace(">", "&gt;")
        data_match = re.search(r'data-\w+\s*=\s*["\']([^"\']*)["\']', test_html, re.IGNORECASE)
        if data_match:
            data_content = data_match.group(1)
            if probe in data_content or encoded_probe in data_content:
                return True
        return False

    return False

# -------------------------
# Scan
# -------------------------
def scan(url):
    global counter
    findings = 0

    injected, cmap = inject_canaries(url)
    if not injected:
        if counter:
            counter.update(url, 0)
        return

    html = fetch(injected)
    if not html:
        if counter:
            counter.update(url, 0)
        return

    refs = find_reflections(html, cmap)

    # Track reported to avoid duplicates (by param + context type)
    reported = set()

    for r in refs:
        # Check for DOM sinks first (srcdoc, innerHTML+dataset)
        dom_sink = check_dom_sinks(html, r["pos"], r["canary"])
        if dom_sink:
            ctx = dom_sink
        else:
            ctx = detect_context(html, r["pos"])

        result = build_probe(r["canary"], ctx)
        if not result or not result[0]:
            continue

        probe = result[0]

        # Dedup key: param + context type + quote
        key = (r["param"], ctx["type"], ctx.get("quote", ""))
        if key in reported:
            continue

        test_url, test_html = send_probe(injected, r["param"], probe)
        if not test_html:
            continue

        # Use context-aware verification
        if verify_probe(test_html, probe, ctx):
            reported.add(key)
            findings += 1
            # Format: URL | param | context
            ctx_str = ctx["type"]
            if "quote" in ctx:
                ctx_str += f"({ctx['quote']})"
            output(f"{test_url} | {r['param']} | {ctx_str}")
        elif ctx["type"] == "script":
            # Fallback: if script quote probe failed, try </script> HTML breakout
            # First test with </canary> to check if tag-like content passes (WAF bypass test)
            fallback_ctx = {"type": "script_html"}
            fallback_result = build_probe(r["canary"], fallback_ctx)
            if fallback_result and fallback_result[0]:
                fallback_probe = fallback_result[0]
                fallback_url, fallback_html = send_probe(injected, r["param"], fallback_probe)
                if fallback_html and fallback_probe in fallback_html:
                    # Now verify </script> actually terminates the script
                    # Test with </script><suffix to see if it breaks out
                    verify_probe_val = f"{r['canary']}</script><x7"
                    verify_url, verify_html = send_probe(injected, r["param"], verify_probe_val)
                    if verify_html:
                        # Check if <x7 appears OUTSIDE script blocks after injection
                        # If </script> worked, the <x7 won't be inside any script
                        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', verify_html, re.DOTALL | re.IGNORECASE)
                        x7_in_script = any("<x7" in block for block in script_blocks)
                        if not x7_in_script and "<x7" in verify_html:
                            # <x7 is in HTML body, meaning </script> broke out
                            reported.add((r["param"], "script_html", ""))
                            findings += 1
                            output(f"{verify_url} | {r['param']} | script(</tag>)")

    # Update counter after scanning this URL
    if counter:
        counter.update(url, findings)

# -------------------------
# Main
# -------------------------
def main():
    global counter, output_file, TIMEOUT
    args = parse_args()
    targets = load_targets(args)

    # Set timeout
    TIMEOUT = args.timeout

    # Initialize output file
    if args.output:
        output_file = args.output
        # Clear file at start
        with open(output_file, "w", encoding="utf-8") as f:
            pass

    # Initialize counter
    counter = Counter(len(targets))

    # Run with threads
    threads = max(1, args.threads)
    if threads == 1:
        for target in targets:
            scan(target)
    else:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan, target): target for target in targets}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    # Show final stats
    counter.finish()

    if output_file:
        sys.stderr.write(f"Results saved to: {output_file}\n")

if __name__ == "__main__":
    main()
