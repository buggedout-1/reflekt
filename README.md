<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:ff6b6b,100:845ef7&height=220&section=header&text=Reflekt&fontSize=80&fontColor=ffffff&fontAlignY=35&desc=Smart%20Reflected%20XSS%20Scanner&descSize=20&descAlignY=55&animation=fadeIn" width="100%"/>

<br/>

<img src="https://img.shields.io/badge/python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/license-MIT-00C853?style=for-the-badge" />
<img src="https://img.shields.io/badge/version-1.0-FF6D00?style=for-the-badge" />
<img src="https://img.shields.io/badge/XSS-Context--Aware-E91E63?style=for-the-badge&logo=hackthebox&logoColor=white" />

<br/><br/>

> **Reflekt** doesn't just find reflections — it understands **where** your input lands<br/>and verifies if it's actually **exploitable**.

<br/>

[Features](#-features) | [Install](#-installation) | [Usage](#-usage) | [How It Works](#-how-it-works) | [Output](#-output-format) | [Workflow](#-recommended-workflow)

<br/>

```
  ____       __ _      _    _
 |  _ \ ___ / _| | ___| | _| |_
 | |_) / _ \ |_| |/ _ \ |/ / __|
 |  _ <  __/  _| |  __/   <| |_
 |_| \_\___|_| |_|\___|_|\_\\__|

   Context-Aware XSS Detection
```

</div>

---

## Why Reflekt?

Most XSS scanners spray payloads like `<script>alert(1)</script>` and grep the response. This triggers WAFs, generates noise, and misses context-specific vulnerabilities.

**Reflekt takes a different approach:**

```
Traditional Scanner                    Reflekt

  Inject payload -----> Grep          Inject canary -----> Find reflection
       |                  |                |                     |
       v                  v                v                     v
  "Found XSS!"     90% false pos     Detect context        Build smart probe
                                           |                     |
                                           v                     v
                                      Attribute? Script?    Send & verify
                                      HTML? DOM sink?       in correct context
                                           |                     |
                                           v                     v
                                      Craft minimal        Confirmed. Zero noise.
                                      context probe
```

---

## Features

<table>
<tr>
<td width="50%">

### Detection
- **6 reflection contexts** detected automatically
- **Quote-aware** — single, double, backtick, unquoted
- **DOM sink detection** — srcdoc, innerHTML+dataset
- **HTML comment filtering** — skips non-exploitable contexts
- **Content-Type filtering** — skips JSON/XML/text responses

</td>
<td width="50%">

### Performance
- **Thread-local connection pooling** — TLS sessions reused
- **Multi-threaded** — scales to 50+ concurrent threads
- **Smart deduplication** — one report per param+context
- **Minimal probes** — no bulky payloads, no WAF triggers
- **Streaming progress** — real-time stderr updates

</td>
</tr>
</table>

---

## Installation

```bash
git clone https://github.com/yourusername/reflekt.git
cd reflekt
pip install requests
```

That's it. Pure Python 3.8+, single dependency.

---

## Usage

### Single URL
```bash
python3 reflekt.py -u "https://target.com/search?q=test&lang=en"
```

### Scan URL List
```bash
python3 reflekt.py -l urls.txt -t 50 -o results.txt
```

### All Options

```
Usage: reflekt.py [-u URL | -l FILE] [options]

Required (one of):
  -u, --url       Single URL to scan
  -l, --list      File containing URLs (one per line)

Options:
  -t, --threads   Number of concurrent threads    [default: 1]
  -o, --output    Save results to file
  --timeout       Request timeout in seconds       [default: 10]
```

### Examples

```bash
# Quick single target
python3 reflekt.py -u "https://example.com/page?id=1&name=test"

# Large list with 50 threads
python3 reflekt.py -l parameterized_urls.txt -t 50 -o findings.txt

# Slow targets — longer timeout, fewer threads
python3 reflekt.py -l urls.txt -t 10 --timeout 20 -o results.txt

# Pipe results cleanly (progress on stderr, results on stdout)
python3 reflekt.py -l urls.txt -t 50 2>/dev/null > results.txt
```

---

## How It Works

<div align="center">

```
         +---------------------+
         |    Target URL        |
         |  ?id=1&name=foo      |
         +---------+-----------+
                   |
         +---------v-----------+
         |   Inject Canaries    |
         |  id=buggedout1AbC    |
         |  name=buggedout2xYz  |
         +---------+-----------+
                   |
         +---------v-----------+
         |   Fetch Response     |
         |  (TLS session reuse) |
         +---------+-----------+
                   |
         +---------v-----------+
         |  Find Reflections    |
         |  Where did canary    |
         |  land in the HTML?   |
         +---------+-----------+
                   |
     +-------------+-------------+
     |             |             |
+----v----+  +----v----+  +----v----+
|  HTML   |  |  Attr   |  | Script  |
| <p>..   |  | value=" |  | var x=' |
| Probe:  |  | Probe:  |  | Probe:  |
|   <x7   |  |   "x7   |  |  ';//x7 |
+----+----+  +----+----+  +----+----+
     |             |             |
     +-------------+-------------+
                   |
         +---------v-----------+
         |   Send Probe &       |
         |   Verify Context     |
         |                      |
         |  - Quote not encoded?|
         |  - Not escaped?      |
         |  - Correct context?  |
         +---------+-----------+
                   |
         +---------v-----------+
         |   Confirmed XSS      |
         +---------------------+
```

</div>

### Step 1: Canary Injection

Each parameter gets a unique canary — a random string that won't appear naturally in the page:

```
Original:  ?name=john&role=admin
Injected:  ?name=buggedout1kQ9m&role=buggedout2pX7z
```

### Step 2: Context Detection

Reflekt analyzes the HTML structure around each reflected canary:

| Context | What It Looks Like | Probe Sent |
|---------|-------------------|------------|
| **HTML Body** | `<div>CANARY</div>` | `canary<x7` |
| **Attribute `"`** | `<input value="CANARY">` | `canary"x7` |
| **Attribute `'`** | `<input value='CANARY'>` | `canary'x7` |
| **Attribute unquoted** | `<input value=CANARY>` | `canary>x7` |
| **Script `'`** | `var x = 'CANARY';` | `canary';//x7` |
| **Script `"`** | `var x = "CANARY";` | `canary";//x7` |
| **Script `` ` ``** | `` var x = `CANARY`; `` | `` canary`;//x7 `` |
| **Script raw** | `var x = CANARY;` | `canary;//x7` |

### Step 3: Context-Aware Verification

This is what makes Reflekt different. It doesn't just check "is my string in the response?" — it verifies exploitability:

```
Attribute Breakout:
  Probe:   buggedout1abc"x7
  Check 1: Is " literal? (not &quot; or &#34; or &#x22;)
  Check 2: Does it break the attribute context?
  Result:  CONFIRMED only if both pass

Script Breakout:
  Probe:   buggedout1abc';//x7
  Check 1: Is ' inside a <script> block?
  Check 2: Is ' NOT escaped as \' ?
  Check 3: If fail -> try </script> tag breakout (fallback)
  Result:  CONFIRMED only if unescaped in script context

HTML Injection:
  Probe:   buggedout1abc<x7
  Check 1: Does < appear in response?
  Check 2: Is it OUTSIDE <script> blocks? (not just in JS string)
  Result:  CONFIRMED only if injectable in HTML body
```

### Advanced Detection

| Context | Detection | Why It Matters |
|---------|-----------|---------------|
| **HTML Comment** | `<!-- CANARY -->` | **Skipped** — not exploitable |
| **srcdoc** | `<iframe srcdoc="CANARY">` | HTML entities get decoded by browser |
| **DOM Sink** | `data-x="CANARY"` + `innerHTML=dataset.x` | JS decodes entities at runtime |
| **Script tag breakout** | Fallback when JS quote escape fails | `</script><img onerror=...>` |

---

## Output Format

```
URL | parameter | context
```

### Example Results

```
https://target.com/search?q=buggedout1abc%22x7       | q    | attribute(")
https://target.com/page?name=buggedout1abc%3Cx7       | name | html
https://target.com/app?data=buggedout1abc%27%3B//x7   | data | script(')
https://target.com/view?msg=...%3C/script%3E%3Cx7     | msg  | script(</tag>)
```

### Context Types Reference

| Output | Meaning | Exploitability |
|--------|---------|---------------|
| `html` | HTML body — tag injection works | `<img onerror=...>` |
| `attribute(")` | Double-quoted attribute breakout | `" onfocus=... autofocus="` |
| `attribute(')` | Single-quoted attribute breakout | `' onfocus=... autofocus='` |
| `attribute(unquoted)` | Unquoted attribute | `onfocus=... ` |
| `script(')` | JS single-quoted string breakout | `';alert();//` |
| `script(")` | JS double-quoted string breakout | `";alert();//` |
| `script(`)` | JS template literal breakout | `` `;alert();// `` |
| `script(</tag>)` | Script tag closure | `</script><img onerror=...>` |
| `srcdoc` | iframe srcdoc injection | Entity-decoded HTML |
| `dom_sink` | innerHTML via dataset | Entity-decoded DOM XSS |

---

## Recommended Workflow

```bash
# 1. Collect parameterized URLs
katana -u https://target.com -d 3 -f qurl | tee all_urls.txt
waybackurls target.com | grep "=" >> all_urls.txt

# 2. Deduplicate
sort -u all_urls.txt > unique_urls.txt

# 3. Scan with Reflekt
python3 reflekt.py -l unique_urls.txt -t 50 -o xss_results.txt

# 4. Review confirmed findings
cat xss_results.txt
```

---

## Performance Notes

| Feature | Benefit |
|---------|---------|
| **TLS Session Reuse** | Thread-local connection pools — no redundant handshakes |
| **Content-Type Filter** | Skips JSON, XML, plain text (XSS not possible) |
| **Smart Dedup** | One probe per param+context combo, not per reflection |
| **Minimal Probes** | 1-3 char probes instead of full payloads — faster, stealthier |

---

## Contributing

Pull requests welcome! For major changes, please open an issue first.

## License

MIT License — free to use in your security assessments.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:ff6b6b,100:845ef7&height=120&section=footer" width="100%"/>

**Smart scanning beats payload spraying.**

</div>







