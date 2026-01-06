<p align="center">
  <img src="https://img.shields.io/badge/python-3.7+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/version-1.0-orange.svg" alt="Version">
</p>

<h1 align="center">
  <br>
  Reflekt
  <br>
</h1>

<h4 align="center">Smart Reflected XSS Scanner with Zero False Positives</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#output">Output</a>
</p>

---

## Overview

**Reflekt** is an intelligent reflected XSS vulnerability scanner that uses context-aware detection to minimize false positives. Unlike traditional scanners that blindly inject payloads, Reflekt first understands *where* your input lands in the response and then crafts minimal probes to verify actual exploitability.

```
┌─────────────────────────────────────────────────────────────┐
│  [1/100] Found: 12 | https://target.com/search?q=test       │
│                                                             │
│  https://target.com/search?q=probe | q | attribute(")       │
│  https://target.com/page?id=probe | id | script(')          │
│  https://target.com/view?name=probe | name | html           │
│                                                             │
│  [100/100] Total findings: 47                               │
│  Results saved to: results.txt                              │
└─────────────────────────────────────────────────────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| **Context Detection** | Identifies HTML, attribute, script, and comment contexts |
| **Quote-Aware** | Detects single, double, backtick quotes and unquoted attributes |
| **WAF Bypass Testing** | Tests `</script>` breakout with WAF-safe probes |
| **DOM Sink Detection** | Identifies `srcdoc`, `innerHTML`, `javascript:` sinks |
| **Zero Payloads** | No `<script>alert(1)</script>` - uses minimal probes |
| **Multi-threaded** | Parallel scanning for large URL lists |
| **False Positive Prevention** | Context-aware verification eliminates noise |

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/reflekt.git
cd reflekt

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
# Single URL
python reflekt.py -u "https://target.com/search?q=test&page=1"

# Multiple URLs from file
python reflekt.py -l urls.txt
```

### Advanced Options
```bash
# 10 threads, 20s timeout, save results
python reflekt.py -l urls.txt -t 10 --timeout 20 -o results.txt

# Fast scan with high concurrency
python reflekt.py -l urls.txt -t 20 -o output.txt
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Single URL to scan | - |
| `-l, --list` | File containing URLs | - |
| `-o, --output` | Save results to file | - |
| `-t, --threads` | Concurrent threads | 1 |
| `--timeout` | Request timeout (seconds) | 10 |

## How It Works

### 1. Canary Injection
Reflekt injects unique canary strings into each parameter:
```
?name=reflekt1xK9m&id=reflekt2pQ7z
```

### 2. Context Detection
Analyzes where each canary appears in the response:

| Context | Example | Probe |
|---------|---------|-------|
| HTML Body | `<div>reflekt1xK9m</div>` | `canary<x7` |
| Attribute (") | `value="reflekt1xK9m"` | `canary"x7` |
| Attribute (') | `value='reflekt1xK9m'` | `canary'x7` |
| Script (') | `var x='reflekt1xK9m'` | `canary';//x7` |
| Script (") | `var x="reflekt1xK9m"` | `canary";//x7` |
| Unquoted | `value=reflekt1xK9m` | `canary>x7` |

### 3. Verification
Each probe is verified in the correct context:
- Attribute breakout: Checks quote is NOT HTML-encoded
- Script breakout: Verifies quote is NOT escaped (`\'`)
- HTML injection: Confirms `<` appears outside script blocks
- Fallback: Tests `</script>` tag breakout if quote fails

### 4. Smart Deduplication
Reports each vulnerability once per parameter+context combination.

## Output Format

```
URL | PARAMETER | CONTEXT
```

### Examples
```
https://target.com/s?q=probe"x7 | q | attribute(")
https://target.com/p?id=probe';//x7 | id | script(')
https://target.com/v?x=probe<x7 | x | html
https://target.com/j?data=probe</script><x7 | data | script(</tag>)
```

### Context Types

| Context | Meaning |
|---------|---------|
| `html` | HTML body injection (`<tag>` possible) |
| `attribute(")` | Double-quoted attribute breakout |
| `attribute(')` | Single-quoted attribute breakout |
| `attribute(unquoted)` | Unquoted attribute breakout |
| `script(')` | Single-quoted JS string breakout |
| `script(")` | Double-quoted JS string breakout |
| `script(`)` | Template literal breakout |
| `script(</tag>)` | Script tag closure breakout |
| `href` | javascript: protocol injection |
| `srcdoc` | iframe srcdoc entity decoding |
| `dom_sink` | innerHTML/dataset DOM XSS |

## Performance Tips

```bash
# Large lists: use more threads
python reflekt.py -l 10k-urls.txt -t 20 -o results.txt

# Slow targets: increase timeout
python reflekt.py -l urls.txt --timeout 30 -t 5

# Quick scan: lower timeout, more threads
python reflekt.py -l urls.txt --timeout 5 -t 30
```

## Contributing

Pull requests are welcome! For major changes, please open an issue first.

## License

MIT License - feel free to use in your security assessments.

---

<p align="center">
  <b>Reflekt</b> - Because smart scanning beats payload spraying.
</p>
