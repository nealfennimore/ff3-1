#!/usr/bin/env python3
"""
scripts/build_index.py  (FF3-1 repo)
Assembles dist/ after wasm-pack build.

Called by the GitHub Actions workflow:
    python3 scripts/build_index.py dist/

Expects wasm-pack output at: pkg/
Writes: dist/index.html  dist/pkg/*
"""

import pathlib
import shutil
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: build_index.py <dist_dir>")
        sys.exit(1)

    dist = pathlib.Path(sys.argv[1]).resolve()
    dist.mkdir(parents=True, exist_ok=True)

    src_pkg  = pathlib.Path("pkg").resolve()
    dist_pkg = dist / "pkg"

    if not src_pkg.exists():
        print("ERROR: pkg/ not found — run wasm-pack build first")
        sys.exit(1)

    if dist_pkg.exists():
        shutil.rmtree(dist_pkg)
    shutil.copytree(src_pkg, dist_pkg)
    print(f"Copied pkg/ -> {dist_pkg}")

    html = build_html()
    out  = dist / "index.html"
    out.write_text(html, encoding="utf-8")
    print(f"Wrote  {out}  ({len(html):,} bytes)")


def build_html() -> str:
    return """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FF3-1 Format-Preserving Encryption — WASM Demo</title>
  <meta name="description" content="Interactive FF3-1 FPE demo compiled to WebAssembly from Rust.">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:      #0f1117;
      --surface: #1a1d2e;
      --border:  #2d3748;
      --text:    #e2e8f0;
      --muted:   #718096;
      --accent:  #90cdf4;
      --green:   #68d391;
      --red:     #fc8181;
      --yellow:  #fbd38d;
    }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 2rem 1rem;
    }
    .container { max-width: 640px; margin: 0 auto; }
    h1 { font-size: 1.5rem; color: var(--accent); margin-bottom: 0.3rem; }
    .subtitle { color: var(--muted); font-size: 0.88rem; margin-bottom: 1.5rem; }
    .warning {
      background: #2d1b00;
      border-left: 4px solid #d69e2e;
      color: var(--yellow);
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-size: 0.82rem;
      line-height: 1.5;
      margin-bottom: 1.75rem;
    }
    .note {
      background: #1a2535;
      border-left: 4px solid var(--accent);
      color: #90cdf4cc;
      padding: 0.65rem 1rem;
      border-radius: 6px;
      font-size: 0.8rem;
      line-height: 1.5;
      margin-bottom: 1.5rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
    }
    label {
      display: block;
      font-size: 0.78rem;
      color: var(--muted);
      margin: 0.85rem 0 0.25rem;
    }
    input, select {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      padding: 7px 10px;
      font-size: 0.875rem;
      font-family: inherit;
    }
    input:focus, select:focus { outline: none; border-color: var(--accent); }
    .tweak-hint { font-size: 0.72rem; color: var(--muted); margin-top: 3px; }
    .btn-row { display: flex; gap: 8px; margin-top: 1rem; }
    button {
      flex: 1;
      padding: 9px;
      border: none;
      border-radius: 7px;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 600;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.85; }
    .btn-enc { background: #2b6cb0; color: #fff; }
    .btn-dec { background: #276749; color: #fff; }
    .result {
      margin-top: 0.75rem;
      padding: 9px 10px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      font-family: monospace;
      font-size: 0.82rem;
      min-height: 2.4rem;
      word-break: break-all;
    }
    .result.ok    { border-color: #276749; color: var(--green); }
    .result.error { border-color: #9b2335; color: var(--red);   }
    .result.info  { color: var(--accent); }
    .log-section { margin-top: 1.5rem; }
    .log-label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase;
                 letter-spacing: 0.08em; margin-bottom: 0.4rem; }
    .log {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.65rem 1rem;
      font-family: monospace;
      font-size: 0.78rem;
      max-height: 160px;
      overflow-y: auto;
      line-height: 1.6;
    }
    .le       { color: var(--muted); }
    .le.ok    { color: var(--green); }
    .le.error { color: var(--red);   }
    .le.info  { color: var(--accent);}
    footer { margin-top: 2rem; text-align: center; font-size: 0.75rem; color: var(--muted); }
    footer a { color: var(--accent); text-decoration: none; }
  </style>
</head>
<body>
<div class="container">
  <h1>FF3-1 Format-Preserving Encryption</h1>
  <p class="subtitle">
    NIST SP 800-38G Rev 1 &mdash; Rust compiled to WebAssembly via wasm-pack
  </p>

  <div class="warning">
    ⚠ <strong>Security notice:</strong> AI-generated implementation, no formal security audit.
    For educational and experimental use only. Do not use to protect real sensitive data.
  </div>

  <div class="note">
    ℹ FF3-1 requires a tweak of <strong>exactly 7 bytes</strong> (14 hex chars).
    NIST SP 800-38G Rev 1 Second Public Draft (Feb 2025) withdrew FF3-1 in favour of FF1.
  </div>

  <div class="card">
    <label>Key (hex &mdash; 32 / 48 / 64 chars)</label>
    <input id="key" value="2DE79D232DF5585D68CE47882AE256D6" spellcheck="false">

    <label>Radix</label>
    <select id="radix" onchange="syncAlpha()">
      <option value="10" selected>10 &mdash; decimal digits (0–9)</option>
      <option value="26">26 &mdash; lowercase alpha (a–z)</option>
      <option value="36">36 &mdash; alphanumeric (0–9 a–z)</option>
    </select>

    <label>Alphabet</label>
    <input id="alphabet" value="0123456789" spellcheck="false">

    <label>Tweak (hex &mdash; exactly 14 hex chars = 7 bytes)</label>
    <input id="tweak" value="D8E7920AFA330A" maxlength="14" spellcheck="false">
    <div class="tweak-hint">Must be exactly 14 hex characters. Example: D8E7920AFA330A</div>

    <label>Plaintext / Ciphertext</label>
    <input id="pt" value="4111111111111111" spellcheck="false">

    <div class="btn-row">
      <button class="btn-enc" onclick="run('encrypt')">Encrypt ↓</button>
      <button class="btn-dec" onclick="run('decrypt')">Decrypt ↑</button>
    </div>
    <div class="result info" id="result">Initialising…</div>
  </div>

  <div class="log-section">
    <div class="log-label">Console</div>
    <div class="log" id="log"><div class="le info">Loading WASM…</div></div>
  </div>

  <footer>
    <a href="https://github.com/YOUR_USERNAME/ff3_1">Source on GitHub</a>
    &mdash;
    <a href="https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd">NIST SP 800-38G Rev 1</a>
  </footer>
</div>

<script type="module">
  const ALPHABETS = {
    "10": "0123456789",
    "26": "abcdefghijklmnopqrstuvwxyz",
    "36": "0123456789abcdefghijklmnopqrstuvwxyz",
  };

  let Ff3Cls = null;

  function log(msg, type = "info") {
    const el = document.getElementById("log");
    const e  = document.createElement("div");
    e.className = `le ${type}`;
    const t = new Date().toLocaleTimeString("en-GB", { hour12: false });
    e.textContent = `[${t}] ${msg}`;
    el.appendChild(e);
    el.scrollTop = el.scrollHeight;
  }

  function setResult(text, type) {
    const el = document.getElementById("result");
    el.textContent = text;
    el.className = `result ${type}`;
  }

  window.syncAlpha = () => {
    const r = document.getElementById("radix").value;
    document.getElementById("alphabet").value = ALPHABETS[r] ?? "";
  };

  try {
    const m = await import("./pkg/ff3_1.js");
    await m.default();
    Ff3Cls = m.Ff3;
    setResult("Ready", "ok");
    log("FF3-1 WASM loaded ✓", "ok");
  } catch (err) {
    setResult(`Failed to load: ${err}`, "error");
    log(`Load error: ${err}`, "error");
  }

  window.run = (dir) => {
    if (!Ff3Cls) { log("Not loaded", "error"); return; }
    try {
      const cipher = new Ff3Cls(
        document.getElementById("key").value.trim(),
        parseInt(document.getElementById("radix").value)
      );
      const input = document.getElementById("pt").value.trim();
      const tweak = document.getElementById("tweak").value.trim();
      const alpha = document.getElementById("alphabet").value;
      const out   = dir === "encrypt"
        ? cipher.encryptStrHexTweak(input, tweak, alpha)
        : cipher.decryptStrHexTweak(input, tweak, alpha);
      setResult(out, "ok");
      document.getElementById("pt").value = out;
      log(`${dir}: "${input}" → "${out}"`, "ok");
    } catch (err) {
      setResult(String(err), "error");
      log(`${dir} error: ${err}`, "error");
    }
  };
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()