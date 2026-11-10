"""
Generates an SVG terminal mockup showing TriageForge in action.
"""

from pathlib import Path


def generate_terminal_svg(out_path: Path):
    svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 950 560" width="100%" height="100%">
  <defs>
    <style>
      .bg { fill: #0d1117; stroke: #30363d; stroke-width: 1.5; rx: 12px; }
      .bar { fill: #161b22; rx: 12px; }
      .btn-r { fill: #ff5f56; }
      .btn-y { fill: #ffbd2e; }
      .btn-g { fill: #27c93f; }
      .title { fill: #8b949e; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; font-size: 13px; font-weight: 500; }
      .text { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; font-size: 13px; }
      .c-dim { fill: #6e7681; }
      .c-white { fill: #f0f6fc; }
      .c-cyan { fill: #38bdf8; font-weight: 600; }
      .c-green { fill: #3fb950; font-weight: 600; }
      .c-red { fill: #f85149; font-weight: 600; }
      .c-yellow { fill: #e3b341; font-weight: 600; }
      .c-magenta { fill: #d2a8ff; font-weight: 600; }
      .box { fill: #161b22; stroke: #30363d; stroke-width: 1; rx: 6px; }
      .panel-crit { fill: #161b22; stroke: #f85149; stroke-width: 1.5; rx: 6px; }
    </style>
  </defs>

  <!-- Window Frame -->
  <rect width="950" height="560" class="bg"/>
  <path d="M0,0 H950 V40 H0 Z" class="bar"/>
  <circle cx="24" cy="20" r="6" class="btn-r"/>
  <circle cx="44" cy="20" r="6" class="btn-y"/>
  <circle cx="64" cy="20" r="6" class="btn-g"/>
  <text x="475" y="24" text-anchor="middle" class="title">sre-engineer@triageforge-lab: ~</text>

  <!-- Terminal Content -->
  <g class="text" transform="translate(25, 68)">
    <!-- Command 1: Break -->
    <text y="0"><tspan class="c-green">sre@forge:~$</tspan> <tspan class="c-white">make break FAULT=02_gunicorn_down</tspan></text>
    <text y="20"><tspan class="c-yellow">--&gt; Injecting fault: 02_gunicorn_down...</tspan></text>
    <text y="38"><tspan class="c-green">[OK] Fault successfully injected.</tspan> <tspan class="c-dim">triageforge-app worker terminated (Nginx 502 primed).</tspan></text>

    <!-- Command 2: Diagnose -->
    <text y="70"><tspan class="c-green">sre@forge:~$</tspan> <tspan class="c-white">triageforge diagnose --url http://localhost:80</tspan></text>

    <!-- Header Box -->
    <rect x="0" y="85" width="900" height="42" class="box" stroke="#38bdf8"/>
    <text x="16" y="105"><tspan class="c-cyan">TRIAGEFORGE CLOUD DIAGNOSTIC PROBE</tspan></text>
    <text x="16" y="120"><tspan class="c-dim">Target: http://localhost:80  |  Duration: 18.4ms  |  Status: </tspan><tspan class="c-red">[ALERT] INCIDENT DETECTED</tspan></text>

    <!-- Table -->
    <text y="152"><tspan class="c-magenta">DIAGNOSTIC LAYER TELEMETRY</tspan></text>
    <text y="172"><tspan class="c-dim">LAYER       STATUS     DURATION   KEY TELEMETRY / FINDING</tspan></text>
    <text y="188"><tspan class="c-dim">──────────────────────────────────────────────────────────────────────────────────────────</tspan></text>
    <text y="204"><tspan class="c-white">DNS         </tspan><tspan class="c-green">PASS  </tspan><tspan class="c-white">       0.3ms   Resolved 'localhost' to 127.0.0.1</tspan></text>
    <text y="222"><tspan class="c-white">TCP         </tspan><tspan class="c-green">PASS  </tspan><tspan class="c-white">       1.1ms   Established 3-way handshake on port 80</tspan></text>
    <text y="240"><tspan class="c-white">TLS         </tspan><tspan class="c-dim">SKIP  </tspan><tspan class="c-white">       0.0ms   Plain HTTP probe</tspan></text>
    <text y="258"><tspan class="c-white">HTTP        </tspan><tspan class="c-red">FAIL  </tspan><tspan class="c-white">      12.1ms   </tspan><tspan class="c-red">HTTP 502 Bad Gateway</tspan><tspan class="c-dim"> (Server: nginx/1.25.4)</tspan></text>
    <text y="276"><tspan class="c-white">HOST        </tspan><tspan class="c-red">FAIL  </tspan><tspan class="c-white">       4.9ms   Container 'triageforge-app' status is 'exited'</tspan></text>

    <!-- Root Cause Panel -->
    <rect x="0" y="296" width="900" height="175" class="panel-crit"/>
    <text x="16" y="318"><tspan class="c-red">#1 Upstream Application Process Down (Nginx 502 Bad Gateway) — 97% Match</tspan></text>
    <text x="16" y="338"><tspan class="c-white">Fault Category:</tspan> <tspan class="c-cyan">Application</tspan>   <tspan class="c-white">Severity:</tspan> <tspan class="c-red">SEV-2</tspan>   <tspan class="c-white">Confidence:</tspan> <tspan class="c-red">97%</tspan></text>
    <text x="16" y="358"><tspan class="c-white">Root Cause:</tspan> <tspan class="c-dim">Gunicorn/FastAPI worker crashed. Nginx received ECONNREFUSED on 127.0.0.1:8000.</tspan></text>
    <text x="16" y="378"><tspan class="c-white">Supporting Evidence:</tspan></text>
    <text x="32" y="394"><tspan class="c-yellow">* HTTP 502 Bad Gateway returned by reverse proxy (nginx/1.25.4)</tspan></text>
    <text x="32" y="410"><tspan class="c-yellow">* Application container 'triageforge-app' status is exited (exit code 137)</tspan></text>
    <text x="16" y="432"><tspan class="c-green">Next Best Diagnostic Command (SRE Runbook):</tspan></text>
    <text x="32" y="450"><tspan class="c-yellow">docker logs triageforge-nginx --tail 25 | grep -i 'connect() failed'</tspan></text>
  </g>
</svg>"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(svg_content, encoding="utf-8")
    print(f"Generated demo SVG: {out_path}")


if __name__ == "__main__":
    generate_terminal_svg(Path(__file__).resolve().parent / "demo_terminal.svg")
