#!/usr/bin/env python3
"""Render the Phase 1 crossover chart as light/dark SVGs, from the result file.

Reads a committed result file and derives every number in the chart from it —
including the crossover annotation — so the picture cannot drift from the data
the way hand-drawn figures do. Regenerate after any new measurement:

    python3 scripts/mkchart.py docs/results/<file>.json docs/images

Two SVGs are emitted because GitHub serves light and dark READMEs; the README
selects between them with <picture> and prefers-color-scheme.
"""
import json, math, sys
from pathlib import Path

RESULT = Path(sys.argv[1])
OUTDIR = Path(sys.argv[2])
OUTDIR.mkdir(parents=True, exist_ok=True)

d = json.loads(RESULT.read_text())
cells = sorted(d["statistics"]["by_trials"], key=lambda c: c["trials"])
base = d["honest_baseline"]
CLOSEST = base["expected_cpl_closest_honest_peer"]
TWENTIETH = base["expected_cpl_20th_closest_honest_peer"]
NPEERS = base["n_peers"]
provisional = set(d.get("provisional_cells", {}).get("trials", []))

THEMES = {
    "light": dict(surface="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781",
                  grid="#e1e0d9", axis="#c3c2b7", accent="#2a78d6", band="#0b0b0b"),
    "dark":  dict(surface="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781",
                  grid="#2c2c2a", axis="#383835", accent="#3987e5", band="#ffffff"),
}

W, H = 780, 440
ML, MR, MT, MB = 64, 186, 62, 58
PW, PH = W - ML - MR, H - MT - MB
YMAX = 27.0

def sx(trials): # log x
    lo, hi = math.log10(cells[0]["trials"]), math.log10(cells[-1]["trials"])
    return ML + (math.log10(trials) - lo) / (hi - lo) * PW

def sy(v):
    return MT + PH - (v / YMAX) * PH

def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def render(mode):
    t = THEMES[mode]
    o = []
    a = o.append
    a(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
      f'font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif" '
      f'role="img" aria-label="Attacker common-prefix length versus grinding effort, '
      f'crossing the honest network baseline between 100,000 and 1,000,000 trials.">')
    a(f'<rect width="{W}" height="{H}" fill="{t["surface"]}"/>')

    # Title
    a(f'<text x="{ML}" y="26" fill="{t["ink"]}" font-size="15" font-weight="600">'
      f'Grinding effort vs. how close the attacker lands</text>')
    a(f'<text x="{ML}" y="45" fill="{t["ink2"]}" font-size="12">'
      f'Common-prefix length with the target key, in bits. Higher is closer. '
      f'Median of seeded repetitions.</text>')

    # "honest territory" band: everything at or below the closest honest peer
    a(f'<rect x="{ML}" y="{sy(CLOSEST):.1f}" width="{PW}" height="{MT+PH-sy(CLOSEST):.1f}" '
      f'fill="{t["band"]}" opacity="0.035"/>')

    # y gridlines
    for v in range(0, int(YMAX) + 1, 5):
        a(f'<line x1="{ML}" y1="{sy(v):.1f}" x2="{ML+PW}" y2="{sy(v):.1f}" '
          f'stroke="{t["grid"]}" stroke-width="1"/>')
        a(f'<text x="{ML-10}" y="{sy(v)+4:.1f}" fill="{t["muted"]}" font-size="11" '
          f'text-anchor="end">{v}</text>')
    a(f'<text x="18" y="{MT+PH/2:.0f}" fill="{t["muted"]}" font-size="11" '
      f'text-anchor="middle" transform="rotate(-90 18 {MT+PH/2:.0f})">CPL (bits)</text>')

    # axes
    a(f'<line x1="{ML}" y1="{MT+PH}" x2="{ML+PW}" y2="{MT+PH}" stroke="{t["axis"]}" stroke-width="1"/>')

    # x ticks
    labels = {100000: "100k", 1000000: "1M", 10000000: "10M"}
    for c in cells:
        x = sx(c["trials"])
        secs = c["elapsed_s"]["median"]
        secs = f"{secs:.0f}" if secs >= 100 else f"{secs:.1f}"
        mark = " †" if c["trials"] in provisional else ""
        a(f'<line x1="{x:.1f}" y1="{MT+PH}" x2="{x:.1f}" y2="{MT+PH+5}" stroke="{t["axis"]}" stroke-width="1"/>')
        a(f'<text x="{x:.1f}" y="{MT+PH+20}" fill="{t["ink2"]}" font-size="11.5" '
          f'text-anchor="middle">{labels.get(c["trials"], c["trials"])}{mark}</text>')
        a(f'<text x="{x:.1f}" y="{MT+PH+35}" fill="{t["muted"]}" font-size="10.5" '
          f'text-anchor="middle">{secs}s</text>')
    a(f'<text x="{ML+PW/2:.0f}" y="{H-6}" fill="{t["muted"]}" font-size="11" '
      f'text-anchor="middle">keypair trials (log scale) · single core</text>')

    # honest reference lines
    for val, lab in ((CLOSEST, f"closest of ~{NPEERS:,} honest peers"),
                     (TWENTIETH, "honest 20th-closest")):
        a(f'<line x1="{ML}" y1="{sy(val):.1f}" x2="{ML+PW}" y2="{sy(val):.1f}" '
          f'stroke="{t["muted"]}" stroke-width="1.5" stroke-dasharray="5 4"/>')
        a(f'<text x="{ML+PW+10}" y="{sy(val)-3:.1f}" fill="{t["ink2"]}" font-size="10.5">{esc(lab)}</text>')
        a(f'<text x="{ML+PW+10}" y="{sy(val)+10:.1f}" fill="{t["muted"]}" font-size="10.5">CPL {val}</text>')

    # context series (gray)
    for key, lab in (("cpl_best", "best of the 20"), ("cpl_mean_of_kept", "mean of the 20")):
        pts = [(sx(c["trials"]), sy(c[key]["median"])) for c in cells]
        path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(pts))
        a(f'<path d="{path}" fill="none" stroke="{t["muted"]}" stroke-width="1.5" opacity="0.75"/>')
        for x, y in pts:
            a(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{t["muted"]}" '
              f'stroke="{t["surface"]}" stroke-width="2" opacity="0.75"/>')
        lx, ly = pts[-1]
        dy = 4 if key == "cpl_best" else -9
        a(f'<text x="{lx+10:.1f}" y="{ly+dy:.1f}" fill="{t["muted"]}" font-size="10.5">{esc(lab)}</text>')

    # emphasis series: the worst kept identity — this crossing is the finding
    pts = [(sx(c["trials"]), sy(c["cpl_20th"]["median"]), c) for c in cells]
    path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y, _) in enumerate(pts))
    a(f'<path d="{path}" fill="none" stroke="{t["accent"]}" stroke-width="2.5"/>')
    for i, (x, y, c) in enumerate(pts):
        a(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{t["accent"]}" '
          f'stroke="{t["surface"]}" stroke-width="2"/>')
        if i < len(pts) - 1:  # last cell is provisional and its label crowds the legend
            a(f'<text x="{x:.1f}" y="{y-12:.1f}" fill="{t["accent"]}" font-size="11.5" '
              f'font-weight="600" text-anchor="middle">{c["cpl_20th"]["median"]:g}</text>')
    lx, ly, lc = pts[-1]
    a(f'<text x="{lx+10:.1f}" y="{ly+16:.1f}" fill="{t["accent"]}" font-size="11" '
      f'font-weight="600">worst of the 20</text>')
    a(f'<text x="{lx+10:.1f}" y="{ly+29:.1f}" fill="{t["ink2"]}" font-size="10">'
      f'{lc["cpl_20th"]["median"]:g} bits — the line that matters</text>')

    # crossover annotation between the first two cells
    v0 = cells[0]["cpl_20th"]["median"]
    v1 = cells[1]["cpl_20th"]["median"]
    frac = (CLOSEST - v0) / (v1 - v0) if v1 != v0 else 0.5
    cxx = sx(cells[0]["trials"]) + frac * (sx(cells[1]["trials"]) - sx(cells[0]["trials"]))
    cyy = sy(CLOSEST)
    a(f'<circle cx="{cxx:.1f}" cy="{cyy:.1f}" r="7" fill="none" '
      f'stroke="{t["ink"]}" stroke-width="1.5" opacity="0.8"/>')
    a(f'<line x1="{cxx:.1f}" y1="{cyy-8:.1f}" x2="{cxx:.1f}" y2="{cyy-30:.1f}" '
      f'stroke="{t["ink2"]}" stroke-width="1" opacity="0.6"/>')
    # Derive the crossing cost rather than asserting it: interpolate the trial
    # count in log space, then divide by the measured median rate. Approximate by
    # construction — CPL is integer-valued, so the true crossing is a step, not a
    # point — hence the tilde.
    lo, hi = cells[0]["trials"], cells[1]["trials"]
    cross_trials = 10 ** (math.log10(lo) + frac * (math.log10(hi) - math.log10(lo)))
    rate = (cells[0]["rate_keypairs_per_s"]["median"] + cells[1]["rate_keypairs_per_s"]["median"]) / 2
    cross_s = cross_trials / rate
    # Halo as a separate stroke-only element beneath the fill. `paint-order` is
    # not honoured by every SVG renderer, and where it is ignored the stroke
    # paints over the glyphs and the label vanishes — which it did, in dark mode.
    def haloed(x, y, txt, fill, size, weight="400"):
        common = (f'x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" '
                  f'text-anchor="middle"')
        a(f'<text {common} fill="none" stroke="{t["surface"]}" stroke-width="3.5" '
          f'stroke-linejoin="round">{esc(txt)}</text>')
        a(f'<text {common} fill="{fill}">{esc(txt)}</text>')

    haloed(cxx, cyy - 36, "overtakes the whole network here", t["ink"], 10.5, "600")
    haloed(cxx, cyy - 24, f"~{cross_s:.0f}s of grinding", t["muted"], 10)

    # band caption, inside the plot so it cannot collide with the axis labels
    a(f'<text x="{ML+10}" y="{MT+PH-12}" fill="{t["muted"]}" font-size="10.5">'
      f'shaded: at or below the closest honest peer</text>')
    a('</svg>')
    return "\n".join(o)

for mode in ("light", "dark"):
    p = OUTDIR / f"phase1-crossover-{mode}.svg"
    p.write_text(render(mode) + "\n")
    print("wrote", p)
