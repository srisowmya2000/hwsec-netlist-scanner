#!/usr/bin/env python3
"""
pcb2net.py - build a netlist from a KiCad PCB file (.kicad_pcb).

Use it when a schematic can't be exported (e.g. an old KiCad 5 project whose
symbol libraries are missing). The PCB still knows every part and which pad
sits on which net, which is enough for most of circuit.py's checks.

Usage:
    python3 tools/pcb2net.py board.kicad_pcb board.net

Limits: a PCB has no pin names or pin types (input/output/power), so checks
that rely on them (e.g. "wired straight into a chip pin", supply decoupling)
find less than they would from a real schematic netlist.
"""

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from circuit import tokenize, parse, find  # noqa: E402


def quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as f:
        tree = parse(tokenize(f.read()))

    comps, nets = [], defaultdict(list)
    for fp in find(tree, "module") + find(tree, "footprint"):     # KiCad 5 / KiCad 6+
        ref = val = ""
        for t in find(fp, "fp_text"):                              # KiCad 5
            if t[1] == "reference":
                ref = t[2]
            elif t[1] == "value":
                val = t[2]
        for p in find(fp, "property"):                             # KiCad 8+
            if p[1] == "Reference":
                ref = p[2]
            elif p[1] == "Value":
                val = p[2]
        if not ref or ref.startswith("REF"):
            continue
        comps.append((ref, val))
        for pad in find(fp, "pad"):
            net = find(pad, "net")
            if net and len(net[0]) > 2 and net[0][2]:
                nets[net[0][2]].append((ref, pad[1]))

    lines = ['(export (version "E")', "  (components"]
    lines += [f"    (comp (ref {quote(r)}) (value {quote(v)}))" for r, v in comps]
    lines += ["  )", "  (nets"]
    for i, (name, nodes) in enumerate(nets.items(), 1):
        pads = " ".join(f"(node (ref {quote(r)}) (pin {quote(p)}))" for r, p in nodes)
        lines.append(f'    (net (code "{i}") (name {quote(name)}) {pads})')
    lines += ["  )", ")"]
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {sys.argv[2]}: {len(comps)} components, {len(nets)} nets")


if __name__ == "__main__":
    main()
