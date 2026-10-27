"""
Tests for circuit.py. No extra libraries needed.

Run all tests (from the project folder):
    python3 -m unittest discover -s tests -v

After an intended change to the findings, refresh the saved reports and
review the difference with `git diff tests/expected` before committing:
    python3 tests/test_circuit.py --update
"""

import contextlib
import difflib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import circuit  # noqa: E402

SCRIPT = os.path.join(ROOT, "circuit.py")
EXAMPLES = os.path.join(ROOT, "examples")
EXPECTED = os.path.join(ROOT, "tests", "expected")
BOARDS = os.path.join(ROOT, "tests", "boards")


def boards():
    """Every board with a saved report: the examples plus the hand-written test boards."""
    found = []
    for folder in (EXAMPLES, BOARDS):
        found += [os.path.join(folder, f) for f in sorted(os.listdir(folder)) if f.endswith(".net")]
    return found


def report_for(path):
    components, nets = circuit.load_netlist(path)
    return circuit.build_report(path, components, nets)


def text_report(path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        circuit.print_text(report_for(path))
    return out.getvalue()


def expected_path(board):
    return os.path.join(EXPECTED, os.path.basename(board)[:-4] + ".txt")


def messages(report, level=None):
    return [f["message"] for s in report["sections"] for c in s["checks"] for f in c["findings"]
            if level is None or f["level"] == level]


def run_cli(*args, seed=None):
    env = dict(os.environ)
    if seed is not None:
        env["PYTHONHASHSEED"] = str(seed)
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True, env=env, cwd=ROOT)


class SavedReports(unittest.TestCase):
    """Each board's text report must match the saved copy in tests/expected/."""

    def test_every_board_has_a_saved_report(self):
        missing = [os.path.basename(b) for b in boards() if not os.path.exists(expected_path(b))]
        self.assertEqual(missing, [], "Run `python3 tests/test_circuit.py --update` to create them.")

    def test_reports_match(self):
        for board in boards():
            with self.subTest(board=os.path.basename(board)):
                with open(expected_path(board), encoding="utf-8") as f:
                    expected = f.read()
                actual = text_report(board)
                if actual != expected:
                    diff = "".join(list(difflib.unified_diff(
                        expected.splitlines(True), actual.splitlines(True), "expected", "actual"))[:60])
                    self.fail(f"Report changed for {os.path.basename(board)}. If this is intended, run "
                              f"`python3 tests/test_circuit.py --update`.\n{diff}")


class ChipKnowledge(unittest.TestCase):
    """The hand-written board wires each chip's debug and boot pins to headers and switches."""

    @classmethod
    def setUpClass(cls):
        cls.report = report_for(os.path.join(BOARDS, "chips.net"))
        cls.high = messages(cls.report, "HIGH")
        cls.medium = messages(cls.report, "MEDIUM")

    def assertFound(self, text, found):
        self.assertTrue(any(text in m for m in found), f"{text!r} not in:\n" + "\n".join(found))

    def test_debug_pins(self):
        for text in ("U1 PA13 pin (SWD SWDIO",          # STM32
                     "U1 PA14 pin (SWD SWCLK",
                     "U1 PA9 pin (USART1 TX",
                     "U2 SWCLK pin (SWD clock",         # RP2040
                     "U3 PB3 pin (ISP MOSI",            # ATmega328P
                     "U3 PC6 pin (RESET / debugWIRE",
                     "U4 SWDCLK pin (SWD clock",        # nRF52
                     "U5 PA30 pin (SWD SWCLK",          # SAMD21
                     "U6 TXD pin (UART0 TX"):           # ESP8266
            with self.subTest(text=text):
                self.assertFound(text, self.high)

    def test_boot_pins(self):
        for text in ("Boot pin U1 BOOT0 pin", "Boot pin U2 QSPI_SS pin", "Boot pin U6 GPIO0 pin"):
            with self.subTest(text=text):
                self.assertFound(text, self.medium)

    def test_gpio10_is_not_gpio1(self):
        # RP2040 GPIO1 is UART0 RX, GPIO10 is an ordinary pin.
        self.assertFalse(any("GPIO10" in m for m in self.high), "\n".join(self.high))


class HeaterAppliance(unittest.TestCase):
    """espgaggia: ESP32 dev board, SSRs for pump/valve on mains, an external SSR for the boiler heater."""

    @classmethod
    def setUpClass(cls):
        cls.report = report_for(os.path.join(EXAMPLES, "espgaggia.net"))
        cls.all = messages(cls.report)

    def assertFound(self, text):
        self.assertTrue(any(text in m for m in self.all), f"{text!r} not in:\n" + "\n".join(self.all))

    def test_heater_on_external_ssr(self):
        self.assertFound("external power load (relay/SSR/heater/motor) through SSR Boiler (J10)")

    def test_ssr_switched_mains_loads(self):
        self.assertFound("Firmware-controlled mains loads: Valve (J8) via U4; Pump (J9) via U5")

    def test_mains_entry_and_isolation(self):
        self.assertFound("Mains input 220V (J3) is fused (F1)")
        self.assertFound("isolated supply PS1 and solid-state relays U4, U5")

    def test_heater_is_in_fix_first(self):
        # Safety findings rank first within their level, so the boiler can't be pushed out of the top 5.
        top = [f["message"] for f in self.report["assessment"]["fix_first"]]
        self.assertTrue(any("SSR Boiler (J10)" in m for m in top), "\n".join(top))

    def test_dev_board(self):
        self.assertFound("U3 (ESP32-DEVKITC-32D) is a development board with a built-in USB programming port")
        self.assertFound("Power output +3V3 to J6 comes through U3")


class PinMatching(unittest.TestCase):
    def meaning(self, part, function):
        components = {"U1": {"value": part}}
        return circuit.meaning_of({"ref": "U1", "function": function}, components)

    def test_digit_boundary(self):
        self.assertIn("UART0 RX", self.meaning("RP2040", "GPIO1"))
        self.assertIsNone(self.meaning("RP2040", "GPIO10"))
        self.assertIn("USART1 RX", self.meaning("STM32F401", "PA10"))
        self.assertIsNone(self.meaning("STM32F401", "PA1"))

    def test_more_specific_chip_wins(self):
        # ESP32-S3 is listed before plain ESP32, so IO19 is its USB-JTAG pin.
        self.assertIn("USB-Serial/JTAG", self.meaning("ESP32-S3-WROOM-1", "IO19"))
        self.assertIsNone(self.meaning("ESP32-WROOM-32", "IO19"))

    def test_unknown_chip(self):
        self.assertIsNone(self.meaning("LM358", "PA13"))


class StableOutput(unittest.TestCase):
    def test_same_report_every_run(self):
        # Python shuffles set order between runs; the report must not change with it.
        board = os.path.join(EXAMPLES, "satellite_tracker.net")
        outputs = {run_cli(board, seed=seed).stdout for seed in range(6)}
        self.assertEqual(len(outputs), 1)


class OutputFormats(unittest.TestCase):
    def test_json_matches_findings(self):
        result = run_cli(os.path.join(EXAMPLES, "doorman.net"), "--json", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        levels = [f["level"] for s in data["sections"] for c in s["checks"] for f in c["findings"]]
        self.assertEqual(data["summary"], {k: levels.count(k) for k in circuit.ORDER if k in levels})
        self.assertEqual(data["assessment"]["overall_risk"], "HIGH")
        self.assertEqual(data["netlist"], "doorman.net")

    def test_html_and_json_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            html_file, json_file = os.path.join(tmp, "r.html"), os.path.join(tmp, "r.json")
            result = run_cli(os.path.join(EXAMPLES, "mygenwashy.net"), "--html", html_file, "--json", json_file)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Overall risk: HIGH", result.stdout)        # text report still printed
            with open(html_file, encoding="utf-8") as f:
                page = f.read()
            self.assertTrue(page.startswith("<!doctype html>"))
            self.assertIn("mygenwashy.net", page)
            self.assertIn("Fix first", page)
            with open(json_file, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["assessment"]["overall_risk"], "HIGH")

    def test_html_escapes_text(self):
        report = report_for(os.path.join(EXAMPLES, "doorman.net"))
        report["sections"][0]["checks"][0]["findings"][0]["message"] = "<script>alert(1)</script>"
        page = circuit.render_html(report)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)


class CommandLine(unittest.TestCase):
    def test_no_arguments(self):
        result = run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage:", result.stderr)

    def test_missing_file(self):
        result = run_cli("no_such_board.net")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("file not found", result.stderr)

    def test_not_a_netlist(self):
        result = run_cli("README.md")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not read", result.stderr)


def update_expected():
    os.makedirs(EXPECTED, exist_ok=True)
    for board in boards():
        with open(expected_path(board), "w", encoding="utf-8") as f:
            f.write(text_report(board))
        print("saved", os.path.relpath(expected_path(board), ROOT))


if __name__ == "__main__":
    if "--update" in sys.argv:
        update_expected()
    else:
        unittest.main()
