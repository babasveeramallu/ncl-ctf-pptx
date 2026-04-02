#!/usr/bin/env python3
"""
NCL Hash Cracking TUI - Interactive interface for cracking MD5, NTLM, LM, and Office hashes
"""
import os
import subprocess
import json
from pathlib import Path
from typing import Optional
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Select, TextArea, Label, Static, Input
from textual.screen import Screen
from textual import on
from textual.app import App
from textual.widgets import TabbedContent, TabPane
import asyncio


class CrackConfig:
    """Configuration holder for cracking session"""
    def __init__(self):
        self.hash_type: str = "md5"
        self.attack_mode: str = "rockyou"
        self.hash_file: str = ""
        self.custom_dict: str = ""
        self.custom_mask: str = ""
        self.output_file: str = "cracked.txt"


class HashInputScreen(Screen):
    """Screen for entering/loading hashes"""
    def __init__(self, config: CrackConfig):
        super().__init__()
        self.config = config

    @staticmethod
    def _is_hex_of_len(value: str, expected_len: int) -> bool:
        """Return True when value is a hex string of expected length."""
        return len(value) == expected_len and all(ch in "0123456789abcdefABCDEF" for ch in value)

    @staticmethod
    def _normalize_hash_type(value) -> str:
        """Normalize Select values to a supported hash type string."""
        allowed = {"md5", "ntlm", "lm_ntlm", "office2013", "sha1", "sha256"}
        if isinstance(value, str) and value in allowed:
            return value
        return "md5"

    def detect_hash_type(self, content: str) -> Optional[str]:
        """Detect hash type from provided content using common hash signatures."""
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if not lines:
            return None

        # Office hashes commonly begin with $office$ after extraction.
        if all(line.lower().startswith("$office$") for line in lines):
            return "office2013"

        # LM:NTLM format is two 32-char hex hashes separated by a colon.
        if all(":" in line for line in lines):
            all_pairs = True
            for line in lines:
                parts = line.split(":")
                if len(parts) != 2:
                    all_pairs = False
                    break
                left, right = parts
                if not (self._is_hex_of_len(left, 32) and self._is_hex_of_len(right, 32)):
                    all_pairs = False
                    break
            if all_pairs:
                return "lm_ntlm"

        if all(self._is_hex_of_len(line, 64) for line in lines):
            return "sha256"
        if all(self._is_hex_of_len(line, 40) for line in lines):
            return "sha1"
        if all(self._is_hex_of_len(line, 32) for line in lines):
            # 32-char hashes are ambiguous (MD5/NTLM/LM). Use casing as a heuristic.
            # Common dumps use uppercase for NTLM and lowercase for MD5 examples.
            if all(line.upper() == line for line in lines):
                return "ntlm"
            # Prefer NTLM by default for challenge workflows; user can switch to MD5 manually.
            return "ntlm"

        return None

    def auto_select_hash_type(self, content: str):
        """Auto-select hash type in UI if detection is successful."""
        detected = self.detect_hash_type(content)
        if not detected:
            return

        hash_type_select = self.query_one("#hash-type-select", Select)
        if hash_type_select.value != detected:
            hash_type_select.value = detected
            self.app.notify(f"🎯 Auto-detected hash type: {detected}")

    @on(TextArea.Changed, "#hash-input")
    def on_hash_input_changed(self, _event: TextArea.Changed):
        """Auto-detect hash type while user types or pastes hashes."""
        text_area = self.query_one("#hash-input", TextArea)
        self.auto_select_hash_type(text_area.text)

    def _extract_ntlm_from_pairs(self, content: str) -> str:
        """Extract NTLM (right-hand) hashes from LM:NTLM pair lines."""
        ntlm_hashes = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) != 2:
                raise ValueError(f"Invalid LM:NTLM line: {line}")
            lm_hash, ntlm_hash = parts
            if not (self._is_hex_of_len(lm_hash, 32) and self._is_hex_of_len(ntlm_hash, 32)):
                raise ValueError(f"Invalid LM:NTLM hash format: {line}")
            ntlm_hashes.append(ntlm_hash)

        if not ntlm_hashes:
            raise ValueError("No LM:NTLM pairs found")

        temp_file = Path("temp_ntlm_from_pairs.txt")
        temp_file.write_text("\n".join(ntlm_hashes) + "\n")
        return str(temp_file)

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="input-main"):
            yield Label("📋 Hash Input", id="title")
            
            with Horizontal(id="hash-type-row"):
                yield Label("Hash Type:")
                yield Select(
                    [
                        ("MD5", "md5"),
                        ("NTLM", "ntlm"),
                        ("LM:NTLM Pairs", "lm_ntlm"),
                        ("Office 2013 (.pptx/.docx)", "office2013"),
                        ("SHA1", "sha1"),
                        ("SHA256", "sha256"),
                    ],
                    value="md5",
                    id="hash-type-select",
                )
            
            yield Label("Paste hashes (one per line) or load from file:")
            yield TextArea(id="hash-input", language="text")
            
            with Horizontal(id="button-row-1"):
                yield Button("📁 Load from File", id="load-file-btn", variant="primary")
                yield Button("🎯 Auto Detect", id="auto-detect-btn", variant="warning")
                yield Button("📋 Clear", id="clear-btn")
                yield Button("Next →", id="next-btn", variant="success")
        
        yield Footer()

    @on(Button.Pressed, "#load-file-btn")
    def load_file(self):
        """Load hashes from file"""
        self.app.push_screen(FilePickerScreen(self.config, self))

    @on(Button.Pressed, "#clear-btn")
    def clear_input(self):
        """Clear text area"""
        text_area = self.query_one("#hash-input", TextArea)
        text_area.text = ""

    @on(Button.Pressed, "#auto-detect-btn")
    def run_auto_detect(self):
        """Manually trigger hash auto-detection."""
        text_area = self.query_one("#hash-input", TextArea)
        detected = self.detect_hash_type(text_area.text)
        if not detected:
            self.app.notify("⚠️ Could not auto-detect hash type", severity="warning")
            return
        hash_type_select = self.query_one("#hash-type-select", Select)
        hash_type_select.value = detected
        self.app.notify(f"🎯 Auto-detected hash type: {detected}")

    @on(Button.Pressed, "#next-btn")
    def go_next(self):
        """Save config and go to next screen"""
        hash_type_select = self.query_one("#hash-type-select", Select)
        text_area = self.query_one("#hash-input", TextArea)

        self.auto_select_hash_type(text_area.text)
        
        self.config.hash_type = self._normalize_hash_type(hash_type_select.value)

        if self.config.hash_type == "lm_ntlm":
            try:
                self.config.hash_file = self._extract_ntlm_from_pairs(text_area.text)
                self.app.notify("ℹ️ Extracted NTLM hashes from LM:NTLM pairs")
            except ValueError as e:
                self.app.notify(f"❌ {e}", severity="error")
                return
        else:
            self.config.hash_file = self._create_temp_hash_file(text_area.text)
        
        if not self.config.hash_file:
            self.app.notify("❌ No hashes entered", severity="error")
            return
        
        self.app.push_screen(AttackModeScreen(self.config))

    def _create_temp_hash_file(self, content: str) -> str:
        """Create temporary file with hashes"""
        if not content.strip():
            return ""
        
        temp_file = Path("temp_hashes.txt")
        temp_file.write_text(content)
        return str(temp_file)


class FilePickerScreen(Screen):
    """Simple file picker for hash files"""
    def __init__(self, config: CrackConfig, hash_input_screen: Screen):
        super().__init__()
        self.config = config
        self.hash_input_screen = hash_input_screen

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Label("Enter hash file path:")
            yield Input(id="file-path-input", placeholder="e.g., hashes.txt")
            with Horizontal():
                yield Button("Load", id="load-btn", variant="primary")
                yield Button("Back", id="back-btn")
        yield Footer()

    @on(Button.Pressed, "#load-btn")
    def load(self):
        """Load the specified file"""
        file_input = self.query_one("#file-path-input", Input)
        file_path = Path(file_input.value)
        
        if not file_path.exists():
            self.app.notify(f"❌ File not found: {file_path}", severity="error")
            return
        
        try:
            text_area = self.hash_input_screen.query_one("#hash-input", TextArea)
            text_area.text = file_path.read_text()
            self.hash_input_screen.auto_select_hash_type(text_area.text)
            self.app.pop_screen()
            self.app.notify(f"✅ Loaded {len(text_area.text.splitlines())} hashes")
        except Exception as e:
            self.app.notify(f"❌ Error loading file: {e}", severity="error")

    @on(Button.Pressed, "#back-btn")
    def go_back(self):
        """Go back to parent screen"""
        self.app.pop_screen()


class AttackModeScreen(Screen):
    """Screen for selecting attack strategy"""
    def __init__(self, config: CrackConfig):
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="attack-main"):
            safe_hash_type = (
                self.config.hash_type.upper()
                if isinstance(self.config.hash_type, str)
                else "MD5"
            )
            yield Label(f"⚔️  Attack Mode (Hash Type: {safe_hash_type})", id="title")
            
            with Horizontal(id="mode-row"):
                yield Label("Select Attack:")
                yield Select(
                    [
                        ("🎯 Rockyou Wordlist (fast)", "rockyou"),
                        ("📚 Custom Dictionary", "custom_dict"),
                        ("🎭 Pattern (Adjective+Noun+2Digits)", "adj_noun_digits"),
                        ("💪 Brute-Force (letters+numbers)", "bruteforce"),
                        ("🔀 Hybrid Attack", "hybrid"),
                    ],
                    value="rockyou",
                    id="attack-select",
                )
            
            with Vertical(id="settings-panel"):
                yield Label("Additional Settings:")
                
                with Horizontal():
                    yield Label("Custom Dictionary File (optional):")
                    yield Input(id="dict-input", placeholder="path/to/wordlist.txt")
                
                with Horizontal():
                    yield Label("Mask Pattern (optional):")
                    yield Input(id="mask-input", placeholder="?a?a?a?d?d")
                
                with Horizontal():
                    yield Label("Max Runtime (seconds, 0=unlimited):")
                    yield Input(id="runtime-input", value="600")
            
            with Horizontal(id="button-row-2"):
                yield Button("← Back", id="back-btn")
                yield Button("Start Cracking! 🚀", id="start-btn", variant="success")
        
        yield Footer()

    @on(Button.Pressed, "#back-btn")
    def go_back(self):
        """Go back"""
        self.app.pop_screen()

    @on(Button.Pressed, "#start-btn")
    def start_cracking(self):
        """Start the cracking process"""
        attack_select = self.query_one("#attack-select", Select)
        dict_input = self.query_one("#dict-input", Input)
        mask_input = self.query_one("#mask-input", Input)
        runtime_input = self.query_one("#runtime-input", Input)
        
        self.config.attack_mode = attack_select.value
        self.config.custom_dict = dict_input.value
        self.config.custom_mask = mask_input.value
        
        # Validate inputs
        if not self.config.hash_file or not Path(self.config.hash_file).exists():
            self.app.notify("❌ Hash file not found", severity="error")
            return
        
        if self.config.attack_mode == "custom_dict" and not self.config.custom_dict:
            self.app.notify("❌ Custom dictionary path required", severity="error")
            return
        
        runtime = runtime_input.value or "0"
        
        # Start cracking screen
        self.app.push_screen(CrackingProgressScreen(self.config, runtime))


class CrackingProgressScreen(Screen):
    """Screen showing cracking progress"""
    def __init__(self, config: CrackConfig, runtime: str):
        super().__init__()
        self.config = config
        self.runtime = runtime
        self.process: Optional[subprocess.Popen] = None
        self.results = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="crack-main"):
            yield Label("⚡ Cracking in Progress", id="title")
            yield Label(f"Hash Type: {self.config.hash_type} | Attack: {self.config.attack_mode}", id="info-label")
            yield Label("Output:", id="output-label")
            yield ScrollableContainer(
                TextArea(id="output-area", read_only=True),
                id="output-container"
            )
            with Horizontal(id="button-row-3"):
                yield Button("Stop", id="stop-btn", variant="error")
                yield Button("Done", id="done-btn", variant="success")
        yield Footer()

    def on_mount(self):
        """Start the cracking process"""
        self.app.call_later(self._run_crack)

    async def _run_crack(self):
        """Run hashcat with selected parameters"""
        output_area = self.query_one("#output-area", TextArea)
        
        try:
            cmd = self._build_hashcat_command()
            output_area.text += f"🔧 Command: {' '.join(cmd)}\n\n"
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            
            # Stream output
            for line in self.process.stdout:
                output_area.text += line
                output_area.scroll_end()
                await asyncio.sleep(0.01)  # Prevent blocking
            
            self.process.wait()
            
            # Read results
            output_area.text += "\n✅ Cracking completed!"
            self._read_potfile()
            
        except Exception as e:
            output_area.text += f"\n❌ Error: {e}"

    def _build_hashcat_command(self) -> list:
        """Build hashcat command based on config"""
        hashcat_path = Path("tools/hashcat-6.2.6/hashcat.exe")
        if not hashcat_path.exists():
            hashcat_path = Path("hashcat.exe")
        
        # Mode map
        mode_map = {
            "md5": 0,
            "ntlm": 1000,
            # LM:NTLM pairs are preprocessed to NTLM-only in HashInputScreen.go_next.
            "lm_ntlm": 1000,
            "office2013": 9500,
            "sha1": 100,
            "sha256": 1400,
        }
        
        mode = mode_map.get(self.config.hash_type, 0)
        cmd = [str(hashcat_path), "-m", str(mode)]
        
        # Attack mode
        if self.config.attack_mode == "rockyou":
            cmd.extend(["-a", "0", self.config.hash_file, "rockyou_full.txt"])
        
        elif self.config.attack_mode == "custom_dict":
            cmd.extend(["-a", "0", self.config.hash_file, self.config.custom_dict])
        
        elif self.config.attack_mode == "adj_noun_digits":
            cmd.extend(["-a", "6", self.config.hash_file, "adj_noun_combo.txt", "?d?d"])
        
        elif self.config.attack_mode == "bruteforce":
            mask = self.config.custom_mask or "?a?a?a?a?d?d"
            cmd.extend(["-a", "3", self.config.hash_file, mask])
        
        elif self.config.attack_mode == "hybrid":
            cmd.extend(["-a", "6", self.config.hash_file, "rockyou_full.txt", "?d?d?d"])
        
        # Runtime limit
        if self.runtime and self.runtime != "0":
            cmd.extend(["--runtime", self.runtime])
        
        # Status monitoring
        cmd.extend(["--status", "--status-timer", "10"])
        
        return cmd

    def _read_potfile(self):
        """Read results from hashcat potfile"""
        potfile = Path("hashcat.potfile")
        if potfile.exists():
            self.results = potfile.read_text()
            output_area = self.query_one("#output-area", TextArea)
            output_area.text += f"\n{'='*50}\n📊 RESULTS:\n{'='*50}\n{self.results}"

    @on(Button.Pressed, "#stop-btn")
    def stop_crack(self):
        """Stop the cracking process"""
        if self.process:
            self.process.terminate()
            self.app.notify("⏹️  Process stopped")

    @on(Button.Pressed, "#done-btn")
    def go_done(self):
        """Go to results screen"""
        self.app.push_screen(ResultsScreen(self.results, self.config))


class ResultsScreen(Screen):
    """Screen showing final results"""
    def __init__(self, results: str, config: CrackConfig):
        super().__init__()
        self.results = results
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="results-main"):
            yield Label("🎉 Cracking Results", id="title")
            yield Label(f"Hash Type: {self.config.hash_type} | Attack: {self.config.attack_mode}", id="info-label")
            yield ScrollableContainer(
                TextArea(id="results-area", read_only=True, text=self.results),
                id="results-container"
            )
            with Horizontal(id="button-row-4"):
                yield Button("💾 Save Results", id="save-btn", variant="primary")
                yield Button("🔄 New Session", id="new-btn", variant="success")
                yield Button("❌ Exit", id="exit-btn")
        yield Footer()

    @on(Button.Pressed, "#save-btn")
    def save_results(self):
        """Save results to file"""
        output_file = Path(f"results_{self.config.hash_type}_{self.config.attack_mode}.txt")
        output_file.write_text(self.results)
        self.app.notify(f"✅ Results saved to {output_file}")

    @on(Button.Pressed, "#new-btn")
    def new_session(self):
        """Start new session"""
        self.app.pop_screen()
        self.app.pop_screen()
        self.app.pop_screen()

    @on(Button.Pressed, "#exit-btn")
    def exit_app(self):
        """Exit the application"""
        self.app.exit()


class HashCrackingApp(App):
    """Main TUI Application"""
    CSS = """
    Screen {
        background: $surface;
        color: $text;
    }
    
    #input-main, #attack-main, #crack-main, #results-main {
        width: 100%;
        height: 100%;
        border: heavy $accent;
    }
    
    #title {
        width: 100%;
        content-align: left middle;
        background: $boost;
        color: $text;
        text-style: bold;
        height: 3;
    }
    
    #info-label {
        width: 100%;
        background: $boost;
        color: $accent;
        height: 2;
    }
    
    Label {
        margin: 1;
    }
    
    Select {
        width: 50%;
    }
    
    Input {
        width: 1fr;
        margin: 1;
    }
    
    TextArea {
        width: 100%;
        height: 1fr;
    }
    
    #output-container, #results-container {
        width: 100%;
        height: 1fr;
        border: round $accent;
    }
    
    Horizontal {
        margin: 1;
    }
    
    Button {
        margin: 0 2;
    }
    
    #hash-type-row, #mode-row, #button-row-1, #button-row-2, #button-row-3, #button-row-4, #settings-panel {
        width: 100%;
    }
    """

    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self):
        super().__init__()
        self.config = CrackConfig()

    def on_mount(self):
        """Show initial screen"""
        self.push_screen(HashInputScreen(self.config))

    def action_quit(self):
        """Quit the app"""
        self.exit()


if __name__ == "__main__":
    app = HashCrackingApp()
    app.run()
