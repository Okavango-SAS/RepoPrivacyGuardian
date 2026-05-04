from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _validate_screenshot(path: Path, *, min_width: int, min_height: int) -> None:
    try:
        from PIL import Image, ImageStat
    except ImportError as exc:  # pragma: no cover - environment preflight
        raise RuntimeError("Pillow is required for visual QA screenshots.") from exc

    with Image.open(path) as image:
        width, height = image.size
        if width < min_width or height < min_height:
            raise RuntimeError(f"{path.name} is too small: {width}x{height}")
        stat = ImageStat.Stat(image.convert("L"))
        extrema = stat.extrema[0]
        if extrema[0] == extrema[1]:
            raise RuntimeError(f"{path.name} appears blank or single-color")


def _capture_root(root: object, path: Path) -> None:
    try:
        from PIL import ImageGrab
    except ImportError as exc:  # pragma: no cover - environment preflight
        raise RuntimeError("Pillow ImageGrab is required for GUI visual QA.") from exc

    root.update_idletasks()
    root.update()
    x = root.winfo_rootx()
    y = root.winfo_rooty()
    width = root.winfo_width()
    height = root.winfo_height()
    image = ImageGrab.grab((x, y, x + width, y + height))
    image.save(path)


def _settings_payload(appearance: str) -> dict[str, object]:
    import Repo_Privacy_Guardian as rpg

    return {
        "schema_version": rpg.GUI_SETTINGS_SCHEMA_VERSION,
        "setup_completed": True,
        "gui_locale": "en",
        "gui_appearance": appearance,
        "root": str(REPO_ROOT),
        "policy": str(rpg.default_policy_path()),
        "report_dir": str(REPO_ROOT / "Audit_Results"),
        "report_json": "",
        "max_matches": "20",
        "strict_profile": "default",
        "suppressions": "",
        "public_only": False,
        "dry_run": True,
        "low_confidence_blocking": False,
        "audit_litellm_incident": False,
        "audit_github_hardening": False,
        "open_report": False,
    }


def run_visual_qa(output_root: Path, *, min_width: int, min_height: int) -> Path:
    import Repo_Privacy_Guardian as rpg

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    tabs = (
        ("audit", "_audit_tab_name"),
        ("reports", "_reports_tab_name"),
        ("prompts", "_prompts_tab_name"),
        ("repair", "_repair_tab_name"),
    )
    with tempfile.TemporaryDirectory(prefix="rpg-gui-visual-qa-") as temp_dir:
        settings_path = Path(temp_dir) / "gui_settings.json"
        original_settings_env = os.environ.get(rpg.GUI_SETTINGS_ENV_VAR)
        try:
            os.environ[rpg.GUI_SETTINGS_ENV_VAR] = str(settings_path)
            settings_path.write_text(
                json.dumps(_settings_payload("system"), indent=2),
                encoding="utf-8",
            )
            app = rpg.GuiApp()
            try:
                app.root.geometry("1280x860+80+80")
                app.root.update_idletasks()
                app.root.update()
                for appearance in ("system", "light", "dark"):
                    if appearance != "system":
                        app._on_gui_appearance_selected(  # noqa: SLF001
                            rpg.gui_appearance_label(appearance, app._current_locale())  # noqa: SLF001
                        )
                    for tab_slug, tab_attr in tabs:
                        app._set_active_flow_tab(getattr(app, tab_attr))  # noqa: SLF001
                        screenshot_path = run_dir / f"{appearance}-{tab_slug}.png"
                        _capture_root(app.root, screenshot_path)
                        _validate_screenshot(
                            screenshot_path,
                            min_width=min_width,
                            min_height=min_height,
                        )
            finally:
                app.root.destroy()
        finally:
            if original_settings_env is None:
                os.environ.pop(rpg.GUI_SETTINGS_ENV_VAR, None)
            else:
                os.environ[rpg.GUI_SETTINGS_ENV_VAR] = original_settings_env

    manifest = {
        "run_id": run_id,
        "screenshots": sorted(path.name for path in run_dir.glob("*.png")),
        "min_width": min_width,
        "min_height": min_height,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture basic GUI visual QA screenshots.")
    parser.add_argument(
        "--output-root",
        default=str(REPO_ROOT / ".local-meta" / "visual-qa"),
        help="Directory where timestamped screenshot runs are written.",
    )
    parser.add_argument("--min-width", type=int, default=900)
    parser.add_argument("--min-height", type=int, default=620)
    args = parser.parse_args()

    try:
        run_dir = run_visual_qa(Path(args.output_root), min_width=args.min_width, min_height=args.min_height)
    except Exception as exc:
        print(f"[ERROR] Visual QA failed: {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] Visual QA screenshots written to {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
