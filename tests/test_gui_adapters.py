from __future__ import annotations

from pathlib import Path
from typing import Any

from repo_privacy_guardian.gui import background as gui_background
from repo_privacy_guardian.gui import dialogs as gui_dialogs
from repo_privacy_guardian.gui import navigation as gui_navigation


class FakeVariable:
    def __init__(self, value: str = "") -> None:
        self.value = value

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


class FakeFileDialog:
    def __init__(self, *, directory: str = "", open_file: str = "", save_file: str = "") -> None:
        self.directory = directory
        self.open_file = open_file
        self.save_file = save_file
        self.calls: list[tuple[str, dict[str, object]]] = []

    def askdirectory(self, **kwargs: object) -> str:
        self.calls.append(("askdirectory", kwargs))
        return self.directory

    def askopenfilename(self, **kwargs: object) -> str:
        self.calls.append(("askopenfilename", kwargs))
        return self.open_file

    def asksaveasfilename(self, **kwargs: object) -> str:
        self.calls.append(("asksaveasfilename", kwargs))
        return self.save_file


class FakeThread:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.started = False

    def start(self) -> None:
        self.started = True


class ImmediateRoot:
    def __init__(self) -> None:
        self.scheduled: list[tuple[int, str]] = []

    def after(self, delay_ms: int, callback: Any) -> str:
        self.scheduled.append((delay_ms, getattr(callback, "__name__", "<callback>")))
        callback()
        return "after-id"


class FakeTab:
    def __init__(self) -> None:
        self.forgotten = False

    def grid_forget(self) -> None:
        self.forgotten = True


class FakeSegmentedButton:
    def __init__(self) -> None:
        self.selected = ""

    def set(self, value: str) -> None:
        self.selected = value


class FakeFlowTabs:
    def __init__(self) -> None:
        self._tab_dict = {"Audit": FakeTab(), "Reports": FakeTab(), "Repair": FakeTab()}
        self._current_name = "Audit"
        self._segmented_button = FakeSegmentedButton()
        self._name_list = ["Audit", "Reports", "Repair"]
        self.renames: list[tuple[str, str]] = []
        self.grid_current_calls = 0
        self.grid_forget_exclude = ""

    def rename(self, current_name: str, desired_name: str) -> None:
        self.renames.append((current_name, desired_name))

    def _set_grid_current_tab(self) -> None:
        self.grid_current_calls += 1

    def _grid_forget_all_tabs(self, *, exclude_name: str) -> None:
        self.grid_forget_exclude = exclude_name


def test_dialog_initial_dir_uses_existing_paths_and_fallback(tmp_path: Path) -> None:
    fallback = tmp_path / "fallback"
    fallback.mkdir()
    directory = tmp_path / "repo"
    directory.mkdir()
    file_path = directory / "report.json"
    file_path.write_text("{}", encoding="utf-8")

    assert gui_dialogs.dialog_initial_dir("", default_dir=fallback) == str(fallback)
    assert gui_dialogs.dialog_initial_dir(str(directory), default_dir=fallback) == str(directory)
    assert gui_dialogs.dialog_initial_dir(str(file_path), default_dir=fallback) == str(directory)
    assert gui_dialogs.dialog_initial_dir(str(directory / "missing.json"), default_dir=fallback) == str(directory)
    assert gui_dialogs.dialog_initial_dir(str(tmp_path / "missing" / "report.json"), default_dir=fallback) == str(
        fallback
    )


def test_browse_dialog_helpers_set_target_only_when_selected(tmp_path: Path) -> None:
    initial_dir = str(tmp_path)
    target = FakeVariable("old")
    dialog = FakeFileDialog(directory=str(tmp_path / "selected"))

    assert gui_dialogs.browse_directory(
        dialog,
        target,
        title="Choose",
        initial_dir=initial_dir,
        mustexist=True,
    )
    assert target.get() == str(tmp_path / "selected")
    assert dialog.calls == [
        (
            "askdirectory",
            {"title": "Choose", "initialdir": initial_dir, "mustexist": True},
        )
    ]

    cancelled = FakeFileDialog()
    assert not gui_dialogs.browse_existing_file(
        cancelled,
        target,
        title="Open",
        initial_dir=initial_dir,
        filetypes=[("JSON", "*.json")],
    )
    assert target.get() == str(tmp_path / "selected")


def test_background_runner_starts_daemon_thread_with_args() -> None:
    created: list[FakeThread] = []

    def factory(**kwargs: object) -> FakeThread:
        thread = FakeThread(**kwargs)
        created.append(thread)
        return thread

    def target(_value: str) -> None:
        raise AssertionError("target should not run in fake thread factory")

    thread = gui_background.start_daemon_worker(target=target, args=("repo",), thread_factory=factory)

    assert thread is created[0]
    assert thread.started
    assert thread.kwargs["target"] is target
    assert thread.kwargs["args"] == ("repo",)
    assert thread.kwargs["daemon"] is True


def test_background_ui_scheduling_and_blocking_bool_prompt() -> None:
    root = ImmediateRoot()
    emitted: list[str] = []

    result = gui_background.schedule_on_ui(root, lambda: emitted.append("scheduled"), delay_ms=5)
    accepted = gui_background.ask_bool_on_ui(root, lambda: "yes")

    assert result == "after-id"
    assert accepted is True
    assert emitted == ["scheduled"]
    assert [delay for delay, _name in root.scheduled] == [5, 0]


def test_navigation_select_flow_tab_without_delayed_cleanup() -> None:
    flow_tabs = FakeFlowTabs()

    assert gui_navigation.select_flow_tab_without_delayed_cleanup(flow_tabs, "Reports")

    assert flow_tabs._current_name == "Reports"
    assert flow_tabs._tab_dict["Audit"].forgotten
    assert flow_tabs._segmented_button.selected == "Reports"
    assert flow_tabs.grid_current_calls == 1
    assert flow_tabs.grid_forget_exclude == "Reports"


def test_navigation_rename_flow_tabs_preserves_order_and_active_mapping() -> None:
    flow_tabs = FakeFlowTabs()
    current = gui_navigation.FlowTabNames(
        audit="Audit",
        reports="Reports",
        prompts="Prompts",
        settings="Settings",
        repair="Repair",
    )
    desired = gui_navigation.FlowTabNames(
        audit="Auditoria",
        reports="Informes",
        prompts="Prompts",
        settings="Ajustes",
        repair="Reparar",
    )

    gui_navigation.rename_flow_tabs(flow_tabs, current=current, desired=desired)

    assert flow_tabs.renames == [
        ("Audit", "Auditoria"),
        ("Reports", "Informes"),
        ("Settings", "Ajustes"),
        ("Repair", "Reparar"),
    ]
    assert flow_tabs._name_list == ["Auditoria", "Informes", "Prompts", "Ajustes", "Reparar"]
    assert (
        gui_navigation.active_flow_tab_after_rename("Reports", current=current, desired=desired)
        == "Informes"
    )
    assert gui_navigation.active_flow_tab_after_rename("Unknown", current=current, desired=desired) is None
