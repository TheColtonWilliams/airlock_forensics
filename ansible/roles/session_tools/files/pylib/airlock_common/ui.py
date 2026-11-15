"""Prompts: whiptail when available on a TTY, plain input() otherwise.

Every prompt has a command-line flag equivalent; callers only prompt when the flag is absent
and ``--yes``/non-interactive mode is off.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Sequence


class NonInteractiveError(RuntimeError):
    """A value is needed but there is no TTY and no flag supplied it."""


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _whiptail() -> str | None:
    return shutil.which("whiptail") if interactive() else None


def info(title: str, text: str) -> None:
    wt = _whiptail()
    if wt:
        subprocess.run([wt, "--title", title, "--msgbox", text, "20", "76"], check=False)
    else:
        print(f"== {title} ==\n{text}\n")


def ask_text(title: str, prompt: str, default: str = "", *, flag: str = "") -> str:
    if not interactive():
        if default:
            return default
        raise NonInteractiveError(f"{title}: no value given; pass {flag or 'the matching flag'}")
    wt = _whiptail()
    if wt:
        cp = subprocess.run(
            [wt, "--title", title, "--inputbox", prompt, "10", "76", default],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if cp.returncode != 0:
            raise KeyboardInterrupt
        return cp.stderr.strip()
    answer = input(f"{prompt} [{default}]: ").strip()
    return answer or default


def ask_yes_no(title: str, prompt: str, *, default: bool = False, flag: str = "") -> bool:
    if not interactive():
        raise NonInteractiveError(f"{title}: no answer given; pass {flag or 'the matching flag'}")
    wt = _whiptail()
    if wt:
        args = [wt, "--title", title]
        if not default:
            args.append("--defaultno")
        cp = subprocess.run([*args, "--yesno", prompt, "12", "76"], check=False)
        return cp.returncode == 0
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{prompt} {suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def ask_choice(
    title: str,
    prompt: str,
    choices: Sequence[tuple[str, str]],
    *,
    default: str = "",
    flag: str = "",
) -> str:
    """``choices`` is a list of (value, description). Returns the chosen value."""
    if not interactive():
        if default:
            return default
        raise NonInteractiveError(f"{title}: no choice given; pass {flag or 'the matching flag'}")
    wt = _whiptail()
    if wt:
        items: list[str] = []
        for value, desc in choices:
            items += [value, desc]
        args = [wt, "--title", title]
        if default:
            args += ["--default-item", default]
        cp = subprocess.run(
            [*args, "--menu", prompt, "20", "76", str(min(len(choices), 12)), *items],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if cp.returncode != 0:
            raise KeyboardInterrupt
        return cp.stderr.strip()
    print(prompt)
    for i, (value, desc) in enumerate(choices, 1):
        mark = "*" if value == default else " "
        print(f" {mark}{i}. {value}: {desc}")
    while True:
        answer = input("Number or name: ").strip()
        if not answer and default:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1][0]
        for value, _ in choices:
            if answer == value:
                return value
        print("Not one of the choices. Try again.")


def ask_checklist(
    title: str, prompt: str, choices: Sequence[tuple[str, str, bool]], *, flag: str = ""
) -> list[str]:
    """``choices`` is (value, description, on). Returns the selected values in choice order."""
    if not interactive():
        return [v for v, _, on in choices if on]
    wt = _whiptail()
    if wt:
        items: list[str] = []
        for value, desc, on in choices:
            items += [value, desc, "ON" if on else "OFF"]
        cp = subprocess.run(
            [
                wt,
                "--title",
                title,
                "--separate-output",
                "--checklist",
                prompt,
                "20",
                "76",
                str(min(len(choices), 12)),
                *items,
            ],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if cp.returncode != 0:
            raise KeyboardInterrupt
        picked = set(cp.stderr.split())
        return [v for v, _, _ in choices if v in picked]
    print(prompt)
    for value, desc, on in choices:
        print(f"  [{'x' if on else ' '}] {value}: {desc}")
    answer = input("Comma-separated names (empty keeps the marked ones): ").strip()
    if not answer:
        return [v for v, _, on in choices if on]
    wanted = {a.strip() for a in answer.split(",") if a.strip()}
    return [v for v, _, _ in choices if v in wanted]


def confirm_typed(title: str, prompt: str, expected: str) -> bool:
    """The operator must type ``expected`` back exactly."""
    if not interactive():
        raise NonInteractiveError(
            f"{title}: typed confirmation needed; pass --yes with the exact value"
        )
    answer = ask_text(title, f"{prompt}\nType {expected} to confirm.")
    return answer == expected
