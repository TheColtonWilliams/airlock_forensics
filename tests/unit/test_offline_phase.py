"""Hard rule 1: the provision phase never reaches for a network (tasks 1.5, 2B.4, 4.9).

``forensic-provision`` and ``forensic-import`` run ``site.yml`` offline with
``airlock_phase=provision``. This walks every task every role can run (following
``import_tasks``/``include_tasks``, blocks, ``import_role``/``include_role``, handlers and the
role-level ``when`` in ``site.yml``) and fails on anything that can run in that phase and would
fetch: an apt index refresh (``update_cache``, ``cache_valid_time``), ``get_url``, ``uri``,
``git``, an apt or ``.deb`` install from a URL, ``pip`` without ``--no-index``, a shell
``curl``/``wget``/``apt-get update``, or an apt install of a package the image phase does not
always install (apt would have to download it). An apt install that runs in both phases under
the same build-time conditions (say ``base_test_agent``) is fine: the image build already
installed what it names. One gated on something provisioning sets (``install_autopsy``, the
profile features) is not: the image build may have skipped it.

A task is treated as image-only when one of its ``when`` conditions (its own, or one inherited
from a block, an import or the role entry) is ``airlock_phase == 'image'`` (or
``!= 'provision'``) as a plain conjunct. Anything else is assumed to be able to run offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml

from airlock_common import assets
from airlock_provision import runner

REPO = Path(__file__).resolve().parents[2]
ANSIBLE = REPO / "ansible"
ROLES = ANSIBLE / "roles"

IMAGE_ONLY = {"airlock_phase == 'image'", "airlock_phase != 'provision'"}
INCLUDE_TASKS = {
    "import_tasks",
    "include_tasks",
    "ansible.builtin.import_tasks",
    "ansible.builtin.include_tasks",
}
INCLUDE_ROLE = {
    "import_role",
    "include_role",
    "ansible.builtin.import_role",
    "ansible.builtin.include_role",
}
APT = {"apt", "ansible.builtin.apt"}
FETCHERS = {
    "get_url",
    "ansible.builtin.get_url",
    "uri",
    "ansible.builtin.uri",
    "git",
    "ansible.builtin.git",
    "apt_key",
    "ansible.builtin.apt_key",
    "apt_repository",
    "ansible.builtin.apt_repository",
    "deb822_repository",
    "ansible.builtin.deb822_repository",
}
PIP = {"pip", "ansible.builtin.pip"}
COMMANDS = {"command", "shell", "ansible.builtin.command", "ansible.builtin.shell"}
INSTALL_STATES = {None, "present", "latest", "fixed", "build-dep"}
URL = re.compile(r"^\s*(https?|ftp)://", re.I)
SHELL_FETCH = [
    (re.compile(r"\b(curl|wget)\b"), "downloads with curl/wget"),
    (re.compile(r"\bapt(-get)?\s+(update|upgrade|dist-upgrade|full-upgrade)\b"), "apt update"),
    (re.compile(r"\bgit\s+(clone|fetch|pull)\b"), "git fetch"),
]
SIMPLE_VAR = re.compile(r"^\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$")


@dataclass(frozen=True)
class Task:
    role: str
    file: str
    body: dict[str, Any]
    conds: tuple[str, ...]

    @property
    def where(self) -> str:
        return f"{self.role}/{self.file}: {self.body.get('name', '(unnamed)')}"

    @property
    def conjuncts(self) -> list[str]:
        out: list[str] = []
        for c in self.conds:
            norm = re.sub(r"\s+", " ", c.strip()).replace('"', "'")
            if " or " in norm or "(" in norm:
                out.append(norm)
            else:
                out += [p.strip() for p in norm.split(" and ")]
        return out

    @property
    def can_run_at_provision(self) -> bool:
        return not any(c in IMAGE_ONLY for c in self.conjuncts)

    @property
    def always_in_image(self) -> bool:
        return all(c in IMAGE_ONLY for c in self.conjuncts)


def _when(entry: dict[str, Any]) -> list[str]:
    w = entry.get("when")
    if w is None:
        return []
    if isinstance(w, list):
        return [str(x) for x in w]
    return [str(w)]


def _load(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    assert isinstance(data, list), path
    return data


def _module(task: dict[str, Any]) -> tuple[str, Any]:
    for key, value in task.items():
        if key in APT | FETCHERS | PIP | COMMANDS | INCLUDE_TASKS | INCLUDE_ROLE:
            return key, value
        if key.startswith("ansible.builtin.") or key in ("package", "unarchive"):
            return key, value
    return "", None


def _walk_list(
    role: str, base: Path, rel: str, entries: list[dict[str, Any]], conds: tuple[str, ...],
    out: list[Task],
) -> None:  # fmt: skip
    for t in entries:
        c = conds + tuple(_when(t))
        if "block" in t:
            for key in ("block", "rescue", "always"):
                _walk_list(role, base, rel, t.get(key) or [], c, out)
            continue
        mod, arg = _module(t)
        if mod in INCLUDE_TASKS:
            name = arg if isinstance(arg, str) else (arg or {}).get("file")
            assert name and "{{" not in str(name), f"{role}/{rel}: unresolvable include {name!r}"
            _walk_file(role, base, str(name), c, out)
            continue
        if mod in INCLUDE_ROLE:
            other = (arg or {}).get("name")
            assert other and "{{" not in str(other), f"{role}/{rel}: unresolvable role {other!r}"
            _walk_role(str(other), c, out)
            continue
        out.append(Task(role, rel, t, c))


def _walk_file(role: str, base: Path, rel: str, conds: tuple[str, ...], out: list[Task]) -> None:
    path = base / rel
    assert path.is_file(), f"{role}: missing task file {rel}"
    _walk_list(role, base, rel, _load(path), conds, out)


def _walk_role(role: str, conds: tuple[str, ...], out: list[Task]) -> None:
    meta = ROLES / role / "meta" / "main.yml"
    if meta.is_file():
        for dep in (yaml.safe_load(meta.read_text(encoding="utf-8")) or {}).get(
            "dependencies"
        ) or []:
            name = dep if isinstance(dep, str) else dep.get("role") or dep.get("name")
            dep_when = tuple(_when(dep)) if isinstance(dep, dict) else ()
            _walk_role(str(name), conds + dep_when, out)
    _walk_file(role, ROLES / role / "tasks", "main.yml", conds, out)
    handlers = ROLES / role / "handlers" / "main.yml"
    if handlers.is_file():
        _walk_list(role, handlers.parent, "../handlers/main.yml", _load(handlers), conds, out)


def all_tasks() -> list[Task]:
    out: list[Task] = []
    for play in _load(ANSIBLE / "site.yml"):
        play_conds = tuple(_when(play))
        for key in ("pre_tasks", "tasks", "post_tasks"):
            _walk_list("site.yml", ANSIBLE, "site.yml", play.get(key) or [], play_conds, out)
        for entry in play.get("roles") or []:
            name = entry if isinstance(entry, str) else entry["role"]
            conds = play_conds + (tuple(_when(entry)) if isinstance(entry, dict) else ())
            _walk_role(str(name), conds, out)
    return out


TASKS = all_tasks()


# ------------------------------------------------------------------ variables


def _yaml_vars(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
    return data if isinstance(data, dict) else {}


GROUP_VARS: dict[str, Any] = {}
for _p in sorted((ANSIBLE / "group_vars" / "all").glob("*.yml")):
    GROUP_VARS.update(_yaml_vars(_p))


ROLE_DEFAULTS: dict[str, dict[str, Any]] = {
    p.name: {**_yaml_vars(p / "defaults" / "main.yml"), **_yaml_vars(p / "vars" / "main.yml")}
    for p in sorted(ROLES.iterdir())
}
ALL_DEFAULTS: dict[str, Any] = {k: v for d in ROLE_DEFAULTS.values() for k, v in d.items()}


def role_vars(task: Task) -> dict[str, Any]:
    """Group vars, every role's defaults (later plays see earlier roles'), the task's own role
    defaults and vars on top, then the task's ``vars``."""
    return {
        **GROUP_VARS,
        **ALL_DEFAULTS,
        **ROLE_DEFAULTS.get(task.role, {}),
        **(task.body.get("vars") or {}),
    }


def render_at_provision(value: Any, task: Task) -> Any:
    """``value`` as it renders with airlock_phase=provision; raises for unknown variables."""
    if not isinstance(value, str) or "{{" not in value:
        return value
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
    ctx = {**role_vars(task), "airlock_phase": "provision", "omit": "__omit__"}
    return env.from_string(value).render(**ctx).strip()


def falsy(rendered: Any) -> bool:
    return rendered in (False, None, 0, "", "False", "false", "no", "0", "__omit__")


def packages(value: Any, task: Task, depth: int = 0) -> set[str]:
    """Package names an apt ``name:`` installs (simple ``{{ var }}`` lists are expanded)."""
    if depth > 5:
        return {repr(value)}
    if isinstance(value, list):
        return set().union(*(packages(v, task, depth + 1) for v in value)) if value else set()
    if isinstance(value, str):
        m = SIMPLE_VAR.match(value.strip())
        if m:
            got = role_vars(task).get(m.group(1))
            if got is None:
                return {value}
            return packages(got, task, depth + 1)
        if "{{" in value:
            return {value}
        return {p.strip() for p in value.split(",") if p.strip()}
    return {repr(value)}


IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _provision_vars() -> set[str]:
    """Variables forensic-provision passes, and every default or fact derived from them.

    A ``when`` on one of these can be false while the image is built and true when
    provisioning (``install_autopsy``, the profile features), so it does not prove the image
    build ran the task.
    """
    names = set(runner.build_vars(assets.AssetReport(ok=True))) | {"airlock_phase"}
    sources: dict[str, str] = {}
    for role_dir in sorted(ROLES.iterdir()):
        for k, v in _yaml_vars(role_dir / "defaults" / "main.yml").items():
            sources[k] = sources.get(k, "") + " " + str(v)
    for t in TASKS:
        mod, arg = _module(t.body)
        if mod == "ansible.builtin.set_fact" and isinstance(arg, dict):
            for k, v in arg.items():
                sources[k] = sources.get(k, "") + " " + str(v) + " " + " ".join(t.conds)
    grew = True
    while grew:
        grew = False
        for k, text in sources.items():
            if k not in names and set(IDENT.findall(text)) & names:
                names.add(k)
                grew = True
    return names


def _bool(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes", "on", "1")


def true_in_image_build(conjunct: str, task: Task) -> bool:
    """The conjunct holds in an image build with the default variables (unknown: False)."""
    if conjunct in IMAGE_ONLY:
        return True
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
    env.filters["bool"] = _bool
    try:
        out = env.from_string("{{ (" + conjunct + ") | bool }}").render(
            **{**role_vars(task), "airlock_phase": "image"}
        )
    except (jinja2.TemplateError, TypeError, ValueError):
        return False
    return out == "True"


def image_packages() -> set[str]:
    """Every package an apt task installs on every image build with the default variables."""
    got: set[str] = set()
    for t in TASKS:
        mod, arg = _module(t.body)
        if mod not in APT or not isinstance(arg, dict):
            continue
        if not all(true_in_image_build(c, t) for c in t.conjuncts):
            continue
        if arg.get("state") in INSTALL_STATES and arg.get("name") is not None:
            got |= packages(arg["name"], t)
    return got


def ran_in_the_same_image_build(task: Task, provision_vars: set[str]) -> bool:
    """The image build ran this very task under the same conditions it has now: no phase
    condition and no condition on anything provisioning sets."""
    return not any(set(IDENT.findall(c)) & provision_vars for c in task.conjuncts)


# ------------------------------------------------------------------ the check


def offline_problems(tasks: list[Task]) -> list[str]:
    on_image = image_packages()
    provision_vars = _provision_vars()
    problems: list[str] = []
    for t in tasks:
        if not t.can_run_at_provision:
            continue
        mod, arg = _module(t.body)
        args = arg if isinstance(arg, dict) else {}
        if mod in FETCHERS:
            problems.append(f"{t.where}: {mod} can run when airlock_phase is provision")
        elif mod in ("unarchive", "ansible.builtin.unarchive") and URL.match(
            str(args.get("src", ""))
        ):
            problems.append(f"{t.where}: unarchive from a URL at provision")
        elif mod in APT:
            for key in ("update_cache", "cache_valid_time", "upgrade"):
                if key not in args:
                    continue
                try:
                    rendered = render_at_provision(args[key], t)
                except jinja2.UndefinedError as exc:
                    problems.append(f"{t.where}: {key} cannot be checked ({exc})")
                    continue
                if not falsy(rendered):
                    problems.append(f"{t.where}: apt {key}={rendered!r} at provision")
            if URL.match(str(args.get("deb", ""))):
                problems.append(f"{t.where}: apt deb from a URL at provision")
            state = args.get("state")
            if args.get("name") is not None and state in INSTALL_STATES:
                if state == "latest":
                    problems.append(f"{t.where}: apt state=latest at provision")
                missing = sorted(packages(args["name"], t) - on_image)
                if missing and not ran_in_the_same_image_build(t, provision_vars):
                    problems.append(
                        f"{t.where}: apt would download {missing} at provision (not installed "
                        "by every image build)"
                    )
        elif mod in PIP:
            extra = str(args.get("extra_args", ""))
            if "--no-index" not in extra:
                problems.append(f"{t.where}: pip without --no-index at provision")
        elif mod in COMMANDS:
            text = arg if isinstance(arg, str) else " ".join(
                str(x) for x in (args.get("argv") or [args.get("cmd", "")])
            )  # fmt: skip
            for rx, what in SHELL_FETCH:
                if rx.search(text):
                    problems.append(f"{t.where}: {what} at provision")
            if re.search(r"\bpip3?\b.*\binstall\b", text) and "--no-index" not in text:
                problems.append(f"{t.where}: pip install without --no-index at provision")
    return problems


def test_walker_sees_every_role_and_the_known_tasks() -> None:
    roles = {t.role for t in TASKS}
    assert {p.name for p in ROLES.iterdir() if (p / "tasks" / "main.yml").is_file()} <= roles
    names = {str(t.body.get("name", "")) for t in TASKS}
    assert any("base packages" in n for n in names)
    assert any("Java 17" in n for n in names)


def test_no_task_reaches_for_a_network_when_provisioning() -> None:
    problems = offline_problems(TASKS)
    assert problems == [], "\n".join(problems)


def test_base_packages_are_installed_by_every_image() -> None:
    assert set(GROUP_VARS.get("base_packages") or role_vars(TASKS[0])["base_packages"]) <= (
        image_packages()
    )


def test_autopsy_prerequisites_are_on_every_image() -> None:
    """4.9: a later profile can turn Autopsy on offline (Java 17 and libraries are baked)."""
    autopsy = _yaml_vars(ROLES / "tools_autopsy" / "defaults" / "main.yml")
    assert set(autopsy["tools_autopsy_packages"]) <= image_packages()


# ------------------------------------------------------------------ the checker itself


def _fake(body: dict[str, Any], *conds: str, role: str = "base") -> Task:
    return Task(role, "fake.yml", body, tuple(conds))


@pytest.mark.parametrize(
    "body",
    [
        # The defect this test was written for: cache_valid_time with no phase guard.
        {
            "name": "base",
            "ansible.builtin.apt": {
                "name": "{{ base_packages }}",
                "update_cache": "{{ airlock_phase == 'image' }}",
                "cache_valid_time": 3600,
            },
        },
        {"name": "refresh", "ansible.builtin.apt": {"update_cache": True}},
        {"name": "fetch", "ansible.builtin.get_url": {"url": "https://x", "dest": "/x"}},
        {"name": "call", "ansible.builtin.uri": {"url": "https://x"}},
        {"name": "wheel", "ansible.builtin.pip": {"name": "x", "virtualenv": "/v"}},
        {"name": "dl", "ansible.builtin.command": {"argv": ["curl", "-o", "/x", "https://x"]}},
        {"name": "upd", "ansible.builtin.shell": "apt-get update && true"},
        {"name": "remote", "ansible.builtin.apt": {"deb": "https://x/y.deb"}},
        {"name": "new pkg", "ansible.builtin.apt": {"name": ["not-on-the-image-xyz"]}},
        # Autopsy's Java at provision with only the install_autopsy role gate (finding 2).
        {"name": "java", "ansible.builtin.apt": {"name": ["openjdk-99-jre"], "state": "present"}},
    ],
    ids=lambda b: b["name"],
)
def test_checker_catches_network_tasks(body: dict[str, Any]) -> None:
    assert offline_problems([_fake(body, "install_autopsy | bool")])


@pytest.mark.parametrize(
    "conds",
    [
        ("airlock_phase == 'image'",),
        ('airlock_phase == "image"',),
        ("airlock_phase != 'provision'",),
        ("install_autopsy | bool and airlock_phase == 'image'",),
        ("install_autopsy | bool", "airlock_phase == 'image'"),
    ],
)
def test_checker_accepts_image_only_guards(conds: tuple[str, ...]) -> None:
    body = {"name": "fetch", "ansible.builtin.get_url": {"url": "https://x", "dest": "/x"}}
    assert offline_problems([_fake(body, *conds)]) == []


def test_checker_accepts_packages_the_image_build_installed_the_same_way() -> None:
    body = {"name": "agent", "ansible.builtin.apt": {"name": ["not-on-the-image-xyz"]}}
    assert offline_problems([_fake(body, "base_test_agent | bool")]) == []
    assert offline_problems([_fake(body, "tools_autopsy_features.autopsy | default(false)")])
    assert offline_problems([_fake(body, "airlock_phase == 'provision'")])


def test_checker_does_not_treat_or_as_a_guard() -> None:
    body = {"name": "fetch", "ansible.builtin.get_url": {"url": "https://x", "dest": "/x"}}
    assert offline_problems([_fake(body, "airlock_phase == 'image' or force | bool")])


def test_checker_follows_blocks_and_imports(tmp_path: Path) -> None:
    out: list[Task] = []
    (tmp_path / "inner.yml").write_text(
        "- name: fetch\n  ansible.builtin.get_url: {url: 'https://x', dest: /x}\n",
        encoding="utf-8",
    )
    entries = [
        {
            "block": [{"ansible.builtin.import_tasks": "inner.yml"}],
            "when": "airlock_phase == 'image'",
        },
        {"ansible.builtin.include_tasks": {"file": "inner.yml"}},
    ]  # fmt: skip
    _walk_list("r", tmp_path, "main.yml", entries, (), out)
    assert [t.can_run_at_provision for t in out] == [False, True]
    assert len(offline_problems(out)) == 1


# ------------------------------------------------------------------ profile.json (finding 11)
# ASSETS is writable from any computer and profile.json is not signed, so no role may read it:
# features reach the roles only as forensic-provision's schema-checked airlock_profile_features.

PROFILE_JSON = "profile.json"
JINJA_BLOCK = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
FEATURE_ROLES = {
    "tools_ai": "tools_ai_staged",
    "tools_autopsy": "tools_autopsy_staged",
    "tools_eztools": "tools_eztools_staged",
}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _strings(k) + _strings(v)]
    if isinstance(value, list | tuple):
        return [s for v in value for s in _strings(v)]
    return []


def profile_json_problems(tasks: list[Task], extra_roots: list[Path] | None = None) -> list[str]:
    """Every task, role variable or template expression that names profile.json."""
    problems = [
        f"{t.where}: names {PROFILE_JSON}"
        for t in tasks
        if any(PROFILE_JSON in s for s in _strings(t.body))
    ]
    roots = extra_roots if extra_roots is not None else [ROLES]
    for root in roots:
        for sub in ("defaults", "vars"):
            for path in sorted(root.glob(f"*/{sub}/*.yml")):
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                if any(PROFILE_JSON in s for s in _strings(data)):
                    problems.append(f"{path.relative_to(root)}: names {PROFILE_JSON}")
        for path in sorted(root.glob("*/templates/**/*.j2")):
            for block in JINJA_BLOCK.findall(path.read_text(encoding="utf-8")):
                if PROFILE_JSON in block:
                    problems.append(f"{path.relative_to(root)}: reads {PROFILE_JSON}")
    if extra_roots is None:
        for path in [ANSIBLE / "site.yml", *sorted((ANSIBLE / "group_vars").rglob("*.yml"))]:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            for s in _strings(data):
                if PROFILE_JSON in s and any(m in s for m in ("{{", "{%")):
                    problems.append(f"{path.relative_to(ANSIBLE)}: templates {PROFILE_JSON}")
    return problems


def test_no_role_reads_profile_json() -> None:
    problems = profile_json_problems(TASKS)
    assert problems == [], "\n".join(problems)


@pytest.mark.parametrize("role", sorted(FEATURE_ROLES))
def test_features_come_only_from_forensic_provision(role: str) -> None:
    """Each staged feature is on only for a real true from airlock_profile_features."""
    defaults = _yaml_vars(ROLES / role / "defaults" / "main.yml")
    assert defaults[f"{role}_features"] == "{{ airlock_profile_features | default({}) }}"
    body = _load(ROLES / role / "tasks" / "profile_features.yml")
    assert len(body) == 1, f"{role}: profile_features.yml must only set the staged features"
    staged = body[0]["ansible.builtin.set_fact"][FEATURE_ROLES[role]]
    assert staged, role
    for name, expr in staged.items():
        assert expr == f"{{{{ ({role}_features.{name} | default(false)) is sameas true }}}}", (
            f"{role}: {name}"
        )


@pytest.mark.parametrize(
    "body",
    [
        {"name": "read", "ansible.builtin.slurp": {"src": "/media/ASSETS/profile.json"}},
        {"name": "look", "ansible.builtin.stat": {"path": "{{ mnt }}/profile.json"}},
        {"name": "vars", "ansible.builtin.include_vars": {"file": "/a/profile.json"}},
        {
            "name": "fact",
            "ansible.builtin.set_fact": {"x": "{{ lookup('file', '/p/profile.json') }}"},
        },
        {"name": "cat", "ansible.builtin.command": {"argv": ["cat", "/a/profile.json"]}},
    ],
    ids=lambda b: b["name"],
)
def test_profile_json_checker_catches_reads(body: dict[str, Any]) -> None:
    assert profile_json_problems([_fake(body, role="tools_ai")], extra_roots=[])


def test_profile_json_checker_reads_defaults_and_templates(tmp_path: Path) -> None:
    (tmp_path / "r" / "defaults").mkdir(parents=True)
    (tmp_path / "r" / "templates").mkdir()
    (tmp_path / "r" / "defaults" / "main.yml").write_text(
        "r_features: \"{{ lookup('file', '/a/profile.json') | from_json }}\"\n", encoding="utf-8"
    )
    (tmp_path / "r" / "templates" / "x.j2").write_text(
        "# profile.json is read by forensic-provision only\n"
        "{{ lookup('file', '/a/profile.json') }}\n",
        encoding="utf-8",
    )
    assert len(profile_json_problems([], extra_roots=[tmp_path])) == 2
