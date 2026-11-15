## Task

<!-- The task number(s) from docs/build-plan.md. The first commit line starts with it, for example "3A.5: add write tracer". -->

Task:

## What changed and why

<!-- Plain words. If this is a design change, link the new docs/decision-log.md entry. -->

## One control = one task + one test + one doc line

- [ ] Code or config at the path the task names (one control per Ansible task file, with a comment naming its test)
- [ ] A test that fails without this change and passes with it: <!-- path -->
- [ ] One line of documentation in docs/: <!-- path -->
- [ ] Status cell updated in docs/build-plan.md
- [ ] Every new download is in `ansible/group_vars/all/pins.yml` with URL, version and SHA-256 (no guessed hashes)
- [ ] Any new third-party dependency has a decision-log entry stating its licence

## Checks I ran

- [ ] `scripts/lint.sh`
- [ ] `tests/run-unit.sh`
- [ ] `sudo tests/run-functional.sh` (or: the tests that cannot run here, and why)
- [ ] `tests/run-qemu-tests.sh` on a built image (only when the image changes)

## Hard rules

- [ ] The running drive gets no network use, download, update check, or listener
- [ ] Nothing writes to an evidence device; nothing mounts a target
- [ ] No dependence on a hardware vendor or model
- [ ] No secrets, no evidence data, no sexual, violent or otherwise sensitive media (fixtures are generated shapes and text)
- [ ] No age or child detection
- [ ] The software read-only layer is called the "software read-only policy", never a write blocker
- [ ] AI output is labelled, carries model and prompt SHA-256, and is never presented as evidence
- [ ] Evidence-derived text is treated as data: never passed to a shell or into a model instruction
