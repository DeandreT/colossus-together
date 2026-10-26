"""Interrupt regressions execute emitted instructions, using synthetic state only."""

import pytest
import test_injection_barriers as barriers
import test_native_constructor_hooks as constructors
import test_native_lifecycle_hooks as lifecycle
import test_native_render_hook as render
import test_native_retry_hook as retry


def run_lifecycle(interrupt_at):
    machine = lifecycle.Machine(lifecycle.config())
    machine.interrupt_at = interrupt_at
    machine.run("hook_canonical_admission")
    machine.assert_preserved()
    return machine


def check_each_boundary(make, run):
    baseline = make()
    run(baseline)
    baseline.assert_preserved()
    for index in range(len(baseline.boundaries)):
        machine = make()
        machine.interrupt_at = index
        run(machine)
        machine.assert_preserved()


def test_lifecycle_every_individual_boundary():
    # Includes every capture/restore transfer and each explicit delay slot.
    baseline = run_lifecycle(None)
    for index in range(len(baseline.boundaries)):
        run_lifecycle(index)


def test_lifecycle_mutation_detects_each_special_transfer_window(monkeypatch):
    baseline = run_lifecycle(None)
    windows = [i + 1 for i, line in enumerate(baseline.boundaries)
               if line.startswith(("pmfhi $at", "pmflo $at", "mfsa $at", "cfc1 $at",
                                   "lq $at", "lw $at"))]
    assert len(windows) == 8
    original = lifecycle.h.render
    monkeypatch.setattr(lifecycle.h, "render", lambda *args:
                        original(*args).replace("$at", "$k0"))
    for index in windows:
        with pytest.raises(AssertionError):
            run_lifecycle(index)


@pytest.mark.parametrize("family,name", [(constructors.h.CHARACTER, "character"),
                                        (constructors.h.ALIAS, "alias")])
@pytest.mark.parametrize("result", [0, 0x850000])
def test_constructor_interrupts(monkeypatch, family, name, result):
    monkeypatch.setattr(lifecycle, "h", constructors.h)
    check_each_boundary(lambda: constructors.Machine(constructors.config(), family, result),
                        lambda machine: machine.run("hook_" + name))


@pytest.mark.parametrize("state", [0, 1])
def test_retry_interrupts(state):
    check_each_boundary(lambda: retry.Machine(state=state), lambda machine: machine.run())


@pytest.mark.parametrize("config", [render.fenced_config, render.prepared_config,
                                     lambda: render.stacked_config(False),
                                     lambda: render.stacked_config(True)])
@pytest.mark.parametrize("fence_result", [0, 1])
def test_render_interrupts(config, fence_result):
    check_each_boundary(lambda: render.Machine(config(), fence_result=fence_result),
                         lambda machine: machine.run())


@pytest.mark.parametrize("fenced", [False, True])
def test_prepare_failure_interrupts_at_each_boundary(fenced):
    config = render.prepared_config(fenced)
    baseline = render.Machine(config, prepare_result=7)
    baseline.run()
    for index in range(len(baseline.boundaries)):
        machine = render.Machine(config, prepare_result=7)
        machine.interrupt_at = index
        machine.run()
        expected = machine.entry[0].copy()
        expected[2] = (expected[2] & ~lifecycle.MASK64) | 1
        machine.assert_context(machine.snapshot(), (expected, *machine.entry[1:]))
        assert machine.events == ["prepare_target"]
        assert machine.post is None
        assert machine.mem[config.stack_state] == 0
        assert machine.mem[config.stack_state + render.h.STACK_FAULT] == 1
        assert machine.mem[config.counter] == 0
        assert machine.mem[config.counter + render.h.COUNTER_FAULT] == 1


@pytest.mark.parametrize("kind", ["character", "alias", "retry", "render", "prepare"])
@pytest.mark.parametrize("register", ["RA", "SP"])
def test_outer_context_copy_mutation(monkeypatch, kind, register):
    # Corrupt only the outer RA/SP copy, leaving special-register transfers safe.
    # Thus these tests cannot pass merely because an earlier HI transfer failed.
    if kind in ("character", "alias"):
        module = constructors.h
        monkeypatch.setattr(lifecycle, "h", module)
        family = module.CHARACTER if kind == "character" else module.ALIAS
        machine = constructors.Machine(constructors.config(), family, 0x850000)

        def run():
            machine.run("hook_" + kind)

        frame = module.FRAME
    elif kind == "retry":
        module = retry.h
        machine = retry.Machine()
        run = machine.run
        frame = module.POST_FRAME
    else:
        module = render.h
        config = render.prepared_config if kind == "prepare" else render.fenced_config
        machine = render.Machine(config())
        run = machine.run
        frame = module.POST_FRAME
    original = module.render
    pair = (f"lq $at, {frame + getattr(module, 'PRE_' + register)}($sp)\n"
            f"sq $at, {getattr(module, 'OUTER_' + register)}($sp)")
    assert pair in original(machine.c, module.guard_expectations(machine.c))

    def mutated(*args):
        text = original(*args)
        return text.replace(pair, pair.replace("$at", "$k0"))

    monkeypatch.setattr(module, "render", mutated)
    # Retry caches its instruction list in __init__; reconstruct after mutation.
    if kind == "retry":
        machine = retry.Machine()
        run = machine.run
    machine.interrupt_at = "all"
    with pytest.raises((AssertionError, KeyError)):
        run()
        machine.assert_preserved()


def run_barrier(interrupt_at):
    machine = barriers.SourceMachine()
    machine.interrupt_at = interrupt_at
    expected = machine.context()

    def external(address, cpu):
        assert address == barriers.CONFIG.g + 0xC0CD0
        cpu.assert_context(cpu.context(), expected)
        assert cpu.field("gameplay_ready") == 0
        return True

    machine.execute("barrier_exit", external)
    return machine


def test_barrier_every_individual_boundary():
    baseline = run_barrier(None)
    for index in range(len(baseline.boundaries)):
        run_barrier(index)


def test_barrier_mutation_detects_reserved_scratch(monkeypatch):
    original = barriers.render
    monkeypatch.setattr(barriers, "render", lambda *args:
                        original(*args).replace("$at", "$k0"))
    with pytest.raises(AssertionError):
        run_barrier("all")
