"""B2 + B3 from docs/plans/0.3-validation-plan.md: prove the reconciler's
rollback is actually resilient.

B2 — rollback-of-rollback: if one rollback action throws, the next one
still runs. Without this, a buggy or transient REMOVE_NETWORK failure
would silently leak FREE_SUBNET (orphan subnet allocations forever).

B3 — PODMAN_RUN rollback: today PODMAN_RUN is the last action in the
plan, so its `_ROLLBACK_MAP` entry (PODMAN_RM) is never exercised on the
happy path. Test it directly so adding a post-RUN action later (e.g.,
a post-start hook) can't quietly leak containers.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from brig.cell.reconciler import (
    Action,
    ActionType,
    _rollback,
    apply,
)


def _completed(rc: int = 0, stdout: str = "", stderr: str = ""):
    import subprocess
    return subprocess.CompletedProcess([], rc, stdout, stderr)


class TestRollbackResilience(unittest.TestCase):
    """If one rollback action throws, _rollback must continue."""

    def test_rollback_continues_after_one_action_throws(self):
        # Two completed actions: ALLOCATE_SUBNET then CREATE_NETWORK.
        # Both have rollback entries (FREE_SUBNET and REMOVE_NETWORK).
        completed = [
            Action(ActionType.ALLOCATE_SUBNET, "cellA"),
            Action(ActionType.CREATE_NETWORK, "cellA"),
        ]

        calls: list[ActionType] = []

        def fake_execute(action, result):
            calls.append(action.type)
            # Make the FIRST rollback (REMOVE_NETWORK) throw. The next
            # one (FREE_SUBNET) must still run.
            if action.type == ActionType.REMOVE_NETWORK:
                raise RuntimeError("podman network rm failed")

        with patch("brig.cell.reconciler._execute_action", side_effect=fake_execute):
            _rollback(completed)

        # Rollback runs in reverse order: REMOVE_NETWORK then FREE_SUBNET.
        # Both must have been attempted even though the first one threw.
        self.assertIn(ActionType.REMOVE_NETWORK, calls)
        self.assertIn(ActionType.FREE_SUBNET, calls)
        # And the order must be the reversed-completion order.
        self.assertEqual(
            calls.index(ActionType.REMOVE_NETWORK) + 1,
            calls.index(ActionType.FREE_SUBNET),
        )

    def test_apply_returns_failure_context_when_rollback_runs(self):
        # If the forward action fails, the failure tuple is preserved on
        # the result even after rollback runs.
        actions = [
            Action(ActionType.ALLOCATE_SUBNET, "cellA"),
            Action(ActionType.CREATE_NETWORK, "cellA"),
        ]

        def fake_execute(action, result):
            if action.type == ActionType.CREATE_NETWORK:
                raise RuntimeError("subnet collision")
            # Rollback actions are no-ops in this test.

        with patch("brig.cell.reconciler._execute_action", side_effect=fake_execute):
            result = apply(actions)

        self.assertFalse(result.success)
        self.assertEqual(len(result.actions_failed), 1)
        failed_action, failed_msg = result.actions_failed[0]
        self.assertEqual(failed_action.type, ActionType.CREATE_NETWORK)
        self.assertIn("subnet collision", failed_msg)


class TestPodmanRunRollbackWiring(unittest.TestCase):
    """B3: PODMAN_RUN has a rollback entry (PODMAN_RM) and it actually fires
    when invoked. This is the safety net for any future plan that adds an
    action *after* PODMAN_RUN."""

    def test_podman_run_rollback_entry_exists(self):
        from brig.cell.reconciler import _ROLLBACK_MAP
        self.assertIn(ActionType.PODMAN_RUN, _ROLLBACK_MAP)
        self.assertEqual(_ROLLBACK_MAP[ActionType.PODMAN_RUN], ActionType.PODMAN_RM)

    def test_rollback_of_podman_run_invokes_podman_rm(self):
        completed = [
            Action(ActionType.ALLOCATE_SUBNET, "cellA"),
            Action(ActionType.CREATE_NETWORK, "cellA"),
            Action(ActionType.PODMAN_RUN, "cellA",
                   params={"spec": MagicMock(name="cellA", is_airgapped=True)}),
        ]

        calls: list[ActionType] = []

        def fake_execute(action, result):
            calls.append(action.type)

        with patch("brig.cell.reconciler._execute_action", side_effect=fake_execute):
            _rollback(completed)

        # Reverse order: PODMAN_RM (rollback of PODMAN_RUN) first.
        self.assertEqual(calls[0], ActionType.PODMAN_RM)
        # Then the network and subnet rollbacks.
        self.assertEqual(calls[1], ActionType.REMOVE_NETWORK)
        self.assertEqual(calls[2], ActionType.FREE_SUBNET)

    def test_apply_runs_podman_rm_when_a_later_action_fails(self):
        # Simulate a future plan that has an action *after* PODMAN_RUN.
        # Wire a synthetic post-run action that fails; assert PODMAN_RUN's
        # rollback (PODMAN_RM) fires.
        actions = [
            Action(ActionType.ALLOCATE_SUBNET, "cellA"),
            Action(ActionType.PODMAN_RUN, "cellA",
                   params={"spec": MagicMock(name="cellA", is_airgapped=True)}),
            # Use REMOVE_NETWORK as the "post-run" step that throws.
            Action(ActionType.REMOVE_NETWORK, "cellA"),
        ]

        executed: list[ActionType] = []

        def fake_execute(action, result):
            executed.append(action.type)
            # Make the third action fail to trigger rollback.
            if action.type == ActionType.REMOVE_NETWORK and \
               executed.count(ActionType.REMOVE_NETWORK) == 1:
                raise RuntimeError("simulated post-run failure")

        with patch("brig.cell.reconciler._execute_action", side_effect=fake_execute):
            result = apply(actions)

        self.assertFalse(result.success)
        # PODMAN_RM must appear in the executed list after the rollback runs.
        self.assertIn(ActionType.PODMAN_RM, executed)
        # And FREE_SUBNET too — the full rollback chain.
        self.assertIn(ActionType.FREE_SUBNET, executed)


if __name__ == "__main__":
    unittest.main()
