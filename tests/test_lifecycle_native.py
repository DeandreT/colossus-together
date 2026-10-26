"""Native P2 teardown requires stopping execution before releasing members."""

import unittest

from lifecycle import (
    AcquireDeleteHold, AllowResourceUnload, CanonicalDeleteRequested,
    CanonicalRegistered, ConstructorCaptured, ConstructorRecord, CreateMain,
    CreationResult, DeleteOwned, GameModeChanged, GameplayReady, Lifecycle,
    OwnedDeleteRequested, OwnedFinalFree, ParentDeletionPrepared,
    ParentDeleteHoldReleased, Part, ReleaseDeleteHold, ResourceUnloadRequested,
    RespawnRequested, RetryRequested, State, TeardownFailed,
)


class NativeTeardownTests(unittest.TestCase):
    def setUp(self):
        self.machine = Lifecycle()

    def main_request(self):
        self.machine.dispatch(CanonicalRegistered(1, 10, 100))
        self.machine.dispatch(GameModeChanged(1, 0))
        for part in Part:
            self.machine.dispatch(ConstructorCaptured(ConstructorRecord(
                1, 10, part, 200, 300, 100, b"copy", 0, frozenset({"shared"}),
            )))
        action, = self.machine.dispatch(GameplayReady(1, True))
        self.assertIsInstance(action, CreateMain)
        return action

    def create(self, complete=True):
        main = self.main_request()
        children = self.machine.dispatch(CreationResult(main.request_id, 400))
        if complete:
            for i, child in enumerate(children):
                self.machine.dispatch(CreationResult(child.request_id, 500 + i))
            self.assertEqual(self.machine.state, State.ACTIVE)
        return main, children

    def acquire(self, main):
        action, = self.machine.dispatch(RespawnRequested(1))
        self.assertIsInstance(action, AcquireDeleteHold)
        self.assertEqual(action.ownership_id, main.request_id)
        delete, = self.machine.dispatch(ParentDeletionPrepared(main.request_id))
        self.assertIsInstance(delete, DeleteOwned)
        self.assertEqual(delete.ownership_id, main.request_id)

    def finish_parent(self, main):
        self.assertEqual(self.machine.dispatch(ParentDeleteHoldReleased(main.request_id)), ())
        return self.machine.dispatch(OwnedFinalFree(main.request_id))

    def test_native_is_default_and_acquisition_precedes_any_delete(self):
        main, _ = self.create()
        self.assertTrue(self.machine.native_parent_hold)
        acquire, = self.machine.dispatch(CanonicalDeleteRequested(1, 100))
        self.assertIsInstance(acquire, AcquireDeleteHold)
        self.assertEqual(acquire.object_ptr, 400)
        self.assertIsNone(self.machine.canonical_p1)
        self.assertEqual(self.machine.constructor_count, 0)
        self.assertEqual(self.machine.state, State.DRAINING)
        self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())
        delete, = self.machine.dispatch(ParentDeletionPrepared(main.request_id))
        self.assertIsInstance(delete, DeleteOwned)
        self.assertEqual(delete.object_ptr, 400)

    def test_automatic_children_observed_before_parent_fence_are_not_re_requested(self):
        main, children = self.create()
        self.acquire(main)
        for child in children:
            self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(child.request_id)), ())
        self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(main.request_id)), ())
        for child in children[:-1]:
            self.assertEqual(self.machine.dispatch(OwnedFinalFree(child.request_id)), ())
        release, = self.machine.dispatch(OwnedFinalFree(children[-1].request_id))
        self.assertIsInstance(release, ReleaseDeleteHold)
        self.assertEqual(release.ownership_id, main.request_id)
        self.assertIn(main.request_id, self.machine.owned_ids)
        self.assertEqual(self.finish_parent(main), ())
        self.assertEqual(self.machine.state, State.WAITING)

    def test_only_unrequested_children_are_explicitly_requested(self):
        main, children = self.create()
        self.acquire(main)
        self.machine.dispatch(OwnedDeleteRequested(children[0].request_id))
        deletes = self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        self.assertEqual([a.ownership_id for a in deletes], [c.request_id for c in children[1:]])
        self.assertTrue(all(isinstance(a, DeleteOwned) for a in deletes))
        self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(main.request_id)), ())
        for child in children[1:]:
            self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(child.request_id)), ())

    def test_no_double_lock_delete_or_unlock(self):
        main, children = self.create()
        self.acquire(main)
        for _ in range(3):
            self.assertEqual(self.machine.dispatch(ParentDeletionPrepared(main.request_id)), ())
            self.assertEqual(self.machine.dispatch(RespawnRequested(1)), ())
        deletes = self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        self.assertEqual(len(deletes), 3)
        for child in children:
            self.machine.dispatch(OwnedFinalFree(child.request_id))
        for _ in range(3):
            self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(main.request_id)), ())
            self.assertEqual(self.machine.dispatch(OwnedFinalFree(children[-1].request_id)), ())
            self.assertEqual(self.machine.dispatch(ParentDeletionPrepared(main.request_id)), ())
        self.assertEqual(self.finish_parent(main), ())
        self.assertEqual(self.machine.dispatch(ParentDeleteHoldReleased(main.request_id)), ())
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), ())

    def test_late_creation_is_deleted_and_blocks_unlock(self):
        main, children = self.create(complete=False)
        self.acquire(main)
        self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(main.request_id)), ())
        for i, child in enumerate(children):
            delete, = self.machine.dispatch(CreationResult(child.request_id, 500 + i))
            self.assertIsInstance(delete, DeleteOwned)
            self.assertEqual(delete.ownership_id, child.request_id)
            actions = self.machine.dispatch(OwnedFinalFree(child.request_id))
            if i < 2:
                self.assertEqual(actions, ())
            else:
                self.assertEqual(len(actions), 1)
                self.assertIsInstance(actions[0], ReleaseDeleteHold)
        self.finish_parent(main)

    def test_failed_pending_creation_must_resolve_before_unlock(self):
        main, children = self.create(complete=False)
        self.acquire(main)
        self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        for child in children[:-1]:
            self.assertEqual(self.machine.dispatch(CreationResult(child.request_id, None)), ())
        release, = self.machine.dispatch(CreationResult(children[-1].request_id, None))
        self.assertIsInstance(release, ReleaseDeleteHold)

    def test_resource_permit_waits_for_held_parent_actual_final_free(self):
        main, children = self.create()
        acquire, = self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared"))
        self.assertIsInstance(acquire, AcquireDeleteHold)
        self.machine.dispatch(ParentDeletionPrepared(main.request_id))
        self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        for child in reversed(children):
            actions = self.machine.dispatch(OwnedFinalFree(child.request_id))
            self.assertFalse(any(isinstance(a, AllowResourceUnload) for a in actions))
        self.assertEqual(self.machine.dispatch(ParentDeleteHoldReleased(main.request_id)), ())
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), (
            AllowResourceUnload(7, 10, "shared"),
        ))

    def test_hold_failure_quarantines_without_deleting_children_or_unlocking(self):
        main, _ = self.create()
        self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared"))
        self.assertEqual(self.machine.dispatch(ParentDeletionPrepared(main.request_id, "lock failed")), ())
        self.assertIn("lock failed", self.machine.teardown_error)
        for event in (
            RetryRequested(1), GameplayReady(1, True), ParentDeletionPrepared(main.request_id),
            CanonicalRegistered(2, 20, 101), GameModeChanged(2, 0), GameplayReady(2, True),
        ):
            self.assertEqual(self.machine.dispatch(event), ())
        self.assertEqual(self.machine.state, State.DRAINING)
        self.assertEqual(len(self.machine.owned_ids), 4)

    def test_missing_acknowledgements_do_not_retry_or_assume_success(self):
        main, _ = self.create()
        acquire, = self.machine.dispatch(RespawnRequested(1))
        self.assertIsInstance(acquire, AcquireDeleteHold)
        for _ in range(20):
            self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())
        self.assertEqual(self.machine.dispatch(ParentDeletionPrepared(main.request_id, "timeout")), ())
        self.assertEqual(self.machine.state, State.DRAINING)
        self.assertIn("timeout", self.machine.teardown_error)

    def test_release_failure_retains_hold_and_barrier(self):
        main, children = self.create()
        self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared"))
        self.machine.dispatch(ParentDeletionPrepared(main.request_id))
        self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        for child in children:
            self.machine.dispatch(OwnedFinalFree(child.request_id))
        self.assertEqual(self.machine.dispatch(ParentDeleteHoldReleased(main.request_id, "unlock timed out")), ())
        self.assertIn("unlock timed out", self.machine.teardown_error)
        self.assertEqual(self.machine.dispatch(RetryRequested(1)), ())
        self.assertEqual(self.machine.dispatch(ParentDeleteHoldReleased(main.request_id)), ())
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), ())
        self.assertIn(main.request_id, self.machine.owned_ids)
        self.assertEqual(self.machine.state, State.DRAINING)

    def test_early_parent_free_is_error_not_success_and_never_uses_stale_pointer(self):
        main, children = self.create()
        self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared"))
        self.machine.dispatch(ParentDeletionPrepared(main.request_id))
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), ())
        self.assertIn("parent final-free", self.machine.teardown_error)
        for child in children:
            self.assertEqual(self.machine.dispatch(OwnedFinalFree(child.request_id)), ())
        for event in (OwnedFinalFree(main.request_id), ParentDeletionPrepared(main.request_id),
                      OwnedDeleteRequested(main.request_id), RetryRequested(1)):
            self.assertEqual(self.machine.dispatch(event), ())
        self.assertIn(main.request_id, self.machine.owned_ids)
        self.assertEqual(self.machine.state, State.DRAINING)

    def test_parent_free_before_release_ack_is_quarantined(self):
        main, children = self.create()
        self.acquire(main)
        self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        for child in children:
            self.machine.dispatch(OwnedFinalFree(child.request_id))
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), ())
        self.assertIsNotNone(self.machine.teardown_error)

    def test_no_parent_allocation_needs_no_hold(self):
        main = self.main_request()
        self.assertEqual(self.machine.dispatch(CreationResult(main.request_id, None, "failed")), ())
        self.assertEqual(self.machine.state, State.FAILED)
        self.assertEqual(self.machine.owned_ids, ())
        self.assertEqual(self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared")), (
            AllowResourceUnload(7, 10, "shared"),
        ))

    def test_partial_main_allocation_uses_hold_protocol(self):
        main = self.main_request()
        acquire, = self.machine.dispatch(CreationResult(main.request_id, 400, "partial"))
        self.assertIsInstance(acquire, AcquireDeleteHold)
        delete, = self.machine.dispatch(ParentDeletionPrepared(main.request_id))
        self.assertIsInstance(delete, DeleteOwned)
        release, = self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        self.assertIsInstance(release, ReleaseDeleteHold)
        self.finish_parent(main)
        self.assertEqual(self.machine.state, State.FAILED)

    def test_generation_change_does_not_bypass_old_hold_or_barrier(self):
        main, children = self.create()
        acquire, = self.machine.dispatch(CanonicalRegistered(2, 20, 101))
        self.assertEqual(acquire.generation, 1)
        self.assertIsInstance(acquire, AcquireDeleteHold)
        self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared"))
        delete, = self.machine.dispatch(ParentDeletionPrepared(main.request_id))
        self.assertEqual(delete.generation, 1)
        self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        for child in children:
            self.machine.dispatch(OwnedFinalFree(child.request_id))
        self.assertEqual(self.finish_parent(main), (AllowResourceUnload(7, 10, "shared"),))
        self.assertEqual(self.machine.generation, 2)
        self.assertEqual(self.machine.canonical_p1, 101)

    def test_unheld_external_parent_deletion_is_protocol_error(self):
        main, _ = self.create()
        self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(main.request_id)), ())
        self.assertIn("without our acquired hold", self.machine.teardown_error)
        self.assertEqual(self.machine.state, State.DRAINING)

    def test_children_can_free_during_immediate_cleanup_but_release_waits_for_fence(self):
        main, children = self.create()
        self.acquire(main)
        for child in children:
            self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(child.request_id)), ())
            self.assertEqual(self.machine.dispatch(OwnedFinalFree(child.request_id)), ())
        release, = self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        self.assertIsInstance(release, ReleaseDeleteHold)
        self.finish_parent(main)
        self.assertEqual(self.machine.state, State.WAITING)

    def test_child_teardown_timeout_does_not_release_parent_hold(self):
        main, children = self.create()
        self.acquire(main)
        self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        self.assertEqual(self.machine.dispatch(TeardownFailed(children[0].request_id, "delete timeout")), ())
        for child in children:
            self.assertEqual(self.machine.dispatch(OwnedFinalFree(child.request_id)), ())
        self.assertIn(main.request_id, self.machine.owned_ids)
        self.assertEqual(self.machine.state, State.DRAINING)
        self.assertIn("delete timeout", self.machine.teardown_error)


if __name__ == "__main__":
    unittest.main()
