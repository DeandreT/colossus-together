import itertools
import unittest

from lifecycle import (
    AllowResourceUnload, CanonicalDeleteRequested, CanonicalFinalFree,
    CanonicalRegistered, ConstructorCaptured, ConstructorRecord, CreateMain,
    CreateVisual, CreationResult, DeleteOwned, GameModeChanged, GameplayReady,
    Lifecycle, OwnedDeleteRequested, OwnedFinalFree, Part,
    ResourceUnloadRequested, RespawnRequested, RetryRequested, State,
)


class LifecycleTests(unittest.TestCase):
    """Generic compatibility-mode coverage; SotC uses the native suite."""

    def setUp(self):
        self.machine = Lifecycle(native_parent_hold=False)

    def capture(self, generation=1, resource_generation=10, p1=100):
        actions = []
        for part in Part:
            actions.extend(self.machine.dispatch(ConstructorCaptured(ConstructorRecord(
                generation, resource_generation, part, 200, 300, p1,
                b"copied parameters", 0x1234, frozenset({part.value, "shared"}),
            ))))
        return actions

    def prepare(self, generation=1, resource_generation=10, p1=100):
        self.machine.dispatch(CanonicalRegistered(generation, resource_generation, p1))
        self.machine.dispatch(GameModeChanged(generation, 0))
        self.capture(generation, resource_generation, p1)
        actions = self.machine.dispatch(GameplayReady(generation, True))
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], CreateMain)
        return actions[0]

    def active(self):
        main = self.prepare()
        visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
        for index, visual in enumerate(visuals):
            self.machine.dispatch(CreationResult(visual.request_id, 500 + index))
        self.assertEqual(self.machine.state, State.ACTIVE)
        return main, visuals

    def free_all(self):
        actions = []
        # Normal adapter teardown acknowledges visuals before their parent.
        ids = self.machine.owned_ids
        for ownership_id in ids[1:] + ids[:1]:
            actions.extend(self.machine.dispatch(OwnedFinalFree(ownership_id)))
        return actions

    def test_transaction_only_publishes_after_all_parts(self):
        main = self.prepare()
        self.assertEqual(self.machine.state, State.BUILDING)
        self.assertIsNone(self.machine.active_p2)
        self.assertTrue(main.independent_group)
        self.assertEqual(main.world_save_authority, "P1")
        visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.assertEqual(len(visuals), 3)
        for index, action in enumerate(visuals):
            self.assertIsInstance(action, CreateVisual)
            self.assertEqual(action.parent_p2, 400)
            self.assertEqual(action.constructor.parent_p1, 100)
            self.assertTrue(action.independent_group)
            self.machine.dispatch(CreationResult(action.request_id, 500 + index))
            self.assertEqual(self.machine.state, State.ACTIVE if index == 2 else State.BUILDING)
        self.assertEqual(self.machine.active_p2, 400)
        self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())

    def test_explicit_readiness_and_no_spawn_veto(self):
        self.machine.dispatch(CanonicalRegistered(1, 10, 100))
        self.capture()
        self.assertEqual(self.machine.dispatch(GameModeChanged(1, 0)), ())
        self.machine.dispatch(GameModeChanged(1, 1))
        self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())
        self.assertEqual(self.machine.state, State.WAITING)
        # Readiness supplied while vetoed is not enough after a veto event.
        self.machine.dispatch(GameModeChanged(1, 1))
        self.assertEqual(self.machine.dispatch(GameModeChanged(1, 0)), ())
        self.assertIsInstance(self.machine.dispatch(GameplayReady(1, True))[0], CreateMain)

    def test_mode_sample_is_required_and_mask_is_configurable(self):
        self.machine = Lifecycle(no_spawn_mask=2, native_parent_hold=False)
        self.machine.dispatch(CanonicalRegistered(1, 10, 100))
        self.capture()
        self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())
        self.assertEqual(self.machine.dispatch(GameModeChanged(1, 2)), ())
        self.machine.dispatch(GameplayReady(1, True))
        self.assertIsInstance(self.machine.dispatch(GameModeChanged(1, 1))[0], CreateMain)

    def test_stale_captures_generations_and_wrong_parent_are_rejected(self):
        self.machine.dispatch(CanonicalRegistered(2, 20, 100))
        self.capture(1, 10)
        self.capture(2, 10)
        self.capture(2, 20, 101)
        self.assertEqual(self.machine.constructor_count, 0)
        self.machine.dispatch(CanonicalRegistered(1, 10, 99))
        self.assertEqual(self.machine.generation, 2)
        self.capture(2, 20)
        self.assertEqual(self.machine.constructor_count, 3)
        self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())

    def test_record_map_is_bounded_and_parameter_inputs_are_copied(self):
        self.machine.dispatch(CanonicalRegistered(1, 10, 100))
        parameter = bytearray(b"original")
        dependencies = {"body"}
        record = ConstructorRecord(1, 10, Part.BODY, 200, 300, 100, parameter, 7, dependencies)
        parameter[:] = b"mutated!"
        dependencies.add("unexpected")
        self.assertEqual(record.parameter_copy, b"original")
        self.assertEqual(record.dependency_ids, frozenset({"body"}))
        for _ in range(100):
            self.capture()
        self.assertEqual(self.machine.constructor_count, 3)
        with self.assertRaises(ValueError):
            Lifecycle(max_constructor_records=2)
        self.machine = Lifecycle(max_parameter_bytes=1, native_parent_hold=False)
        self.machine.dispatch(CanonicalRegistered(1, 10, 100))
        self.capture()
        self.assertEqual(self.machine.constructor_count, 0)

    def test_canonical_delete_invalidates_before_cleanup_and_cannot_revive(self):
        self.active()
        actions = self.machine.dispatch(CanonicalDeleteRequested(1, 100))
        self.assertIsNone(self.machine.canonical_p1)
        self.assertIsNone(self.machine.active_p2)
        self.assertEqual(self.machine.constructor_count, 0)
        self.assertEqual(len(actions), 3)
        self.assertTrue(all(isinstance(a, DeleteOwned) for a in actions))
        self.assertEqual(self.machine.state, State.DRAINING)
        self.capture()
        self.machine.dispatch(GameplayReady(1, True))
        self.machine.dispatch(CanonicalRegistered(1, 10, 100))
        self.assertIsNone(self.machine.canonical_p1)
        self.assertEqual(len(self.machine.owned_ids), 4)
        self.assertEqual(self.machine.dispatch(CanonicalFinalFree(1, 100)), ())
        self.free_all()
        self.assertEqual(self.machine.state, State.WAITING)

    def test_final_free_alone_invalidates_canonical(self):
        main = self.prepare()
        self.machine.dispatch(CanonicalFinalFree(1, 100))
        actions = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.assertIsNone(self.machine.canonical_p1)
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], DeleteOwned)
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), ())

    def test_partial_failure_deletes_late_success_and_latches_until_retry(self):
        main = self.prepare()
        visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.machine.dispatch(CreationResult(visuals[0].request_id, 500))
        actions = self.machine.dispatch(CreationResult(visuals[1].request_id, None, "failed"))
        self.assertEqual(len(actions), 1)
        self.assertEqual(self.machine.state, State.DRAINING)
        self.assertIsInstance(self.machine.dispatch(CreationResult(visuals[2].request_id, 502))[0], DeleteOwned)
        self.free_all()
        self.assertEqual(self.machine.state, State.FAILED)
        for _ in range(20):
            self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())
            self.assertEqual(self.machine.dispatch(RespawnRequested(1)), ())
            self.capture()
        self.assertEqual(self.machine.state, State.FAILED)
        self.assertEqual(self.machine.dispatch(RetryRequested(1)), ())
        self.assertEqual(self.machine.state, State.WAITING)
        self.assertIsInstance(self.machine.dispatch(GameplayReady(1, True))[0], CreateMain)

    def test_error_with_partial_object_is_cleaned(self):
        main = self.prepare()
        actions = self.machine.dispatch(CreationResult(main.request_id, 400, "partially created"))
        self.assertIsInstance(actions[0], DeleteOwned)
        self.assertEqual(self.machine.owned_ids, (main.request_id,))
        self.machine.dispatch(OwnedFinalFree(main.request_id))
        self.assertEqual(self.machine.state, State.FAILED)

    def test_new_generation_waits_for_old_pending_and_final_frees(self):
        main = self.prepare()
        self.machine.dispatch(CanonicalRegistered(2, 20, 100))
        self.machine.dispatch(GameModeChanged(2, 0))
        self.capture(2, 20)
        self.assertEqual(self.machine.dispatch(GameplayReady(2, True)), ())
        actions = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], DeleteOwned)
        actions = self.machine.dispatch(OwnedFinalFree(main.request_id))
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], CreateMain)
        self.assertEqual(actions[0].generation, 2)
        self.assertEqual(actions[0].resource_generation, 20)

    def test_resource_barrier_waits_for_every_dependent_final_free(self):
        self.active()
        actions = self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared"))
        self.assertEqual(len(actions), 3)
        self.assertTrue(all(isinstance(a, DeleteOwned) for a in actions))
        main, *children = self.machine.owned_ids
        for ownership_id in children[:-1]:
            self.assertEqual(self.machine.dispatch(OwnedFinalFree(ownership_id)), ())
        main_delete = self.machine.dispatch(OwnedFinalFree(children[-1]))
        self.assertEqual(len(main_delete), 1)
        self.assertEqual(main_delete[0].ownership_id, main)
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main)), (AllowResourceUnload(7, 10, "shared"),))
        self.assertEqual(self.machine.dispatch(ResourceUnloadRequested(7, 10, "shared")), ())
        self.capture()
        self.assertEqual(self.machine.constructor_count, 0)
        self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())

    def test_resource_barrier_includes_inflight_creation_and_late_success(self):
        main = self.prepare()
        self.assertEqual(self.machine.dispatch(ResourceUnloadRequested(8, 10, "body")), ())
        actions = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], DeleteOwned)
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), (AllowResourceUnload(8, 10, "body"),))

    def test_unrelated_resource_unload_does_not_drain(self):
        self.active()
        self.assertEqual(self.machine.dispatch(ResourceUnloadRequested(9, 10, "other")), (AllowResourceUnload(9, 10, "other"),))
        self.assertEqual(self.machine.state, State.ACTIVE)
        self.assertEqual(self.machine.dispatch(ResourceUnloadRequested(10, 9, "shared")), (AllowResourceUnload(10, 9, "shared"),))
        self.assertEqual(self.machine.state, State.ACTIVE)

    def test_respawn_requires_fresh_readiness_and_never_replaces_p1(self):
        self.active()
        self.assertEqual(len(self.machine.dispatch(RespawnRequested(1))), 3)
        self.free_all()
        self.assertEqual(self.machine.state, State.WAITING)
        self.assertEqual(self.machine.canonical_p1, 100)
        self.assertEqual(self.machine.generation, 1)
        self.assertEqual(self.machine.constructor_count, 3)
        self.assertIsInstance(self.machine.dispatch(GameplayReady(1, True))[0], CreateMain)

    def test_delete_request_retains_ownership_and_final_free_never_redeletes(self):
        main, _ = self.active()
        actions = self.machine.dispatch(OwnedDeleteRequested(main.request_id))
        self.assertEqual(len(actions), 3)
        self.assertIn(main.request_id, self.machine.owned_ids)
        self.assertEqual(self.machine.dispatch(OwnedDeleteRequested(main.request_id)), ())
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), ())
        self.assertNotIn(main.request_id, self.machine.owned_ids)
        self.assertEqual(self.machine.dispatch(OwnedFinalFree(main.request_id)), ())
        self.free_all()
        self.assertEqual(self.machine.state, State.WAITING)

    def test_main_failure_unlocks_only_on_new_generation_or_retry(self):
        main = self.prepare()
        self.machine.dispatch(CreationResult(main.request_id, None))
        self.assertEqual(self.machine.state, State.FAILED)
        self.machine.dispatch(CanonicalRegistered(2, 20, 100))
        self.assertIsNone(self.machine.failure)
        self.assertEqual(self.machine.state, State.WAITING)
        self.machine.dispatch(GameModeChanged(2, 0))
        self.capture(2, 20)
        self.assertIsInstance(self.machine.dispatch(GameplayReady(2, True))[0], CreateMain)

    def test_duplicate_or_unknown_result_cannot_allocate_or_overwrite(self):
        main, _ = self.active()
        self.assertEqual(self.machine.dispatch(CreationResult(main.request_id, 999)), ())
        self.assertEqual(self.machine.dispatch(CreationResult(999, 999)), ())
        self.assertEqual(self.machine.active_p2, 400)

    def test_frozen_build_snapshot_survives_capture_updates(self):
        main = self.prepare()
        self.machine.dispatch(ConstructorCaptured(ConstructorRecord(
            1, 10, Part.BODY, 888, 999, 100, b"replacement", 0, frozenset({"new"}),
        )))
        visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.assertEqual(visuals[0].constructor.definition_ptr, 200)
        self.assertEqual(visuals[0].constructor.parameter_copy, b"copied parameters")

    def test_parent_delete_waits_for_pending_visuals_and_final_frees(self):
        main = self.prepare()
        visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.assertEqual(self.machine.dispatch(RespawnRequested(1)), ())
        for index, visual in enumerate(visuals):
            actions = self.machine.dispatch(CreationResult(visual.request_id, 500 + index))
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].ownership_id, visual.request_id)
        for visual in visuals[:-1]:
            self.assertEqual(self.machine.dispatch(OwnedFinalFree(visual.request_id)), ())
        actions = self.machine.dispatch(OwnedFinalFree(visuals[-1].request_id))
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].ownership_id, main.request_id)
        self.assertEqual(self.machine.state, State.DRAINING)
        self.machine.dispatch(OwnedFinalFree(main.request_id))
        self.assertEqual(self.machine.state, State.WAITING)

    def test_each_unload_request_gets_one_permit_for_same_resource(self):
        main = self.prepare()
        first = ResourceUnloadRequested(1, 10, "shared")
        second = ResourceUnloadRequested(2, 10, "shared")
        self.assertEqual(self.machine.dispatch(first), ())
        self.assertEqual(self.machine.dispatch(second), ())
        self.assertEqual(self.machine.dispatch(CreationResult(main.request_id, None)), (
            AllowResourceUnload(1, 10, "shared"), AllowResourceUnload(2, 10, "shared"),
        ))
        self.assertEqual(self.machine.dispatch(first), ())
        self.assertEqual(self.machine.dispatch(second), ())
        third = ResourceUnloadRequested(3, 10, "shared")
        self.assertEqual(self.machine.dispatch(third), (AllowResourceUnload(3, 10, "shared"),))
        with self.assertRaises(ValueError):
            self.machine.dispatch(ResourceUnloadRequested(3, 20, "shared"))

    def test_multiple_resource_barriers_are_independent(self):
        self.active()
        self.machine.dispatch(ResourceUnloadRequested(1, 10, "head"))
        self.machine.dispatch(ResourceUnloadRequested(2, 10, "mantle"))
        actions = self.free_all()
        permits = [a for a in actions if isinstance(a, AllowResourceUnload)]
        self.assertEqual(permits, [AllowResourceUnload(1, 10, "head"), AllowResourceUnload(2, 10, "mantle")])

    def test_resource_epoch_reload_needs_fresh_captures(self):
        self.active()
        self.machine.dispatch(ResourceUnloadRequested(1, 10, "shared"))
        self.free_all()
        self.machine.dispatch(CanonicalRegistered(2, 20, 100))
        self.machine.dispatch(GameModeChanged(2, 0))
        self.capture(1, 10)
        self.assertEqual(self.machine.dispatch(GameplayReady(2, True)), ())
        actions = self.capture(2, 20)
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], CreateMain)

    def test_pointer_alias_cannot_turn_canonical_p1_into_owned_p2(self):
        main = self.prepare()
        self.assertEqual(self.machine.dispatch(CreationResult(main.request_id, 100)), ())
        self.assertEqual(self.machine.owned_ids, ())
        self.assertEqual(self.machine.canonical_p1, 100)
        self.assertEqual(self.machine.state, State.FAILED)

    def test_duplicate_owned_address_is_not_deleted_twice(self):
        main = self.prepare()
        visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
        self.machine.dispatch(CreationResult(visuals[0].request_id, 500))
        self.machine.dispatch(CreationResult(visuals[1].request_id, 500))
        self.machine.dispatch(CreationResult(visuals[2].request_id, None))
        self.assertEqual(len(self.machine.owned_ids), 2)
        self.free_all()
        self.assertEqual(self.machine.state, State.FAILED)

    def test_cold_boot_multiple_generations_never_reuses_request_ids(self):
        previous_id = 0
        for generation in range(1, 11):
            main = self.prepare(generation, generation * 10, 100)
            self.assertGreater(main.request_id, previous_id)
            previous_id = main.request_id
            self.machine.dispatch(CreationResult(main.request_id, 400))
            self.machine.dispatch(CanonicalDeleteRequested(generation, 100))
            # Complete in-flight visuals after P1 is invalid.
            for request_id in self.machine.pending_ids:
                self.machine.dispatch(CreationResult(request_id, 500 + request_id))
            self.free_all()
            self.assertEqual(self.machine.state, State.WAITING)
            self.assertEqual(self.machine.constructor_count, 0)

    def test_readiness_loss_drains_active_and_requires_new_ready(self):
        self.active()
        actions = self.machine.dispatch(GameplayReady(1, False))
        self.assertEqual(len(actions), 3)
        self.free_all()
        self.assertEqual(self.machine.state, State.WAITING)
        self.assertEqual(self.machine.dispatch(GameModeChanged(1, 0)), ())
        self.assertIsInstance(self.machine.dispatch(GameplayReady(1, True))[0], CreateMain)

    def test_visual_completion_order_does_not_change_atomic_publication(self):
        for order in itertools.permutations(range(3)):
            with self.subTest(order=order):
                self.machine = Lifecycle(native_parent_hold=False)
                main = self.prepare()
                visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
                for count, index in enumerate(order):
                    self.machine.dispatch(CreationResult(visuals[index].request_id, 500 + index))
                    self.assertEqual(self.machine.state, State.ACTIVE if count == 2 else State.BUILDING)

    def test_failure_at_each_visual_position_and_completion_order(self):
        for failed in range(3):
            for order in itertools.permutations(range(3)):
                with self.subTest(failed=failed, order=order):
                    self.machine = Lifecycle(native_parent_hold=False)
                    main = self.prepare()
                    visuals = self.machine.dispatch(CreationResult(main.request_id, 400))
                    for index in order:
                        ptr = None if index == failed else 500 + index
                        self.machine.dispatch(CreationResult(visuals[index].request_id, ptr))
                        self.assertNotEqual(self.machine.state, State.ACTIVE)
                    self.free_all()
                    self.assertEqual(self.machine.owned_ids, ())
                    self.assertEqual(self.machine.pending_ids, ())
                    self.assertEqual(self.machine.state, State.FAILED)
                    self.assertEqual(self.machine.dispatch(GameplayReady(1, True)), ())


if __name__ == "__main__":
    unittest.main()
