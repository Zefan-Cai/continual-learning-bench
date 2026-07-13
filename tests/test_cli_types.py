import unittest

from src.cli import convert_type
from src.registry import get_class_params
from src.systems.ace import ACESystem
from src.systems.qwen_local.system import QwenLocalSystem
from src.tasks.exploitable_poker.task import Poker


class CLITypesTests(unittest.TestCase):
    def test_get_class_params_resolves_future_annotations(self):
        params = get_class_params(ACESystem)
        self.assertIs(params["curate_every_n_updates"]["type"], int)
        self.assertIs(params["generator_model_kwargs_json"]["type"], str)

    def test_convert_type_handles_task_numeric_annotations(self):
        params = get_class_params(Poker)
        self.assertEqual(convert_type("25", params["num_instances"]["type"]), 25)
        self.assertEqual(convert_type("15", params["big_blind"]["type"]), 15)

    def test_get_class_params_includes_variant_parameter(self):
        params = get_class_params(Poker)
        self.assertEqual(
            convert_type("calling_station", params["variant"]["type"]),
            "calling_station",
        )

    def test_get_class_params_includes_schedule_parameter(self):
        params = get_class_params(Poker)
        self.assertEqual(
            convert_type("quick_test", params["schedule"]["type"]),
            "quick_test",
        )

    def test_qwen_candidate_proposer_is_opt_in_and_cli_typed(self):
        params = get_class_params(QwenLocalSystem)
        proposer = params["grpo_candidate_proposer"]
        self.assertIsNone(proposer["default"])
        self.assertEqual(
            convert_type("unit_interval_jitter", proposer["type"]),
            "unit_interval_jitter",
        )
        self.assertEqual(QwenLocalSystem().grpo_candidate_proposer, "policy_sample")

    def test_qwen_adapter_init_seed_is_optional_and_cli_typed(self):
        params = get_class_params(QwenLocalSystem)
        adapter_seed = params["grpo_adapter_init_seed"]
        self.assertIsNone(adapter_seed["default"])
        self.assertEqual(convert_type("2026071200", adapter_seed["type"]), 2026071200)
        self.assertIsNone(QwenLocalSystem().grpo_adapter_init_seed)


if __name__ == "__main__":
    unittest.main()
