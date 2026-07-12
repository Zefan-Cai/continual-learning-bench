"""Dependency-free source contract checks for the corrected D2 group-PG path."""

import ast
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src" / "systems" / "qwen_local" / "system.py"
tree = ast.parse(SOURCE.read_text())


def method(name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing method {name}")


def dotted_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


group_trainer = method("_train_lora_group_objective")
parents = {}
for parent in ast.walk(group_trainer):
    for child in ast.iter_child_nodes(parent):
        parents[child] = parent

optimizer_steps = [
    node
    for node in ast.walk(group_trainer)
    if isinstance(node, ast.Call) and dotted_name(node.func) == "optimizer.step"
]
assert len(optimizer_steps) == 1, "group trainer must contain exactly one optimizer.step"
ancestor = parents.get(optimizer_steps[0])
while ancestor is not None:
    assert not isinstance(ancestor, (ast.For, ast.While)), (
        "optimizer.step must be outside candidate/step loops"
    )
    ancestor = parents.get(ancestor)

group_update = method("_grpo_instance_update")
called = {
    dotted_name(node.func)
    for node in ast.walk(group_update)
    if isinstance(node, ast.Call)
}
assert "self._train_lora_group_objective" in called
assert "self._train_lora_token_batches" not in called

stash = method("_stash_env_bon_candidates")
stash_source = ast.get_source_segment(SOURCE.read_text(), stash) or ""
assert "os.urandom" not in stash_source
assert "_derive_grpo_candidate_seed" in stash_source
assert "candidate_records" in stash_source
assert "sampling_prompt_sha256" in stash_source

respond = method("respond")
respond_source = ast.get_source_segment(SOURCE.read_text(), respond) or ""
assert "primary_continuation=sampled_continuation" in respond_source
assert "interaction_step=self.interaction_count" in respond_source

setter = method("set_parameter_updates_enabled")
setter_source = ast.get_source_segment(SOURCE.read_text(), setter) or ""
assert "not self.freeze_parameter_updates" in setter_source

print("GRPO_V4_SOURCE_CONTRACT_ALL_PASS")
