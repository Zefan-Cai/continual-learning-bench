# Cohort qonly causal formal: statistical addendum v1

Status: preregistered before the provenance-bound formal run. This addendum
changes only the interpretation and reporting of the already frozen experiment.
It does not change the runner, model, corpora, prompts, candidate tape, replay
operations, seeds, hyperparameters, or legacy gate in
`COHORT_QONLY_CAUSAL_PREREG.md`. The original preregistration remains immutable.

## Why this addendum is necessary

For a fixed arm and adaptation seed, the registered held-out contract is greedy
question-only decoding (`temperature=0`) with the same terminal prompt, response
schema, and accumulated context for every held-out ID. The 20 IDs therefore act
as fixed scoring conditions for one terminal policy report, not as 20 independent
experimental replicates. Instance-specific references can change each absolute
reward, but they cancel from the active-minus-LR0 contrast when the terminal
report is fixed within each arm and every submitted value is nonzero. The frozen
scorer treats an exact zero as missing and deterministically imputes that ID's
reference value; this can create variation across fixed scoring conditions, but
it does not turn those conditions into independent replicates. The effective
sample size of the current formal experiment is consequently three independent
adaptation seeds (`effective_n=3`).

The current three-seed formal is an internal mechanism screen. The hierarchical
bootstrap over 20 fixed held-out IDs is retained solely to preserve the legacy
preregistered decision field and thresholds. It is not publication-grade
inference. A legacy `decision=pass` must be described only as
`internal_gate_pass`; it is neither confirmation nor evidence sufficient for a
publication claim.

## Required reporting for the internal screen

The formal report must:

1. retain the legacy `decision`, threshold checks, and hierarchical bootstrap;
2. mark that bootstrap `publication_grade=false`;
3. report the three raw seed-level paired deltas, `effective_n=3`, their sample
   standard deviation, and the two-sided 95% Student-t interval with `df=2`;
4. label that t interval as descriptive and normality-dependent;
5. report the exact two-sided sign-test p-value across nonzero seed deltas; and
6. report, for every arm and seed, the canonical SHA-256 values and unique count
   of all 20 terminal actions, plus the number of exact-zero submitted fields in
   that fixed action. The run is invalid unless the unique count is exactly one
   for every arm and seed; zero fields are reported but are not invalid.

## Publication-grade confirmation requirement

No result from the three screen seeds (`2026071401`, `2026071402`,
`2026071403`) may itself be promoted to a publication claim. A positive screen
must be followed by a separately preregistered confirmation with all of the
following properties:

- at least six wholly new independent adaptation seeds, with no reuse of the
  three screen seeds;
- at least two separately generated, independently seeded, frozen DGP
  populations, with the seed-to-population mapping preregistered before any
  confirmation outcomes are observed; one independent frozen DGP population
  per adaptation seed is preferred;
- the adaptation seed as the primary inferential unit;
- a two-sided exact sign-flip test of the seed-level paired deltas at
  `alpha=0.05`;
- a mean seed-level paired delta of at least `0.02`;
- a preregistered 95% seed-level interval whose lower endpoint is greater than
  zero (the interval construction and random seed, if any, must be fixed before
  observing confirmation outcomes); and
- causal component ablations that preserve the paired frozen-tape control and
  separately identify the contribution of reward-PG and best/worst environment
  distillation, in addition to the LR0/reset control.

All confirmation cells must retain the same fail-closed integrity, frozen
held-out evaluation, exact provenance, and no-schema-regression requirements as
the internal screen. Failure of any confirmation integrity or inferential
requirement precludes a publication-grade positive claim.

If the minimum independent-population requirement is not met, the strongest
permitted positive statement is a mechanism effect within the one fixed DGP
population studied; population-level generalization is not supported.

An internal `valid_no_go` means only that at least one screen threshold was not
met. It does not establish a zero effect or harm. Excluding a practically useful
effect of at least `0.02` requires a publication-grade seed-level one-sided 95%
upper confidence bound below `0.02`; claiming harm requires that upper bound to
be below zero. The current three-seed descriptive t interval cannot support
either negative publication claim.
