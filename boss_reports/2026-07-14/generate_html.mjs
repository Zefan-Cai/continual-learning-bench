import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(await fs.readFile(path.join(here, "report_data.json"), "utf8"));

const esc = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;");

const comma = (value) => Number(value).toLocaleString("en-US");
const signed = (value, digits = 4) => `${value >= 0 ? "+" : ""}${Number(value).toFixed(digits)}`;
const taskRows = data.sixTasks.map((row) => `
  <tr><td><b>${esc(row.task)}</b></td><td>${esc(row.snapshot)}</td><td>${esc(row.conservativeStatus)}</td></tr>`).join("");
const victoryItems = data.victoryContract.map((item) => `<li>${esc(item)}</li>`).join("");
const boundaryTodos = data.privateBoundary.todos.map((item) => `<li>${esc(item)}</li>`).join("");
const healthRows = data.formalRun.collectors.map((collector) => `
  <tr>
    <td>Seed ${esc(collector.seed)}</td>
    <td>${esc(collector.status)}</td>
    <td class="n">${comma(collector.logBytes)}</td>
    <td class="n">${comma(collector.traceBytes)}</td>
    <td class="n">${comma(collector.tapeBytes)}</td>
    <td class="n">${comma(collector.manifestBytes)}</td>
    <td>${collector.artifactContentOpened ? "yes" : "no"}</td>
  </tr>`).join("");
const pairedRows = data.formalRun.pairedCells.map((cell) => `
  <tr>
    <td>Seed ${esc(cell.seed)}</td>
    <td>${esc(cell.arm)}</td>
    <td class="n">${cell.pid}</td>
    <td>${esc(cell.gpu)}</td>
    <td class="n">~${comma(cell.memoryMiB)} MiB</td>
    <td>${esc(cell.processState)}</td>
    <td class="n">${esc(cell.cpu)}</td>
    <td>${esc(cell.status)}</td>
  </tr>`).join("");

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(data.title)} — ${esc(data.reportDate)}</title>
<style>
  :root{--ink:#111;--muted:#444;--line:#333;--soft:#f4f4f4;--blue:#2458a6;--green:#176b3a;--amber:#a45b00;--red:#9b1c1c}
  *{box-sizing:border-box}
  body{font-family:Georgia,"Times New Roman",serif;color:var(--ink);background:#fff;max-width:920px;margin:0 auto;padding:48px 32px 96px;font-size:20px;line-height:1.62}
  h1{font-size:35px;font-weight:700;margin:0 0 4px;line-height:1.18}
  h2{font-size:26px;font-weight:700;margin:52px 0 10px;border-bottom:2px solid var(--ink);padding-bottom:6px}
  h3{font-size:21px;font-weight:700;margin:28px 0 6px}
  p{margin:10px 0}.sub{color:var(--muted);font-size:18px;margin-top:0}
  .status{margin:24px 0 12px;padding:15px 18px;border:2px solid var(--amber);background:#fff8ed;font-family:Arial,sans-serif;font-size:18px;font-weight:700;letter-spacing:.02em}
  .key{background:#f6f6f6;border-left:5px solid var(--ink);padding:13px 18px;margin:18px 0;font-size:19px}
  .warning{background:#fff3e0;border-left:5px solid var(--amber);padding:13px 18px;margin:18px 0;font-size:18px}
  .negative{border-left-color:var(--red)}
  .label{display:inline-block;border:1px solid #aaa;border-radius:4px;padding:1px 7px;font:700 13px/1.5 Arial,sans-serif;letter-spacing:.05em;vertical-align:2px}
  .formal{color:var(--blue);border-color:var(--blue)}.audit{color:#555}.explore{color:var(--amber);border-color:var(--amber)}.nogo{color:var(--red);border-color:var(--red)}
  table{border-collapse:collapse;width:100%;margin:16px 0;font-size:16.5px;line-height:1.45}
  th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
  th{background:#f0f0f0;font-weight:700}.n{font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
  ul,ol{margin:10px 0 10px 4px}li{margin:6px 0}
  code{font-family:"Courier New",monospace;font-size:15px;background:#f2f2f2;padding:1px 5px;overflow-wrap:anywhere}
  .flow{margin:24px 0;border:1px solid #bbb;padding:18px;background:#fafafa}
  .flow-row{display:grid;grid-template-columns:1.2fr 42px 1.2fr 42px 1.2fr;align-items:center;gap:4px;font:16px/1.35 Arial,sans-serif}
  .flow-node{border:1px solid #555;padding:13px;background:#fff;min-height:74px;display:flex;align-items:center;justify-content:center;text-align:center}.arrow{text-align:center;font-size:24px}
  .branch{margin-top:10px;text-align:center;font:15px/1.4 Arial,sans-serif;color:var(--muted)}
  .small{font-size:14.5px;color:#555}.foot{margin-top:48px;padding-top:12px;border-top:1px solid #999}
  @media(max-width:720px){body{padding:28px 18px 64px;font-size:18px}.flow-row{grid-template-columns:1fr}.arrow{transform:rotate(90deg)}table{font-size:14px;display:block;overflow-x:auto}}
  @media print{body{max-width:none;padding:24px 34px}.status,.key,.warning,.flow{break-inside:avoid}h2{break-after:avoid}table{break-inside:avoid}}
</style></head><body>

<h1>${esc(data.title)}</h1>
<p class="sub">Boss progress report &nbsp;·&nbsp; Cohort qonly causal gate &nbsp;·&nbsp; as of ${esc(data.asOf)}</p>
<div class="status">STATUS: ${esc(data.status)}</div>

<h2>1 &nbsp; Executive decision</h2>
<p>We do <b>not</b> yet have causal evidence that test-time parameter adaptation beats matched controls or in-context learning on CLBench. All three formal tapes are sealed, and six paired active/LR0 cells are now running blind. No partial efficacy has been read, summarized, plotted, or inferred.</p>
<div class="key"><b>Decision now:</b> preserve the matched formal run through attempt sealing. ${esc(data.resourceAsk)}</div>

<h2>2 &nbsp; The question and the win contract</h2>
<p>The research question is deliberately causal: with the prompt, candidates, order, compute budget, and evaluation held fixed, does the active TTT update outperform an LR0/reset arm—and then outperform a canonical reward-aware online-ICL comparator?</p>
<ul>${victoryItems}</ul>
<p>The online-ICL formal comparator is gated: it runs only if the active-vs-LR0 causal decision passes. A positive screen would then require an independent N=8 confirmation before any broad claim.</p>

<h2>3 &nbsp; What changed in this milestone</h2>
<ul>
  <li><b>Two parameter-learning mechanisms were retired:</b> group-PG failed its validity gate; candidate distillation did not establish a causal learning signal.</li>
  <li><b>The current mechanism is narrower:</b> ${esc(data.formalConfig.mechanism)}, using <code>question_only</code>, prefix ${data.formalConfig.prefixTokens}, environment BoN${data.formalConfig.environmentCandidates}, step ${data.formalConfig.steps}, LR ${esc(data.formalConfig.learningRate)}.</li>
  <li><b>The comparison is matched:</b> ${esc(data.formalConfig.comparison)} under the same prompt/candidates/order/budget/evaluation contract.</li>
  <li><b>The formal run crossed a blind operational milestone:</b> all three frozen tapes sealed, then 3 seeds &times; {active, LR0} launched as six paired cells.</li>
  <li><b>The evaluation boundary was hardened:</b> private-boundary code reached an audited fail-closed state, but is explicitly not production-ready.</li>
</ul>

<h2>4 &nbsp; Formal run health—not efficacy</h2>
<p><span class="label formal">RUN HEALTH</span> <b>All 3 formal tapes are sealed; 6 paired active/LR0 cells are running blind.</b> Wrapper PID ${data.formalRun.wrapperPid} is ${esc(data.formalRun.wrapperStatus)}. This is metadata-only liveness and pairing evidence—not efficacy or a progress-to-score proxy.</p>
<table>
  <tr><th>Collector</th><th>Status</th><th>Log bytes</th><th>Trace bytes</th><th>Tape bytes</th><th>Manifest bytes</th><th>Content opened?</th></tr>
${healthRows}
</table>
<table>
  <tr><th>Seed</th><th>Arm</th><th>PID</th><th>Device</th><th>GPU memory</th><th>State</th><th>CPU</th><th>Status</th></tr>
${pairedRows}
</table>
<p class="small">All collector outputs above were observed only as filenames and byte counts; their content was not opened. The six paired cells use PIDs and device metadata only.</p>
<div class="warning"><b>Blindness guard:</b> there are zero attempt-level exit, error, fail, replay, eval, or decision artifacts as of ${esc(data.asOf)}. Tape sealing and paired-cell liveness are not efficacy results, and no semantic result opening is authorized.</div>

<h2>5 &nbsp; What the historical audit actually says</h2>
<p><span class="label audit">AUDIT DIAGNOSTIC</span> Across ${comma(data.historicalAudit.primarySweepFamilies)} numeric configuration families, the unweighted mean paired delta is ${signed(data.historicalAudit.primarySweepMean, 7)} and the median is ${data.historicalAudit.primarySweepMedian}. This is a heterogeneous audit diagnostic, <b>not</b> an overall causal estimand.</p>
<p>In the corrected artifact, ${data.historicalAudit.qonlyWithin005}/${data.historicalAudit.qonlyFamilies} aggregated qonly configuration families (${Math.round(100 * data.historicalAudit.qonlyWithin005 / data.historicalAudit.qonlyFamilies)}%) are within &plusmn;0.005 and therefore round to zero at two decimals. The number of <em>exact</em> zeros is ${data.historicalAudit.qonlyExactZero}/${data.historicalAudit.qonlyFamilies}.</p>

<h3>The only historical positive lead is exploratory</h3>
<p><span class="label explore">EXPLORATORY</span> Historical <code>method=bonenv, decode=full</code> Cohort families produced ${data.historicalAudit.cohortBonenvFullPairable}/${data.historicalAudit.cohortBonenvFullFamilies} pairable configurations: mean ${signed(data.historicalAudit.cohortBonenvFullMean, 7)}, median ${signed(data.historicalAudit.cohortBonenvFullMedian, 7)}, ${data.historicalAudit.cohortBonenvFullPositive} positive and ${data.historicalAudit.cohortBonenvFullNegative} negative. Each family has only one repeat. This is neither a fresh-seed result nor matched causal proof, and it is <b>not</b> the current qonly formal configuration.</p>
<p>The exact preregistered qonly configuration has a historical ${signed(data.historicalAudit.currentPreregHistoricalHypothesis, 7)} record. It is a hypothesis-selection signal only—not evidence that the current parameter update caused an improvement.</p>

<h2>6 &nbsp; Six-task audit snapshot</h2>
<table>
  <tr><th>CLBench task</th><th>Historical audit snapshot</th><th>Conservative conclusion</th></tr>
${taskRows}
</table>
<p class="small">Artifact SHA-256: <code>${esc(data.historicalAudit.artifactSha256)}</code>. Task snapshots filter <code>sweep=results</code> primary families and exclude <code>results_probe</code>. Values above are exploratory audit snapshots unless explicitly labeled formal.</p>

<h2>7 &nbsp; The private boundary is audited fail-closed scaffolding</h2>
<p>At research commit <code>${esc(data.privateBoundary.commit)}</code>, the boundary suite reports <b>${esc(data.privateBoundary.tests)}</b>, and independent re-review found <b>${esc(data.privateBoundary.independentReview)}</b>.</p>
<div class="warning"><b>Not production-ready:</b> <code>provider_available=false</code>. The public entry fails before runtime or filesystem activity. The current milestone is audited fail-closed scaffolding, not an enabled private-data service.</div>
<p>Activation still requires:</p><ul>${boundaryTodos}</ul>

<h2>8 &nbsp; The next decision is intentionally narrow</h2>
<figure class="flow">
  <div class="flow-row">
    <div class="flow-node"><b>Finish the six paired active/LR0 cells and seal attempt-002</b></div><div class="arrow">&rarr;</div>
    <div class="flow-node"><b>Apply the preregistered causal gate</b></div><div class="arrow">&rarr;</div>
    <div class="flow-node"><b>If PASS: run reward-aware online ICL, then N=8 confirmation</b></div>
  </div>
  <div class="branch">If NO-GO: allow exactly one structured latent-state pivot. Sales is secondary; no other task receives an advantage claim.</div>
</figure>
<p><b>Resource ask:</b> ${esc(data.resourceAsk)}</p>

<h2>9 &nbsp; Headline conclusions</h2>
<ol>
  <li><b>TTT-RL remains unproven.</b> The historical pool is neutral-to-negative after baseline correction, and the only positive lead is exploratory Cohort evidence.</li>
  <li><b>The current formal test is scientifically cleaner than the historical sweep.</b> It is matched, preregistered, held-out, three-seed, and blind.</li>
  <li><b>The next claim is binary and auditable.</b> Pass the causal gate before online ICL and confirmation; otherwise spend one pivot on structured latent state and close rigorously if that also fails.</li>
</ol>

<p class="small foot">Reproducibility: research branch <code>${esc(data.researchCommit)}</code>; causal code <code>${esc(data.causalCodeCommit)}</code>; attempt <code>${esc(data.attempt)}</code>; evidence state <b>${esc(data.status)}</b>; as of ${esc(data.asOf)}.</p>
</body></html>`;

await fs.writeFile(path.join(here, `ttt_rl_progress_${data.reportDate}.html`), html, "utf8");
console.log(`wrote ttt_rl_progress_${data.reportDate}.html`);
