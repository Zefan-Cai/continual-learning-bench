import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FileBlob, PresentationFile } from "@oai/artifact-tool";

const here = path.dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(await fs.readFile(path.join(here, "report_data.json"), "utf8"));
const starterPptx = process.env.TEMPLATE_STARTER_PPTX || path.join(here, "template_starter_9slides.pptx");
const outputPptx = process.env.REPORT_PPTX || path.join(here, `ttt_rl_progress_${data.reportDate}.pptx`);
const qaDir = process.env.REPORT_QA_DIR || path.join(process.env.TMPDIR || "/tmp", `ttt-rl-boss-report-${data.reportDate}-qa`);

const presentation = await PresentationFile.importPptx(await FileBlob.load(starterPptx));
if (presentation.slides.count !== 9) throw new Error(`Expected 9 inherited slides, found ${presentation.slides.count}`);

function slideAt(number) {
  return presentation.slides.getItem(number - 1);
}

function shapeByName(slide, name) {
  const shape = slide.shapes.items.find((item) => item.name === name);
  if (!shape) throw new Error(`Missing inherited shape ${name} on slide ${slide.index + 1}`);
  return shape;
}

function tableByName(slide, name) {
  const table = slide.tables.items.find((item) => item.name === name);
  if (!table) throw new Error(`Missing inherited table ${name} on slide ${slide.index + 1}`);
  return table;
}

function setTable(table, values) {
  if (values.length !== table.rowCount) throw new Error(`Table row mismatch: ${values.length} != ${table.rowCount}`);
  for (let row = 0; row < values.length; row += 1) {
    if (values[row].length !== table.columnCount) throw new Error(`Table column mismatch at row ${row}`);
    for (let column = 0; column < values[row].length; column += 1) {
      table.getCell(row, column).value = values[row][column];
    }
  }
}

function setNarrative(shape, paragraphs, options = {}) {
  const {
    fontSize = 18,
    position,
    lineSpacing = 1.08,
  } = options;
  if (position) shape.position = position;
  shape.text.set(paragraphs.map((paragraph) => ({
    bulletCharacter: "",
    spaceBefore: paragraph.spaceBefore ?? 0,
    spaceAfter: paragraph.spaceAfter ?? 8,
    runs: paragraph.lead
      ? [
          { run: paragraph.lead, textStyle: { bold: true } },
          { run: paragraph.body ? ` ${paragraph.body}` : "" },
        ]
      : [{ run: paragraph.text }],
  })));
  shape.text.style = {
    typeface: "Arial",
    fontSize,
    color: "#111111",
    alignment: "left",
    verticalAlignment: "top",
    autoFit: "shrinkText",
    lineSpacing,
    insets: { top: 6, right: 8, bottom: 6, left: 8 },
  };
}

function addTextBox(slide, name, text, position, options = {}) {
  const box = slide.shapes.add({
    geometry: "textbox",
    name,
    position,
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  box.text = text;
  box.text.style = {
    typeface: options.typeface || "Arial",
    fontSize: options.fontSize || 16,
    bold: options.bold || false,
    color: options.color || "#222222",
    alignment: options.alignment || "left",
    verticalAlignment: options.verticalAlignment || "top",
    autoFit: "shrinkText",
    lineSpacing: options.lineSpacing || 1.05,
    insets: options.insets || { top: 2, right: 4, bottom: 2, left: 4 },
  };
  return box;
}

function sizeTable(table, { left, top, width, columnWidths, rowHeights, fontSize = 14 }) {
  if (columnWidths.length !== table.columnCount) throw new Error("Column width count mismatch");
  if (rowHeights.length !== table.rowCount) throw new Error("Row height count mismatch");
  for (let column = 0; column < columnWidths.length; column += 1) {
    table.columns.get(column).width = columnWidths[column];
  }
  for (let row = 0; row < rowHeights.length; row += 1) {
    table.rows[row].height = rowHeights[row];
  }
  table.frame = { left, top, width, height: rowHeights.reduce((sum, value) => sum + value, 0) };
  table.cells.block({ row: 0, column: 0, rowCount: table.rowCount, columnCount: table.columnCount }).assign({
    textStyle: { typeface: "Arial", fontSize, color: "#111111" },
    margins: { top: 4, right: 5, bottom: 4, left: 5 },
    anchor: "middle",
  });
  table.cells.block({ row: 0, column: 0, rowCount: 1, columnCount: table.columnCount }).assign({
    textStyle: { typeface: "Arial", fontSize, bold: true, color: "#111111" },
  });
}

function addFooter(slide, page) {
  const footer = slide.shapes.add({
    geometry: "textbox",
    name: `TTT-RL footer ${page}`,
    position: { left: 32, top: 505, width: 896, height: 22 },
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  footer.text = `2026-07-14 · branch d9346b8 · causal 1caf142 · attempt-002 · FORMAL BLIND · ${page}/9`;
  footer.text.style = {
    typeface: "Arial",
    fontSize: 12,
    color: "#666666",
    alignment: "right",
    verticalAlignment: "middle",
    autoFit: "shrinkText",
    insets: { top: 0, right: 0, bottom: 0, left: 0 },
  };
}

function setNotes(slide, text) {
  slide.speakerNotes.text = text;
}

// 1 — opening thesis, cloned from source slide 1.
{
  const slide = slideAt(1);
  shapeByName(slide, "Google Shape;54;p13").text = "TTT-RL on CLBench";
  shapeByName(slide, "Google Shape;55;p13").text = "Causal advantage evaluation\nUNPROVEN / FORMAL RUNNING BLIND\n2026-07-14";
  addFooter(slide, 1);
  setNotes(slide, "Open with the decision state: this deck is not a positive-result claim. The first matched causal run remains blind.");
}

// 2 — executive decision, cloned from source slide 13.
{
  const slide = slideAt(2);
  shapeByName(slide, "Google Shape;133;p25").text = "UNPROVEN: the first causal test is running blind";
  shapeByName(slide, "Google Shape;134;p25").text = [
    "Formal state: all 3 tapes sealed; 6 paired active/LR0 cells running blind.",
    "Scientific claim: no CLBench task has confirmed causal TTT-RL advantage.",
    "Decision: keep the current A100 40G job alive through attempt sealing; no added GPU and no broad sweep.",
  ].join("\n");
  setTable(tableByName(slide, "Google Shape;135;p25"), [
    ["Decision area", "Current answer", "Consequence"],
    ["Efficacy", "UNPROVEN", "No partial read; wait for attempt seal"],
    ["Boundary", "Audited fail-closed", "provider_available=false"],
    ["Resources", "Current A100 job", "Keep alive; no added GPU / sweep"],
  ]);
  addFooter(slide, 2);
  setNotes(slide, `As of ${data.asOf}. The job-level ask is operational continuity only; it is not a request for a wider experiment grid.`);
}

// 3 — preregistered causal gate, cloned from source slide 10.
{
  const slide = slideAt(3);
  shapeByName(slide, "Google Shape;112;p22").text = "A win means causal learning—not a better decode";
  setNarrative(shapeByName(slide, "Google Shape;113;p22"), [
    { text: "Active and LR0/reset share prompt, candidates, order, budget, schema, and evaluation." },
  ], {
    fontSize: 18,
    position: { left: 32.72, top: 120, width: 894.55, height: 48 },
  });
  const table = tableByName(slide, "Google Shape;114;p22");
  setTable(table, [
    ["Gate", "Preregistered bar", "Branch"],
    ["Effect", "3/3 positive; mean >= +0.02; clustered 95% lower > 0", "Fail → NO-GO"],
    ["Integrity", "No schema regression; active > LR0/reset", "Pass → online ICL"],
  ]);
  sizeTable(table, {
    left: 4,
    top: 182,
    width: 952,
    columnWidths: [180, 570, 202],
    rowHeights: [32, 48, 48],
    fontSize: 15,
  });
  addTextBox(
    slide,
    "TTT-RL causal-gate note",
    "Online ICL runs only after causal PASS; the final claim requires active > online ICL. Any positive screen still requires independent N=8 confirmation.",
    { left: 32, top: 336, width: 896, height: 58 },
    { fontSize: 16 },
  );
  addFooter(slide, 3);
  setNotes(slide, "The final win also requires active > reward-aware online ICL. The comparator is deliberately gated to avoid spending compute after a failed causal screen.");
}

// 4 — mechanism research arc, cloned from source slide 29.
{
  const slide = slideAt(4);
  shapeByName(slide, "Google Shape;250;p41").text = "Two mechanisms were retired; one narrow test remains";
  setNarrative(shapeByName(slide, "Google Shape;251;p41"), [
    { lead: "STAGE A — Group-PG", body: "Retired after failing the validity gate; do not resurrect." },
    { lead: "STAGE B — Candidate distillation", body: "Retired without a causal learning signal." },
    { lead: "STAGE C — FORMAL RUNNING BLIND", body: "question_only + prefix512 + env BoN8 + step1 + lr5e-4." },
    { lead: "Current mechanism", body: "Frozen-tape reward-PG plus environment-BoN best/worst SFT prefix; matched active vs LR0/reset." },
    { lead: "NO-GO rule", body: "Exactly one structured latent-state pivot. Sales remains secondary." },
  ], {
    fontSize: 18,
    position: { left: 32.72, top: 122, width: 894.55, height: 334 },
  });
  addFooter(slide, 4);
  setNotes(slide, "Negative results are progress here: each retired mechanism reduces the search space. No broad post-hoc sweep is authorized.");
}

// 5 — matched design, cloned from source slide 27.
{
  const slide = slideAt(5);
  shapeByName(slide, "Google Shape;235;p39").text = "The formal design isolates the learning update";
  shapeByName(slide, "Google Shape;236;p39").delete();
  setNarrative(shapeByName(slide, "Google Shape;238;p39"), [
    { lead: "RISK", body: "Prompt choice, candidate set, order, budget, or evaluation can mimic a gain." },
    { lead: "CONTROL", body: "Active and LR0/reset share every non-update factor." },
    { lead: "BLIND", body: "Held-out evaluation is sealed; no partial efficacy is read." },
    { lead: "DECISION", body: "Reward-aware online ICL runs only after causal PASS." },
  ], {
    fontSize: 18,
    position: { left: 16, top: 121, width: 928, height: 260 },
  });
  const table = tableByName(slide, "Google Shape;237;p39");
  setTable(table, [
    ["Axis", "Active", "LR0 / reset", "Fixed contract"],
    ["Update", "Enabled", "LR=0 / reset", "Prompt / candidates / order"],
    ["Evaluation", "Sealed", "Sealed", "Budget / schema / held-out set"],
  ]);
  sizeTable(table, {
    left: 0,
    top: 405,
    width: 960,
    columnWidths: [135, 150, 165, 510],
    rowHeights: [26, 28, 28],
    fontSize: 14,
  });
  addFooter(slide, 5);
  setNotes(slide, "The causal estimand is the paired active-minus-LR0 difference under a frozen comparison contract.");
}

// 6 — run health, cloned from source slide 39.
{
  const slide = slideAt(6);
  shapeByName(slide, "Google Shape;312;p51").text = "All 3 tapes sealed; 6 active/LR0 cells running blind";
  const table = tableByName(slide, "Google Shape;313;p51");
  setTable(table, [
    ["Seed", "Active", "", "LR0", "", "Matched", "", ""],
    ["01", "RUNNING · PID 123511\nGPU0", "", "RUNNING · PID 123516\nGPU2", "", "YES", "", ""],
    ["02", "RUNNING · PID 123521\nGPU3", "", "RUNNING · PID 123530\nGPU4", "", "YES", "", ""],
    ["03", "RUNNING · PID 123540\nGPU5", "", "RUNNING · PID 123551\nGPU6", "", "YES", "", ""],
  ]);
  for (let row = 0; row < 4; row += 1) {
    table.merge({ startRow: row, endRow: row, startColumn: 1, endColumn: 2 });
    table.merge({ startRow: row, endRow: row, startColumn: 3, endColumn: 4 });
    table.merge({ startRow: row, endRow: row, startColumn: 5, endColumn: 7 });
  }
  sizeTable(table, {
    left: 18,
    top: 164,
    width: 924,
    columnWidths: [70, 150, 150, 150, 150, 85, 85, 84],
    rowHeights: [38, 56, 56, 56],
    fontSize: 15,
  });
  addTextBox(
    slide,
    "TTT-RL run-health note",
    "All six cells: R<l · ~17,256 MiB · ~244–264% CPU. Wrapper PID 34747 alive. Tape contents unopened. Zero attempt-level exit, error, fail, replay, eval, or decision artifacts.",
    { left: 24, top: 390, width: 912, height: 72 },
    { fontSize: 15 },
  );
  addFooter(slide, 6);
  setNotes(slide, `Metadata only as of ${data.asOf}. All three collector tapes are sealed, and their contents were not opened. Six paired active/LR0 cells are running blind. Wrapper PID 34747 is alive. There are no attempt-level terminal, error, fail, replay, eval, or decision artifacts.`);
}

// 7 — historical audit, cloned from source slide 39.
{
  const slide = slideAt(7);
  shapeByName(slide, "Google Shape;312;p51").text = "Historical audit: neutral overall, one exploratory Cohort lead";
  const table = tableByName(slide, "Google Shape;313;p51");
  setTable(table, [
    ["Slice", "n", "Mean", "Median", "Signal", "", "Interpretation", ""],
    ["Primary sweep", "1,292", "-0.0246708", "0", "Diagnostic", "", "Not a causal estimand", ""],
    ["qonly corrected", "670", "407/670 within +/-0.005", "249 exact zero", "~61% near-zero", "", "Neutral / fragile", ""],
    ["Cohort bonenv/full", "32/38", "+0.0776291", "+0.0853732", "30+ / 2-", "", "Exploratory lead", ""],
  ]);
  for (let row = 0; row < 4; row += 1) {
    table.merge({ startRow: row, endRow: row, startColumn: 4, endColumn: 5 });
    table.merge({ startRow: row, endRow: row, startColumn: 6, endColumn: 7 });
  }
  sizeTable(table, {
    left: 18,
    top: 164,
    width: 924,
    columnWidths: [185, 75, 150, 145, 90, 90, 94, 95],
    rowHeights: [38, 52, 62, 62],
    fontSize: 14,
  });
  addTextBox(
    slide,
    "TTT-RL historical-audit note",
    "Current prereg qonly historical +0.0609273 = hypothesis selection only, not causal parameter-update evidence.\nFootnote: filtered sweep=results primary families; results_probe excluded.",
    { left: 24, top: 392, width: 912, height: 78 },
    { fontSize: 14 },
  );
  addFooter(slide, 7);
  setNotes(slide, `Task snapshots filter sweep=results primary families and exclude results_probe. Historical audit artifact SHA-256 ${data.historicalAudit.artifactSha256}. Each pairable bonenv/full family has one repeat.`);
}

// 8 — private boundary and causal readiness, cloned from source slide 27.
{
  const slide = slideAt(8);
  shapeByName(slide, "Google Shape;235;p39").text = "Boundary audit is clean, but the provider remains disabled";
  shapeByName(slide, "Google Shape;236;p39").delete();
  setNarrative(shapeByName(slide, "Google Shape;238;p39"), [
    { lead: "AUDIT", body: "d9346b8; 172 passed + 1 skipped; independent current exploitable P0=0 / P1=0." },
    { lead: "FAIL-CLOSED", body: "provider_available=false; public entry fails before runtime or filesystem activity." },
    { lead: "BOUNDARY", body: "Audited fail-closed scaffolding—not production-ready." },
    { lead: "REMAINING", body: "Root capability broker; persisted join; receipt v2-to-v1 alignment; real Linux UID/GID plus RW-to-RO E2E." },
    { lead: "CAUSAL NEXT", body: "Only after PASS: reset/shuffle/rollback, online ICL, N=8. Sales remains secondary." },
  ], {
    fontSize: 17,
    position: { left: 16, top: 121, width: 928, height: 274 },
  });
  const table = tableByName(slide, "Google Shape;237;p39");
  setTable(table, [
    ["Readiness", "Current state", "Allowed now", "Before enable"],
    ["Exploit review", "P0=0 / P1=0", "Scaffolding only", "Broker + persisted join"],
    ["Provider", "false / hard fail", "No production reads", "Schema align + Linux E2E"],
  ]);
  sizeTable(table, {
    left: 0,
    top: 406,
    width: 960,
    columnWidths: [140, 250, 220, 350],
    rowHeights: [26, 28, 28],
    fontSize: 14,
  });
  addFooter(slide, 8);
  setNotes(slide, "The audit milestone is meaningful because it removes current exploitable P0/P1 paths. It does not authorize production use while the provider is unavailable.");
}

// 9 — decision roadmap, cloned from source slide 28.
{
  const slide = slideAt(9);
  shapeByName(slide, "Google Shape;243;p40").text = "Next: finish the causal gate—no broad sweep";
  shapeByName(slide, "Google Shape;244;p40").delete();
  const table = tableByName(slide, "Google Shape;245;p40");
  setTable(table, [
    ["#", "Next step", "Decision unlocked", "Status"],
    ["1", "Finish 6 paired cells + seal attempt-002", "Complete formal artifacts", "Keep current A100 job"],
    ["2", "Open only after seal", "Apply causal gate", "Blind / non-terminal"],
    ["3", "PASS → reward-aware online ICL", "Active > ICL?", "Gated"],
    ["4", "PASS → independent N=8", "Confirmation", "Gated"],
    ["5", "NO-GO → structured latent state", "One pivot only", "Permitted once"],
    ["6", "Transfer to Sales", "Second-task evidence", "Secondary"],
  ]);
  sizeTable(table, {
    left: 0,
    top: 122,
    width: 960,
    columnWidths: [50, 355, 275, 280],
    rowHeights: [34, 42, 42, 42, 42, 42, 42],
    fontSize: 14,
  });
  addTextBox(
    slide,
    "TTT-RL resource ask",
    "Resource ask: Keep the current A100 40G job alive until attempt sealing; no additional GPU allocation and no broad sweep.",
    { left: 24, top: 432, width: 912, height: 50 },
    { fontSize: 15, bold: true },
  );
  addFooter(slide, 9);
  setNotes(slide, "Resource ask: keep the current A100 40G job alive until attempt sealing; no additional GPU allocation and no broad sweep.");
}

await fs.rm(qaDir, { recursive: true, force: true });
await fs.mkdir(path.join(qaDir, "slides"), { recursive: true });
await fs.mkdir(path.join(qaDir, "layouts", "final"), { recursive: true });

for (let index = 0; index < presentation.slides.count; index += 1) {
  const slide = presentation.slides.getItem(index);
  const stem = `slide-${String(index + 1).padStart(2, "0")}`;
  const png = await presentation.export({ slide, format: "png", scale: 2 });
  await fs.writeFile(path.join(qaDir, "slides", `${stem}.png`), new Uint8Array(await png.arrayBuffer()));
  const layout = await slide.export({ format: "layout" });
  await fs.writeFile(path.join(qaDir, "layouts", "final", `${stem}.layout.json`), await layout.text(), "utf8");
}

const montage = await presentation.export({ format: "webp", montage: true, scale: 1 });
await fs.writeFile(path.join(qaDir, "final-montage.webp"), new Uint8Array(await montage.arrayBuffer()));
const inspection = await presentation.inspect({ kind: "slide,textbox,shape,table,notes", maxChars: 200000 });
await fs.writeFile(path.join(qaDir, "final-inspect.ndjson"), inspection.ndjson, "utf8");

const pptx = await PresentationFile.exportPptx(presentation);
await pptx.save(outputPptx);
console.log(JSON.stringify({ outputPptx, qaDir, slides: presentation.slides.count }, null, 2));
