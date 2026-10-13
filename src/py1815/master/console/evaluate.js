// The Evaluate tab of the Satori DNP3 master console.
//
// The checks an evaluation can run, the report of the last run, and the
// deviations of the selected outstation as switches. Like the rest of the
// console it holds no logic. The service lists the checks, runs them, gives
// each its verdict and applies each deviation: the page sends what was
// chosen and shows what the service answered.
//
// It is loaded before console.js and declares only: what it uses of that
// script, it uses once the page is running.

"use strict";

// What each deviation makes the master do, by the name the service gives it.
// A deviation the service names and this list does not is shown by its name.
const DEVIATIONS = {
  silence: "Sends nothing at all: no request and no confirmation.",
  repeat_request: "Sends each request twice, octet for octet.",
  second_master_address: "Sends every frame from another master's address.",
  corrupt_header_crc: "Flips the header checksum of the first frame of each request.",
  corrupt_body_crc: "Flips the last data-block checksum of the first frame of each request.",
  truncate: "Drops the last octet of the first frame of each request.",
  overstate_length: "Claims a length larger than the first frame of each request carries.",
  break_transport_sequence: "Sends the first segment of each request with a transport sequence number that is out of order.",
  orphan_segment: "Sends the first segment of each request as a continuation, so the request has no first segment.",
  endless_series: "Sends the last segment of each request with its final bit clear, so the series never ends.",
  withhold_confirmation: "Withholds the confirmation of every solicited response.",
  late_confirmation: "Sends the confirmation of each solicited response after the master's next request, and not when the response arrives.",
  wrong_confirmation_sequence: "Confirms a solicited response with a sequence number the outstation did not send.",
  withhold_unsolicited_confirmation: "Withholds the confirmation of every unsolicited response.",
};

// The verdicts, in the order a summary counts them, and the word for each.
const VERDICTS = [
  ["passed", "passed"],
  ["failed", "FAILED"],
  ["not_applicable", "not applicable"],
  ["not_run", "not run"],
];
const VERDICT_WORDS = Object.fromEntries(VERDICTS);

// The trace operation returns the newest frames after an id, up to a limit.
// A check's frames are the oldest of those, so the limit must not cut them off.
const EVERY_FRAME = 1000000;

const evaluation = {
  outstation: null,       // the outstation the tab was last loaded for
  loading: false,
  checks: null,           // a checks result, or an error message
  deviations: null,       // a deviate result for the outstation, or an error message
  question: 0,            // counts each time the deviations are read or changed
  unavailable: null,      // why the outstation cannot be evaluated, as the service says it
  selected: null,         // the ids of the checks to run: every check, until one is cleared
  allowDeviations: false,
  runs: new Map(),        // outstation name -> the evaluation under way, or the last one
};

// The evaluation of one outstation: what was asked for, each result as its
// check ends, and the report or the error the run ended with.
function evaluationOf(name) {
  if (!evaluation.runs.has(name)) {
    evaluation.runs.set(name, { running: false, asked: [], results: new Map(), report: null, error: null, gone: new Set() });
  }
  return evaluation.runs.get(name);
}

async function evaluateAnswer(op, params = {}, name = undefined) {
  try {
    return await api(op, params, name);
  } catch (error) {
    return { error: error.message };
  }
}

// Why an outstation with no profile cannot be evaluated, in the service's
// words. Every operation that needs the profile is refused with the same
// message, and this one is refused before anything is sent.
async function evaluateRefusal(name) {
  const answer = await evaluateAnswer("der.functions", {}, name);
  return answer.error || null;
}

// What the tab shows for an outstation, asked for when the outstation is selected.
async function evaluateSelected(name) {
  evaluation.outstation = name;
  evaluation.deviations = null;
  evaluation.unavailable = null;
  evaluation.loading = name !== null;
  // Evaluations of outstations that have been removed are forgotten.
  for (const each of [...evaluation.runs.keys()]) {
    if (!state.outstations.some((outstation) => outstation.name === each)) evaluation.runs.delete(each);
  }
  renderDeviationState();
  if (name === null) return;
  renderEvaluate();
  const outstation = current();
  const listed = evaluation.checks && !evaluation.checks.error;
  evaluation.question += 1;
  const [checks, deviations, unavailable] = await Promise.all([
    listed ? evaluation.checks : evaluateAnswer("checks"),
    evaluateAnswer("deviate", {}, name),
    outstation && !outstation.profile ? evaluateRefusal(name) : null,
  ]);
  if (state.selected !== name) return;
  evaluation.checks = checks;
  if (!checks.error && !evaluation.selected) evaluation.selected = new Set(checks.checks.map((check) => check.id));
  Object.assign(evaluation, { deviations, unavailable, loading: false });
  renderDeviationState();
  renderEvaluate();
}

// ------------------------------------------------------------- deviations

// Read which deviations are on, and show it. The switches show what the
// service answered and not what was clicked. Answers can arrive out of order,
// so only the answer to the newest question is shown.
async function evaluateDeviations() {
  const name = state.selected;
  if (!name || evaluation.loading) return;
  const question = evaluation.question += 1;
  const deviations = await evaluateAnswer("deviate", {}, name);
  if (question !== evaluation.question) return;
  evaluation.deviations = deviations;
  renderDeviationState();
  renderDeviations();
}

async function evaluateDeviate(label, params) {
  const name = state.selected;
  const question = evaluation.question += 1;
  let answer;
  try {
    answer = await ask(label, "deviate", params);
  } catch (error) {
    // Refused: the switches go back to what the service says they are.
    answer = await evaluateAnswer("deviate", {}, name);
    if (!answer.error) answer.refused = error.message;
  }
  if (question !== evaluation.question) return;
  evaluation.deviations = answer;
  renderDeviationState();
  renderDeviations();
}

// The mark beside the outstation's name, on every tab: a deviation left on
// changes what the master sends the outstation, whichever tab is open.
function renderDeviationState() {
  const on = evaluation.deviations?.on || [];
  const chip = $("#deviation-state");
  chip.hidden = !on.length;
  chip.title = on.length ? `On: ${on.join(", ")}. Turn them off on the Evaluate tab.` : "";
}

function deviationNodes() {
  const answer = evaluation.deviations;
  if (!answer) return [el("p", { class: "hint", text: evaluation.loading ? "Reading…" : "" })];
  if (answer.error) return [el("p", { class: "error", text: answer.error })];
  const run = evaluationOf(state.selected);
  const on = answer.on;
  return [
    el("div", { class: "deviation-head" },
      on.length
        ? el("p", { class: "deviations-on", id: "deviations-on", role: "status",
          text: `On: ${on.join(", ")}. What the master sends this outstation is changed until they are turned off.` })
        : el("p", { class: "hint", id: "deviations-on", role: "status", text: "None is on." }),
      el("div", { class: "spacer" }),
      el("button", { id: "deviations-clear", class: "quiet", text: "Turn all off", disabled: !on.length || run.running,
        onclick: () => evaluateDeviate("turn every deviation off", { clear: true }) })),
    answer.refused ? el("p", { class: "error", role: "alert", text: answer.refused }) : null,
    run.running ? el("p", { class: "hint", text: "An evaluation is running, and turns deviations on and off itself. The switches can be changed when it ends." }) : null,
    Object.entries(answer.deviations).map(([name, isOn]) => el("div", { class: "deviation", "data-deviation": name },
      el("label", { class: "check switch" },
        el("input", {
          type: "checkbox",
          role: "switch",
          "data-deviation": name,
          checked: isOn,
          disabled: run.running,
          "aria-label": `${name}: ${DEVIATIONS[name] || "a deviation"}`,
          onchange: (event) => evaluateDeviate(`turn ${name} ${event.target.checked ? "on" : "off"}`, { set: { [name]: event.target.checked } }),
        }),
        el("span", { class: `deviation-state ${isOn ? "on" : ""}`, text: isOn ? "On" : "Off" })),
      el("span", { class: "deviation-name", text: name }),
      el("span", { class: "hint", text: DEVIATIONS[name] || "" }))),
  ];
}

function renderDeviations() {
  const card = $("#evaluate-deviations");
  if (!card) return;
  card.replaceChildren(
    el("h3", {}, "Deviations ", el("span", { class: "hint", text: "protocol rules the master breaks on purpose, to see whether the outstation rejects what it must" })),
    ...deviationNodes().flat(Infinity).filter(Boolean));
}

// ------------------------------------------------------------------ checks

// The checks in the order the service lists them, grouped by set.
function checkSets() {
  const sets = [];
  for (const check of evaluation.checks.checks) {
    let entry = sets.find((each) => each.name === check.set);
    if (!entry) sets.push(entry = { name: check.set, checks: [] });
    entry.checks.push(check);
  }
  return sets;
}

function verdictNode(verdict) {
  return el("span", { class: `check-verdict ${verdict}`, text: VERDICT_WORDS[verdict] || verdict });
}

// What a check found: why it ended as it did, what it noted, what it cost,
// and the way to its frames in the Traffic tab.
function foundNodes(result, run) {
  const frames = result.frames;
  const gone = run.gone.has(result.id);
  return [
    result.detail ? el("div", { class: `check-detail ${result.verdict}`, text: result.detail }) : null,
    result.notes.map((text) => el("div", { class: "hint check-note", text: `note: ${text}` })),
    result.requests || frames ? el("div", { class: "hint check-cost" },
      `${result.requests} request(s), ${result.seconds} s`,
      frames && !gone ? [", ", el("button", { class: "link", "data-frames": result.id, text: `frames ${frames[0]} to ${frames[1]}`,
        title: "Show these frames in the Traffic tab", onclick: () => evaluateFrames(result) })] : null,
      frames && gone ? `, frames ${frames[0]} to ${frames[1]}, not all of which the master still keeps` : null) : null,
  ];
}

function checkRow(check, run) {
  const result = run.results.get(check.id);
  const pending = run.running && run.asked.includes(check.id);
  return el("tr", { "data-check": check.id },
    el("td", { class: "pick" }, el("input", {
      type: "checkbox",
      "data-check": check.id,
      checked: evaluation.selected.has(check.id),
      "aria-label": `Run ${check.id}, ${check.title}`,
      onchange: (event) => evaluatePick([check.id], event.target.checked),
    })),
    el("td", { class: "mono", text: check.id }),
    // A result's title can say more than the list's: a function check names
    // the function it found, and whether the outstation supports it.
    el("td", { class: "name" }, el("span", { class: "check-title", text: result ? result.title : check.title }),
      check.writes ? el("span", { class: "flag mark writes", text: "writes", title: "Writes to the outstation" }) : null,
      check.deviates ? el("span", { class: "flag mark deviates", text: "deviates", title: "Has the master break a protocol rule on purpose" }) : null),
    el("td", { class: "verdict-cell" }, result ? verdictNode(result.verdict) : (pending ? el("span", { class: "hint", text: "pending" }) : null)),
    el("td", { class: "found" }, result ? foundNodes(result, run) : null));
}

function setRow(set) {
  return el("tr", { class: "check-set", "data-set": set.name },
    el("td", { class: "pick" }, el("input", {
      type: "checkbox",
      "data-set": set.name,
      "aria-label": `Run every check of the set ${set.name}`,
      onchange: (event) => evaluatePick(set.checks.map((check) => check.id), event.target.checked),
    })),
    el("td", { colspan: "4" }, el("span", { class: "set-name", text: set.name }),
      el("span", { class: "hint set-count" })));
}

// The parts of the tab that follow from which checks are picked: each set's
// own box, the count beside it, and whether there is anything to run.
function renderPicked() {
  if (!evaluation.checks || evaluation.checks.error) return;
  const run = evaluationOf(state.selected);
  for (const set of checkSets()) {
    const picked = set.checks.filter((check) => evaluation.selected.has(check.id)).length;
    const box = [...document.querySelectorAll("#evaluate-checks input[data-set]")].find((each) => each.dataset.set === set.name);
    if (!box) continue;
    box.checked = picked === set.checks.length;
    box.indeterminate = picked > 0 && picked < set.checks.length;
    box.closest("tr").querySelector(".set-count").textContent = `${picked} of ${set.checks.length} chosen`;
  }
  for (const box of document.querySelectorAll("#evaluate-checks input[data-check]")) {
    box.checked = evaluation.selected.has(box.dataset.check);
  }
  const button = $("#evaluate-run");
  if (button) {
    button.disabled = run.running || evaluation.selected.size === 0;
    button.textContent = run.running ? "Running…" : "Run";
  }
}

function evaluatePick(ids, picked) {
  for (const id of ids) {
    if (picked) evaluation.selected.add(id);
    else evaluation.selected.delete(id);
  }
  renderPicked();
}

function progressText(run) {
  if (!run.running) return "";
  const ended = run.asked.filter((id) => run.results.has(id)).length;
  return `${ended} of ${run.asked.length} check(s) ended`;
}

function reportNodes(name, run) {
  const report = run.report;
  if (!report) return [];
  return [
    el("h4", { text: "Report" }),
    el("div", { class: "report", id: "evaluate-report" },
      el("dl", { class: "facts", id: "evaluate-summary" }, VERDICTS.map(([verdict]) => [
        el("dt", {}, verdictNode(verdict)),
        el("dd", { "data-verdict": verdict, text: report.summary[verdict] ?? 0 })])),
      el("dl", { class: "facts" },
        el("dt", { text: "Outstation" }), el("dd", { text: report.outstation }),
        el("dt", { text: "Started" }), el("dd", { text: report.started }),
        el("dt", { text: "Profile tables" }), el("dd", { text: report.tables }),
        el("dt", { text: "Checks that write" }), el("dd", { text: report.allow_control ? "Allowed" : "Not allowed: commanding is off" }),
        el("dt", { text: "Checks that break a protocol rule" }), el("dd", { text: report.allow_deviations ? "Allowed" : "Not allowed" })),
      el("div", {}, el("button", { id: "evaluate-save", class: "quiet", text: "Save report",
        title: "Save the report as a JSON file", onclick: () => evaluateSave(name, report) }))),
  ];
}

function checkNodes(name) {
  const run = evaluationOf(name);
  if (evaluation.loading || !evaluation.checks) return [el("p", { class: "hint", text: "Reading…" })];
  if (evaluation.unavailable) return [el("p", { class: "hint", id: "evaluate-unavailable", text: evaluation.unavailable })];
  if (evaluation.checks.error) return [el("p", { class: "error", text: evaluation.checks.error })];
  return [
    state.allowControl
      ? el("p", { class: "hint", id: "evaluate-commanding", text: "Commanding is on: the checks that write change the outstation's settings, curves and switches. Use them on a device on a bench, not on one in service." })
      : el("p", { class: "hint", id: "evaluate-read-only", text: "Commanding is off: the checks that write will be reported as not run. Start the console with --allow-control to run them." }),
    el("p", { class: "hint", text: "A check that breaks a protocol rule is run only when the switch below allows it, and is otherwise reported as not run." }),
    el("div", { class: "inline evaluate-controls" },
      el("div", { class: "buttons" },
        el("button", { id: "evaluate-all", class: "quiet", text: "All", "aria-label": "Choose every check",
          onclick: () => evaluatePick(evaluation.checks.checks.map((check) => check.id), true) }),
        el("button", { id: "evaluate-none", class: "quiet", text: "None", "aria-label": "Choose no check",
          onclick: () => evaluatePick(evaluation.checks.checks.map((check) => check.id), false) })),
      el("label", { class: "check switch" },
        el("input", { type: "checkbox", role: "switch", id: "evaluate-allow-deviations", checked: evaluation.allowDeviations,
          onchange: (event) => { evaluation.allowDeviations = event.target.checked; } }),
        "Allow the checks that break a protocol rule"),
      el("button", { id: "evaluate-run", class: "primary", text: "Run", onclick: evaluateRun }),
      el("span", { class: "hint", id: "evaluate-progress", role: "status", text: progressText(run) })),
    run.error ? el("p", { class: "error", id: "evaluate-error", role: "alert", text: run.error }) : null,
    ...reportNodes(name, run),
    el("div", { class: "table-wrap", id: "evaluate-checks-wrap" },
      el("table", { id: "evaluate-checks" },
        el("thead", {}, el("tr", {},
          el("th", { class: "w-pick", "aria-label": "Run" }), el("th", { class: "w-check", text: "Check" }), el("th", { text: "Title" }),
          el("th", { class: "w-verdict", text: "Verdict" }), el("th", { text: "Found" }))),
        checkSets().map((set) => el("tbody", { "data-set": set.name }, setRow(set), set.checks.map((check) => checkRow(check, run)))))),
  ];
}

// ------------------------------------------------------------------ running

// Run the chosen checks, in the order the service lists them. The answer
// comes when the last has ended; each result arrives before that as an event.
async function evaluateRun() {
  const name = state.selected;
  const run = evaluationOf(name);
  const asked = evaluation.checks.checks.map((check) => check.id).filter((id) => evaluation.selected.has(id));
  // An empty list would ask for every check, so there has to be one chosen.
  if (run.running || !asked.length) return;
  Object.assign(run, { running: true, asked, results: new Map(), report: null, error: null, gone: new Set() });
  renderEvaluate();
  note(`${name}: evaluation of ${asked.length} check(s) started`);
  try {
    run.report = await api("evaluate", { checks: asked, allow_deviations: evaluation.allowDeviations }, name);
    for (const result of run.report.results) run.results.set(result.id, result);
    const counted = VERDICTS.map(([verdict, word]) => `${run.report.summary[verdict] ?? 0} ${word}`).join(", ");
    note(`${name}: evaluation ended: ${counted}`, (run.report.summary.failed ?? 0) > 0);
  } catch (error) {
    run.error = error.message;
    note(`${name}: evaluation failed: ${error.message}`, true);
  }
  run.running = false;
  if (state.selected === name) {
    renderEvaluate();
    // A check that deviates turns its deviation off again: show what is on now.
    evaluateDeviations();
  }
  refreshStatus();
}

// A check ended, as the service's event stream reports it.
function evaluateEnded(name, result) {
  const run = evaluationOf(name);
  run.results.set(result.id, result);
  if (name !== state.selected || state.tab !== "evaluate") return;
  const row = [...document.querySelectorAll("#evaluate-checks tr[data-check]")].find((each) => each.dataset.check === result.id);
  if (row) {
    row.querySelector(".check-title").textContent = result.title;
    row.querySelector(".verdict-cell").replaceChildren(verdictNode(result.verdict));
    row.querySelector(".found").replaceChildren(...foundNodes(result, run).flat(Infinity).filter(Boolean));
  }
  const progress = $("#evaluate-progress");
  if (progress) progress.textContent = progressText(run);
}

// Narrow the Traffic tab to the frames of one check, read from the master's trace.
async function evaluateFrames(result) {
  const name = state.selected;
  const run = evaluationOf(name);
  const [first, last] = result.frames;
  let trace;
  try {
    trace = await ask(`read frames ${first} to ${last}, of ${result.id}`, "trace", { after: first - 1, limit: EVERY_FRAME });
  } catch (error) {
    return;
  }
  if (state.selected !== name) return;
  // The trace drops its oldest frames, so the answer can begin after the
  // check did. Part of a check's frames is not shown as all of them.
  const frames = trace.frames.filter((frame) => frame.id <= last);
  if (!frames.length || frames[0].id !== first || frames[frames.length - 1].id !== last) {
    run.gone.add(result.id);
    renderEvaluate();
    return;
  }
  state.range = { check: result.id, first, last, frames };
  state.frame = null;
  showTab("traffic");
}

function evaluateSave(name, report) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const stamp = String(report.started).slice(0, 19).replace(/[-:]/g, "").replace("T", "-");
  const link = el("a", { href: url, download: `${name}-evaluation-${stamp}.json`, hidden: true });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ------------------------------------------------------------------ render

function renderEvaluate() {
  const panel = $("#evaluate-content");
  if (!panel || state.tab !== "evaluate" || !state.selected) return;
  panel.replaceChildren(
    el("div", { class: "card spaced", id: "evaluate-card" },
      el("h3", {}, "Checks ", el("span", { class: "hint", text: "each a procedure a master carries out, with a verdict" })),
      ...checkNodes(state.selected).filter(Boolean)),
    el("div", { class: "card spaced", id: "evaluate-deviations" }));
  renderDeviations();
  renderPicked();
}
