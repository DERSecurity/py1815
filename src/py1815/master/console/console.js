// The Satori DNP3 master console.
//
// It holds no logic of its own: it asks the master's service for things and
// shows what comes back. Everything here can be done by a script with the
// same messages.

"use strict";

const TOKEN = new URLSearchParams(location.search).get("token");

const POINT_TYPES = [
  ["bi", "Binary inputs"],
  ["bo", "Binary outputs"],
  ["counter", "Counters"],
  ["frozen", "Frozen counters"],
  ["ai", "Analog inputs"],
  ["ao", "Analog outputs"],
];
const TYPE_LABELS = Object.fromEntries(POINT_TYPES);

const INDICATIONS = [
  ["IIN1.0", "BROADCAST"],
  ["IIN1.1", "CLASS_1_EVENTS"],
  ["IIN1.2", "CLASS_2_EVENTS"],
  ["IIN1.3", "CLASS_3_EVENTS"],
  ["IIN1.4", "NEED_TIME"],
  ["IIN1.5", "LOCAL_CONTROL"],
  ["IIN1.6", "DEVICE_TROUBLE"],
  ["IIN1.7", "DEVICE_RESTART"],
  ["IIN2.0", "FUNC_NOT_SUPPORTED", true],
  ["IIN2.1", "OBJECT_UNKNOWN", true],
  ["IIN2.2", "PARAM_ERROR", true],
  ["IIN2.3", "EVENT_BUFFER_OVERFLOW", true],
  ["IIN2.4", "ALREADY_EXECUTING", true],
  ["IIN2.5", "CONFIG_CORRUPT", true],
];

const KEPT_FRAMES = 600;
const KEPT_EVENTS = 1000;
const KEPT_LOG = 300;
const FRESH_SECONDS = 10;
// How long a value that just changed stays marked.
const FRESH_MARK_SECONDS = 3;

const state = {
  outstations: [],
  selected: null,
  tab: "overview",
  pointType: "ai",
  points: {},        // type -> Map(index -> row)
  profile: null,     // type -> Map(index -> point of the profile), when one is known
  events: [],
  frames: [],
  frame: null,       // the frame shown in detail
  log: [],
  allowControl: false,  // whether the service behind this page commands outstations
};

// What a binary output was told, by the control code that told it.
const OPERATIONS = { 3: "Latch on", 4: "Latch off", 1: "Pulse on", 2: "Pulse off", 129: "Trip", 65: "Close" };

// --------------------------------------------------------------- utilities

const $ = (selector) => document.querySelector(selector);

function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (value === false || value === null || value === undefined) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function clockTime(seconds) {
  const date = new Date(seconds * 1000);
  const pad = (number, width = 2) => String(number).padStart(width, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

function stationTime(milliseconds) {
  if (milliseconds === null || milliseconds === undefined) return "";
  return new Date(milliseconds).toISOString().replace("T", " ").replace("Z", " UTC");
}

function formatValue(value) {
  if (value === null || value === undefined) return "";
  if (value === true) return "ON";
  if (value === false) return "OFF";
  if (typeof value === "number" && !Number.isInteger(value)) return value.toPrecision(7).replace(/\.?0+$/, "");
  return String(value);
}

function flagChips(flags) {
  if (flags === null || flags === undefined) return el("span", { class: "flag none", text: "no flags", title: "This variation carries no flag octet" });
  if (flags.length === 0) return el("span", { class: "flag alarm", text: "none set", title: "No flag is set, not even ONLINE" });
  return flags.map((flag) =>
    el("span", { class: `flag ${flag === "ONLINE" ? "ONLINE" : "alarm"}`, text: flag }));
}

async function api(op, params = {}, outstation = undefined) {
  const message = { id: crypto.randomUUID(), op, params };
  if (outstation !== undefined) message.outstation = outstation;
  const headers = { "Content-Type": "application/json" };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  const response = await fetch("api", { method: "POST", headers, body: JSON.stringify(message) });
  if (!response.ok) throw new Error(await response.text());
  const answer = await response.json();
  if (!answer.ok) throw new Error(answer.error.message);
  return answer.result;
}

function note(text, bad = false) {
  state.log.unshift({ at: Date.now() / 1000, text, bad });
  state.log.length = Math.min(state.log.length, KEPT_LOG);
  if (state.tab === "log") renderLog();
}

async function ask(label, op, params = {}) {
  const name = state.selected;
  try {
    const result = await api(op, params, name);
    note(`${name}: ${label}`);
    return result;
  } catch (error) {
    note(`${name}: ${label} failed: ${error.message}`, true);
    throw error;
  }
}

// A point's name as it is shown. An enumerated point's values are written
// into its name in the profile's tables; here the name stands alone, with a
// mark beside it that lists the values when pointed at.
function nameNodes(type, index, name) {
  const point = state.profile?.[type]?.get(index);
  if (!point || !point.enumeration) return [point ? point.label : (name || "")];
  const values = point.enumeration.map((entry) => `${entry.value}: ${entry.name}`).join("\n");
  return [point.label, el("span", {
    class: "info",
    tabindex: "0",
    role: "img",
    "aria-label": `Values: ${point.enumeration.map((entry) => `${entry.value} ${entry.name}`).join(", ")}`,
    "data-tip": values,
    onmouseenter: (event) => showTip(event.currentTarget),
    onmouseleave: hideTip,
    onfocus: (event) => showTip(event.currentTarget),
    onblur: hideTip,
  }, "i")];
}

// One tooltip for the whole page, placed against the screen and not inside
// the table, so the table's own scrolling cannot cut it off.
const tip = el("div", { class: "tip", role: "tooltip", hidden: true });
let tipOwner = null;

function showTip(target) {
  tipOwner = target;
  tip.textContent = target.dataset.tip;
  tip.hidden = false;
  const mark = target.getBoundingClientRect();
  const box = tip.getBoundingClientRect();
  const left = Math.min(mark.left, window.innerWidth - box.width - 12);
  const below = mark.bottom + 8;
  const top = below + box.height > window.innerHeight - 8 ? mark.top - box.height - 8 : below;
  tip.style.left = `${Math.max(12, left)}px`;
  tip.style.top = `${Math.max(8, Math.min(top, window.innerHeight - box.height - 8))}px`;
}

function hideTip() {
  tipOwner = null;
  tip.hidden = true;
}

// The list follows its mark when the table scrolls under it. Reaching a mark
// with the keyboard scrolls it into view, and that must not put the list away.
function followTip() {
  if (!tipOwner) return;
  if (tipOwner.isConnected) showTip(tipOwner);
  else hideTip();
}

function current() {
  return state.outstations.find((outstation) => outstation.name === state.selected) || null;
}

// ------------------------------------------------------------ outstations

async function refreshStatus() {
  const status = await api("status");
  state.outstations = status.outstations;
  if (state.allowControl !== Boolean(status.allow_control) || $("#control-state").hidden) {
    state.allowControl = Boolean(status.allow_control);
    renderControl();
  }
  if (state.selected && !current()) select(null);
  if (!state.selected && state.outstations.length) await select(state.outstations[0].name);
  renderOutstations();
  renderHeader();
  if (state.tab === "overview") renderOverview();
}

function renderOutstations() {
  const list = $("#outstations");
  list.replaceChildren();
  if (!state.outstations.length) {
    list.append(el("li", { class: "none", text: "None added" }));
    $("#add-panel").open = true;
  }
  for (const outstation of state.outstations) {
    list.append(el("li", {
      "aria-selected": String(outstation.name === state.selected),
      onclick: () => select(outstation.name),
    },
      el("span", { class: `lamp ${outstation.connected ? "on" : "off"}`, title: outstation.connected ? "Connected" : "Not connected" }),
      el("div", {},
        el("div", { class: "name", text: outstation.name }),
        el("div", { class: "where", text: `${outstation.host}:${outstation.port} · addr ${outstation.outstation_address}` }))));
  }
}

async function select(name) {
  state.selected = name;
  state.points = {};
  state.profile = null;
  state.events = [];
  state.frames = [];
  state.frame = null;
  $("#point-unreported-label").hidden = true;
  $("#workspace").hidden = name === null;
  $("#empty").hidden = name !== null;
  renderOutstations();
  if (name === null) return;
  renderHeader();
  const [values, events, trace, profile] = await Promise.all([
    api("values", {}, name),
    api("events", { limit: KEPT_EVENTS }, name),
    api("trace", { limit: KEPT_FRAMES }, name),
    api("profile", {}, name),
  ]);
  if (state.selected !== name) return;
  if (profile.points) {
    state.profile = Object.fromEntries(Object.entries(profile.points)
      .map(([type, points]) => [type, new Map(points.map((point) => [point.index, point]))]));
  }
  $("#point-unreported-label").hidden = !state.profile;
  const loaded = performance.now() / 1000;
  for (const [type, rows] of Object.entries(values.points)) {
    state.points[type] = new Map(rows.map((row) => [row.index, { ...row, seen: loaded - row.age, changed: null }]));
  }
  state.events = events.events.map((event) => ({ ...event, received: null, unsolicited: null })).reverse();
  state.frames = trace.frames;
  renderAll();
}

function renderHeader() {
  const outstation = current();
  if (!outstation) return;
  $("#title").textContent = outstation.name;
  const chip = $("#title-state");
  chip.textContent = outstation.connected ? "Connected" : "Not connected";
  chip.className = `chip ${outstation.connected ? "good" : "bad"}`;
  $("#connect-button").textContent = outstation.connected ? "Disconnect" : "Connect";
}

// Whether this page can command is the service's to say, and is said plainly:
// a master is pointed at real equipment.
function renderControl() {
  const chip = $("#control-state");
  chip.hidden = false;
  chip.textContent = state.allowControl ? "Commanding on" : "Read only";
  chip.className = `chip ${state.allowControl ? "armed" : ""}`;
  $("#operate-fields").disabled = !state.allowControl;
  $("#control-off").hidden = state.allowControl;
  for (const button of document.querySelectorAll("#write-buttons button")) {
    button.disabled = !state.allowControl;
  }
  pointHead = null;
  pointRows = new Map();
  if (state.tab === "points") renderPoints();
}

function showOperateFields() {
  const type = $("#operate-form").elements.type.value;
  for (const label of document.querySelectorAll("#operate-form [data-for]")) {
    label.hidden = label.dataset.for !== type;
  }
  $("#operate-form").elements.value.required = type === "ao";
}

// From an output's row to the form that operates it, filled in.
function operatePoint(type, index, value) {
  const form = $("#operate-form");
  form.elements.type.value = type;
  form.elements.index.value = index;
  if (type === "ao" && typeof value === "number") form.elements.value.value = value;
  if (type === "bo" && typeof value === "boolean") form.elements.operation.value = value ? "latch_off" : "latch_on";
  showOperateFields();
  showTab("commands");
  (type === "ao" ? form.elements.value : form.elements.operation).focus();
}

// ---------------------------------------------------------------- overview

function facts(target, pairs) {
  const list = $(target);
  list.replaceChildren();
  for (const [term, value] of pairs) {
    list.append(el("dt", { text: term }), el("dd", { text: value }));
  }
}

// What the master does for an outstation without being asked, in the order
// the service names it, and what each request it makes for one is called.
const TASKS = [
  ["startup", "On connecting, and after a restart", "Stops unsolicited reporting, reads everything"],
  ["clear_restart", "Restart indication", "Cleared when seen"],
  ["write_time", "Clock", "Set when the outstation asks"],
  ["events_when_indicated", "Events waiting", "Fetched when a response says so"],
  ["integrity_on_overflow", "Event buffer overflow", "Everything read again"],
];

const WRITING_TASKS = ["clear_restart", "write_time"];

const TASK_REQUESTS = {
  disable_unsolicited: "stopped unsolicited reporting, on connecting",
  clear_restart: "cleared the restart indication",
  write_time: "set the clock",
  integrity: "read everything",
  events: "fetched the events waiting",
  enable_unsolicited: "turned unsolicited reporting on",
};

function renderOverview() {
  const outstation = current();
  if (!outstation) return;
  const repeat = Object.entries(outstation.repeat).map(([kind, seconds]) => `${kind} every ${seconds} s`);
  facts("#overview-connection", [
    ["Address", `${outstation.host}:${outstation.port}`],
    ["Outstation address", outstation.outstation_address],
    ["Master address", outstation.master_address],
    ["State", outstation.connected ? "Connected" : "Not connected"],
    ["Last response", outstation.last_response_at ? clockTime(outstation.last_response_at) : "None"],
    ["Repeated scans", repeat.length ? repeat.join(", ") : "None"],
  ]);
  const counts = outstation.counts;
  facts("#overview-counts", [
    ["Answered", counts.complete || 0],
    ["Timed out", counts.timeout || 0],
    ["Abandoned", counts.abandoned || 0],
    ["Unsolicited responses", outstation.unsolicited],
    ["Frames recorded", outstation.frames],
  ]);
  facts("#overview-points", POINT_TYPES.map(([type, label]) => [label, outstation.points[type] || 0])
    .concat([["Events", outstation.events]]));
  const tasks = outstation.tasks;
  // The two that write are off in a service that only reads, whatever was asked.
  const alone = (task) => (WRITING_TASKS.includes(task) && !state.allowControl
    ? "Left alone: the console is read only" : "Left alone");
  facts("#overview-tasks", TASKS.map(([task, label, done]) => [label, tasks[task] ? done : alone(task)])
    .concat([
      ["Unsolicited reporting", tasks.enable_unsolicited.length
        ? `Turned on for class ${tasks.enable_unsolicited.join(", ")}` : "Not asked for"],
      ["Lost connection", outstation.reconnect === null
        ? "Not made again" : `Made again, trying every ${outstation.reconnect} s`],
    ]));

  const set = new Set(outstation.indications);
  const lamps = $("#indications");
  lamps.replaceChildren();
  for (const [bit, name, error] of INDICATIONS) {
    lamps.append(el("div", { class: `indication ${error ? "error" : ""} ${set.has(name) ? "set" : ""}` },
      el("span", { class: "lamp" }), `${bit} ${name}`));
  }

  const form = $("#repeat-form");
  if (document.activeElement?.form !== form) {
    form.elements.integrity.value = outstation.repeat.integrity ?? "";
    form.elements.events.value = outstation.repeat.events ?? "";
    form.elements.outputs.value = outstation.repeat.outputs ?? "";
  }
}

// ------------------------------------------------------------------ points

function applyObjects(objects, unsolicited) {
  const now = performance.now() / 1000;
  const received = Date.now() / 1000;
  for (const object of objects) {
    if (object.type === null || object.index === null) continue;
    if (!state.points[object.type]) state.points[object.type] = new Map();
    // A value reported again unchanged has not changed, and a point seen for
    // the first time has nothing to have changed from. Only a different value
    // or different flags mark the row.
    const before = state.points[object.type].get(object.index);
    const same = before && before.value === object.value
      && JSON.stringify(before.flags) === JSON.stringify(object.flags);
    const changed = before ? (same ? before.changed : now) : null;
    state.points[object.type].set(object.index, {
      index: object.index,
      name: object.name,
      value: object.value,
      flags: object.flags,
      time_ms: object.time_ms,
      from_event: object.event,
      group: object.group,
      variation: object.variation,
      seen: now,
      changed,
    });
    if (object.event) state.events.unshift({ ...object, received, unsolicited });
  }
  state.events.length = Math.min(state.events.length, KEPT_EVENTS);
}

// The points of the profile, by type, when the service knows which profile
// the outstation is meant to serve.
function profileOf(type) {
  return state.profile ? state.profile[type] : null;
}

function showingUnreported() {
  return Boolean(state.profile) && $("#point-unreported").checked;
}

function renderPointTypes() {
  const bar = $("#point-types");
  bar.replaceChildren();
  for (const [type, label] of POINT_TYPES) {
    const count = state.points[type]?.size || 0;
    const whole = showingUnreported() ? ` of ${profileOf(type).size}` : "";
    bar.append(el("button", {
      "aria-pressed": String(type === state.pointType),
      onclick: () => { state.pointType = type; renderPoints(); },
    }, `${label} `, el("span", { class: "count", text: `${count}${whole}` })));
  }
}

// The rows on screen, by point, with what each was drawn from. A row whose
// point has not changed is left exactly where it is: a poll that reports the
// same value again must not disturb a table somebody is reading.
let pointRows = new Map();
let pointHead = null;

function operateCell(type, index, value) {
  return el("td", { class: "act" },
    el("button", { class: "quiet", text: "Operate", onclick: () => operatePoint(type, index, value) }));
}

function unreportedRow(point, operable) {
  return el("tr", { class: "unreported" },
    el("td", { class: "num", text: point.index }),
    el("td", { class: "name" }, nameNodes(state.pointType, point.index, point.name),
      point.mandatory && el("span", { class: "flag alarm mandatory", text: "MANDATORY", title: "The profile requires every outstation to implement this point" })),
    el("td", { class: "num value" }),
    el("td", { class: "flags" }, el("span", { class: "flag none", text: "NOT REPORTED" })),
    el("td", {}),
    el("td", {}),
    el("td", {}),
    el("td", { class: "num age" }),
    operable && operateCell(state.pointType, point.index, null));
}

function renderPoints() {
  renderPointTypes();
  const reported = state.points[state.pointType] || new Map();
  const profile = profileOf(state.pointType);
  const unreported = showingUnreported()
    ? [...profile.values()].filter((point) => !reported.has(point.index))
    : [];
  const rows = [...reported.values(), ...unreported.map((point) => ({ ...point, unreported: true }))]
    .sort((a, b) => a.index - b.index);
  const named = Boolean(profile) || rows.some((row) => row.name);
  const filter = $("#point-filter").value.trim().toLowerCase();
  const changedOnly = $("#point-changed").checked;
  const now = performance.now() / 1000;

  // An output's row carries the way to operate it, where this page can.
  const operable = state.allowControl && (state.pointType === "bo" || state.pointType === "ao");
  const head = `${named}:${operable}`;
  if (pointHead !== head) {
    pointHead = head;
    $("#points-table thead").replaceChildren(el("tr", {},
      el("th", { class: "num w-index", text: "Index" }),
      named && el("th", { text: "Name" }),
      el("th", { class: "num w-value", text: "Value" }),
      el("th", { class: "w-flags", text: "Flags" }),
      el("th", { class: "w-time", text: "Outstation time" }),
      el("th", { class: "w-object", text: "Object" }),
      el("th", { class: "w-source", text: "Reported by" }),
      el("th", { class: "num w-age", text: "Age" }),
      operable && el("th", { class: "w-act" })));
  }

  const kept = new Map();
  const nodes = [];
  let shownReported = 0;
  for (const row of rows) {
    if (filter) {
      const haystack = `${row.index} ${row.name || ""} ${(row.flags || []).join(" ")} ${row.unreported ? "not reported" : ""} ${row.unreported && row.mandatory ? "mandatory" : ""}`.toLowerCase();
      if (!haystack.includes(filter)) continue;
    }
    if (row.unreported) {
      if (changedOnly) continue;
      const key = `${state.pointType}:${row.index}:unreported:${operable}`;
      const entry = pointRows.get(key) || { drawn: "", node: unreportedRow(row, operable) };
      entry.node.dataset.seen = "";
      kept.set(key, entry);
      nodes.push(entry.node);
      continue;
    }
    const age = now - row.seen;
    const sinceChange = row.changed === null ? Infinity : now - row.changed;
    if (changedOnly && sinceChange > FRESH_SECONDS) continue;
    const key = `${state.pointType}:${row.index}:${named}:${operable}`;
    const drawn = JSON.stringify([row.name, row.value, row.flags, row.time_ms, row.group, row.variation, row.from_event]);
    let entry = pointRows.get(key);
    if (!entry || entry.drawn !== drawn) {
      entry = {
        drawn,
        node: el("tr", {},
          el("td", { class: "num", text: row.index }),
          named && el("td", { class: "name" }, nameNodes(state.pointType, row.index, row.name)),
          el("td", { class: `num value ${row.value === true ? "on" : ""}`, text: formatValue(row.value) }),
          el("td", { class: "flags" }, flagChips(row.flags)),
          el("td", { text: stationTime(row.time_ms) }),
          el("td", { class: "mono", text: `g${row.group}v${row.variation}` }),
          el("td", {}, el("span", { class: `source ${row.from_event ? "event" : ""}`, text: row.from_event ? "Event" : "Static" })),
          el("td", { class: "num age" }),
          operable && operateCell(state.pointType, row.index, row.value)),
      };
    }
    entry.node.dataset.seen = row.seen;
    entry.node.dataset.changed = row.changed === null ? "" : row.changed;
    entry.node.classList.toggle("fresh", sinceChange < FRESH_MARK_SECONDS);
    entry.node.querySelector(".age").textContent = ageText(age);
    kept.set(key, entry);
    nodes.push(entry.node);
    shownReported += 1;
  }
  pointRows = kept;

  const body = $("#points-table tbody");
  const current = [...body.children];
  if (current.length === nodes.length) {
    nodes.forEach((node, position) => { if (current[position] !== node) current[position].replaceWith(node); });
  } else {
    body.replaceChildren(...nodes);
  }

  const label = TYPE_LABELS[state.pointType].toLowerCase();
  let summary;
  if (showingUnreported()) {
    const mandatory = unreported.filter((point) => point.mandatory).length;
    summary = `${reported.size} reported and ${unreported.length} not, of ${profile.size} ${label} in the profile`
      + (mandatory ? `; ${mandatory} of those not reported are mandatory` : "");
  } else if (reported.size) {
    summary = `${shownReported} of ${reported.size} ${label}`;
  } else if (["bo", "ao"].includes(state.pointType)) {
    summary = "None reported. Output status is not part of an integrity poll: read it from Commands, or repeat it there.";
  } else {
    summary = `No ${label} reported. Run an integrity poll, or read the group.`;
  }
  $("#point-summary").textContent = summary;
}

function ageText(age) {
  return age < 1 ? "now" : `${Math.round(age)} s`;
}

// Once a second the ages move on. Only the age cells are touched: rebuilding
// the table for it would make the whole thing shift under the reader's eye.
function tickAges() {
  if ($("#point-changed").checked) {
    // Rows leave this view as they age, so it has to be drawn again.
    renderPoints();
    return;
  }
  const now = performance.now() / 1000;
  for (const row of document.querySelectorAll("#points-table tbody tr")) {
    if (row.dataset.seen === "") continue;
    const age = now - Number(row.dataset.seen);
    const fresh = row.dataset.changed !== "" && now - Number(row.dataset.changed) < FRESH_MARK_SECONDS;
    row.classList.toggle("fresh", fresh);
    row.querySelector(".age").textContent = ageText(age);
  }
}

// ------------------------------------------------------------------ events

function renderEvents() {
  $("#events-count").textContent = state.events.length || "";
  if (state.tab !== "events") return;
  const body = $("#events-table tbody");
  body.replaceChildren();
  for (const event of state.events.slice(0, 400)) {
    body.append(el("tr", {},
      el("td", { class: "mono", text: event.received ? clockTime(event.received) : "" }),
      el("td", { text: TYPE_LABELS[event.type] || "" }),
      el("td", { class: "num", text: event.index }),
      el("td", { class: "name" }, nameNodes(event.type, event.index, event.name)),
      el("td", { class: "num value", text: formatValue(event.value) }),
      el("td", { class: "flags" }, flagChips(event.flags)),
      el("td", { text: stationTime(event.time_ms) }),
      el("td", { text: event.unsolicited === null ? "" : event.unsolicited ? "Unsolicited" : "Polled" })));
  }
}

// ----------------------------------------------------------------- traffic

function frameShown(frame) {
  const direction = $("#traffic-direction [aria-pressed='true']").dataset.direction;
  if (direction !== "all" && frame.direction !== direction) return false;
  if ($("#traffic-application").checked && !frame.application) return false;
  return true;
}

function renderTraffic() {
  $("#traffic-count").textContent = state.frames.length || "";
  if (state.tab !== "traffic") return;
  const body = $("#traffic-table tbody");
  body.replaceChildren();
  const shown = state.frames.filter(frameShown).slice(-300).reverse();
  if (!state.frame && shown.length) {
    // Something to read as soon as the tab is opened: the newest fragment.
    state.frame = shown.find((frame) => frame.application) || shown[0];
    renderFrame();
  }
  for (const frame of shown) {
    body.append(el("tr", {
      "aria-selected": String(state.frame?.id === frame.id),
      onclick: () => { state.frame = frame; renderTraffic(); renderFrame(); },
    },
      el("td", { class: "mono", text: clockTime(frame.at) }),
      el("td", { class: `direction ${frame.direction}`, text: frame.direction === "tx" ? "→" : "←", title: frame.direction === "tx" ? "Sent" : "Received" }),
      el("td", { class: "summary", text: frame.summary }),
      el("td", { class: "num", text: frame.octets.length / 2 })));
  }
}

// Which layer each octet of a frame belongs to. A frame is a ten-octet header
// and then blocks of up to sixteen octets of user data, each with a CRC.
function octetLayers(hex) {
  const count = hex.length / 2;
  const layers = [];
  for (let position = 0; position < count; position += 1) {
    if (position < 8) layers.push("link");
    else if (position < 10) layers.push("crc");
    else {
      const within = (position - 10) % 18;
      const remaining = count - (position - within);
      const data = Math.min(16, remaining - 2);
      layers.push(within < data ? "application" : "crc");
    }
  }
  const first = layers.indexOf("application");
  if (first !== -1) layers[first] = "transport";
  return layers;
}

function layer(name, title, pairs) {
  const present = pairs.filter(([, value]) => value !== undefined && value !== null && value !== "");
  return el("div", { class: "layer", "data-layer": name,
    onmouseenter: () => highlight(name), onmouseleave: () => highlight(null) },
    el("h4", {}, el("span", { class: `swatch ${name}` }), title),
    el("dl", { class: "facts" }, present.map(([term, value]) => [el("dt", { text: term }), el("dd", { text: String(value) })])));
}

function highlight(name) {
  for (const octet of document.querySelectorAll("#frame-detail .octet")) {
    octet.classList.toggle("dim", name !== null && !octet.classList.contains(name));
  }
}

function renderFrame() {
  const detail = $("#frame-detail");
  const frame = state.frame;
  if (!frame) return;
  const yes = (flag) => (flag ? "yes" : "no");
  const parts = [
    el("h3", { text: `${frame.direction === "tx" ? "Sent" : "Received"} at ${clockTime(frame.at)}` }),
    layer("link", "Data link", [
      ["Function", frame.link.function],
      ["From", frame.link.source],
      ["To", frame.link.destination],
      ["Sent by a master", yes(frame.link.from_master)],
      ["Primary", yes(frame.link.primary)],
      ["User data", `${frame.link.user_data} octets`],
    ]),
  ];
  if (frame.transport) {
    parts.push(layer("transport", "Transport", [
      ["First segment", yes(frame.transport.fir)],
      ["Final segment", yes(frame.transport.fin)],
      ["Sequence", frame.transport.sequence],
      ["Problem", frame.transport.problem],
    ]));
  }
  if (frame.application) {
    const application = frame.application;
    parts.push(layer("application", "Application", [
      ["Function", application.function],
      ["Sequence", application.sequence],
      ["First fragment", yes(application.fir)],
      ["Final fragment", yes(application.fin)],
      ["Asks for confirmation", yes(application.con)],
      ["Unsolicited", yes(application.uns)],
      ["Indications", application.iin ? (application.iin.join(", ") || "none set") : undefined],
      ["Objects", (application.objects || []).join(", ") || undefined],
      ["Fragment", `${application.octets} octets`],
      ["Problem", application.problem],
    ]));
  }
  const layers = octetLayers(frame.octets);
  const hex = el("p", { class: "hex" });
  for (let position = 0; position < layers.length; position += 1) {
    hex.append(el("span", { class: `octet ${layers[position]}`, text: frame.octets.slice(position * 2, position * 2 + 2).toUpperCase() }));
  }
  parts.push(el("div", { class: "layer" },
    el("h4", {}, "Octets ", el("span", { class: "hint", text: "point at a layer to pick out its octets; checksums are unshaded" })), hex));
  detail.replaceChildren(...parts);
}

// ---------------------------------------------------------------- commands

function renderResult(exchange) {
  $("#result-card").hidden = false;
  const result = $("#result");
  const rows = exchange.objects.filter((object) => object.type !== null).slice(0, 200);
  const named = rows.some((row) => row.name);
  result.replaceChildren(
    el("dl", { class: "facts" },
      el("dt", { text: "Request" }), el("dd", {}, exchange.function, " ", el("span", { class: "hint", text: `sequence ${exchange.sequence}` })),
      el("dt", { text: "Outcome" }), el("dd", {}, el("span", { class: `outcome ${exchange.outcome}`, text: exchange.outcome })),
      el("dt", { text: "Fragments" }), el("dd", { text: exchange.fragments }),
      el("dt", { text: "Objects" }), el("dd", { text: exchange.object_count }),
      el("dt", { text: "Indications" }), el("dd", { text: exchange.indications === null ? "No response" : (exchange.indications.join(", ") || "none set") }),
      el("dt", { text: "Took" }), el("dd", { text: `${exchange.elapsed_ms} ms` }),
      exchange.undecoded.length ? [el("dt", { text: "Not read" }), el("dd", { class: "error", text: exchange.undecoded.map((item) => item.problem).join("; ") })] : null),
    rows.length ? el("div", { class: "table-wrap", style: "margin-top:12px; max-height:320px" },
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", { text: "Type" }), el("th", { class: "num", text: "Index" }), named && el("th", { text: "Name" }),
          el("th", { class: "num", text: "Value" }), el("th", { text: "Flags" }), el("th", { text: "Object" }))),
        el("tbody", {}, rows.map((row) => el("tr", {},
          el("td", { text: TYPE_LABELS[row.type] }),
          el("td", { class: "num", text: row.index }),
          named && el("td", { class: "name" }, nameNodes(row.type, row.index, row.name)),
          el("td", { class: "num value", text: formatValue(row.value) }),
          el("td", {}, flagChips(row.flags)),
          el("td", { class: "mono", text: `g${row.group}v${row.variation}${row.event ? " event" : ""}` })))))) : null);
}

// What came of an operate: whether the outstation accepted it, and what it
// said about each control. "Not known" is its own answer and is not shown as
// a refusal: the output may have been operated.
function renderOperated(operated) {
  $("#result-card").hidden = false;
  let verdict = ["unknown", "Not known"];
  let detail = "The outstation did not say. The output may have been operated, and nothing was sent again.";
  if (operated.accepted === true) {
    verdict = ["accepted", "Accepted"];
    detail = "";
  } else if (operated.accepted === false) {
    verdict = ["refused", operated.operated ? "Refused" : "Not operated"];
    detail = operated.operated ? "" : "The select was not accepted, so no operate was sent.";
  }
  const named = operated.statuses.some((status) => status.name);
  $("#result").replaceChildren(
    el("dl", { class: "facts" },
      el("dt", { text: "Outcome" }), el("dd", {}, el("span", { class: `verdict ${verdict[0]}`, text: verdict[1] }), detail && el("span", { class: "hint", text: ` ${detail}` })),
      el("dt", { text: "Requests" }), el("dd", {}, operated.exchanges.map((exchange, position) => [
        position ? ", then " : "",
        exchange.function, " ", el("span", { class: `outcome ${exchange.outcome}`, text: exchange.outcome })])),
      el("dt", { text: "Indications" }), el("dd", { text: (operated.exchanges.at(-1).indications || []).join(", ") || "none set" }),
      el("dt", { text: "Took" }), el("dd", { text: `${operated.exchanges.reduce((sum, exchange) => sum + exchange.elapsed_ms, 0).toFixed(1)} ms` })),
    el("div", { class: "table-wrap", style: "margin-top:12px" },
      el("table", { id: "operated-table" },
        el("thead", {}, el("tr", {},
          el("th", { text: "Output" }), el("th", { class: "num", text: "Index" }), named && el("th", { text: "Name" }),
          el("th", { class: "num", text: "Sent" }), el("th", { text: "Status" }), el("th", { text: "Echoed as sent" }))),
        el("tbody", {}, operated.statuses.map((status) => el("tr", {},
          el("td", { text: status.type === "bo" ? "Binary output" : "Analog output" }),
          el("td", { class: "num", text: status.index }),
          named && el("td", { class: "name" }, nameNodes(status.type, status.index, status.name)),
          el("td", { class: "num value", text: status.type === "bo" ? (OPERATIONS[status.value] || `code ${status.value}`) : formatValue(status.value) }),
          el("td", {}, el("span", { class: `verdict ${status.status === "SUCCESS" ? "accepted" : "refused"}`, text: status.status === null ? "no answer" : status.status })),
          el("td", { text: status.status === null ? "" : (status.echoed ? "Yes" : "No") })))))));
}

async function operate(type, index, value, mode, variation, readback) {
  const sent = type === "bo" ? value.replace("_", " ") : value;
  const label = `operate ${type === "bo" ? "binary" : "analog"} output ${index} (${sent}), ${mode.replace(/_/g, " ")}`;
  const params = { points: { [type]: { [index]: value } }, mode };
  if (variation) params.variation = Number(variation);
  try {
    const operated = await ask(label, "operate", params);
    renderOperated(operated);
    // The status of an output is not part of any scan by class, so it is
    // asked for here, where a person expects to see what the output now is.
    if (readback && operated.operated) await ask(`read back ${type === "bo" ? "binary" : "analog"} output ${index}`, "read", { points: { [type]: [index] } });
  } catch (error) {
    $("#result-card").hidden = false;
    $("#result").replaceChildren(el("p", { class: "error", text: error.message }));
  }
  refreshStatus();
}

async function command(label, op, params) {
  try {
    renderResult(await ask(label, op, params));
  } catch (error) {
    $("#result-card").hidden = false;
    $("#result").replaceChildren(el("p", { class: "error", text: error.message }));
  }
  refreshStatus();
}

// --------------------------------------------------------------------- log

function renderLog() {
  const list = $("#log");
  list.replaceChildren();
  for (const entry of state.log) {
    list.append(el("li", {}, el("time", { text: clockTime(entry.at) }), el("span", { class: entry.bad ? "bad" : "", text: entry.text })));
  }
}

// ------------------------------------------------------------------- tabs

function renderAll() {
  renderHeader();
  renderEvents();
  renderTraffic();
  if (state.tab === "overview") renderOverview();
  if (state.tab === "points") renderPoints();
  if (state.tab === "log") renderLog();
  if (state.tab === "traffic") renderFrame();
}

const TABS = ["overview", "points", "commands", "events", "traffic", "log"];

function showTab(name) {
  state.tab = name;
  history.replaceState(null, "", `#${name}`);
  for (const tab of document.querySelectorAll(".tabs [role='tab']")) {
    tab.setAttribute("aria-selected", String(tab.dataset.tab === name));
  }
  for (const panel of document.querySelectorAll(".panel")) {
    panel.hidden = panel.dataset.panel !== name;
  }
  renderAll();
}

// ----------------------------------------------------------------- events

let pending = false;
function scheduleRender() {
  if (pending) return;
  pending = true;
  requestAnimationFrame(() => {
    pending = false;
    renderEvents();
    renderTraffic();
    if (state.tab === "points") renderPoints();
  });
}

function onServiceEvent(event) {
  if (event.event === "outstations" || event.event === "connection") {
    if (event.event === "connection") {
      note(`${event.outstation}: ${event.connected ? "connected" : "connection ended"}`, !event.connected);
    }
    refreshStatus();
    return;
  }
  if (event.outstation !== state.selected) return;
  if (event.event === "frame") {
    if ($("#traffic-pause").checked) return;
    state.frames.push(event.frame);
    if (state.frames.length > KEPT_FRAMES) state.frames.splice(0, state.frames.length - KEPT_FRAMES);
  } else if (event.event === "exchange") {
    applyObjects(event.exchange.objects, false);
    if (event.exchange.outcome !== "complete") {
      note(`${event.outstation}: ${event.exchange.function} ended as ${event.exchange.outcome}`, true);
    } else if (event.exchange.task) {
      // Nobody asked for this one, so it is said that it was done.
      note(`${event.outstation}: ${TASK_REQUESTS[event.exchange.task] || event.exchange.task}, unasked`);
    }
  } else if (event.event === "unsolicited") {
    applyObjects(event.objects, true);
    note(`${event.outstation}: unsolicited response with ${event.objects.length} object(s)`);
  }
  scheduleRender();
}

function listen() {
  const chip = $("#service-state");
  const source = new EventSource(TOKEN ? `events?token=${encodeURIComponent(TOKEN)}` : "events");
  source.onopen = () => { chip.textContent = "Service running"; chip.className = "chip good"; refreshStatus(); };
  source.onerror = () => { chip.textContent = "Service unreachable"; chip.className = "chip bad"; };
  source.onmessage = (message) => onServiceEvent(JSON.parse(message.data));
}

// ------------------------------------------------------------------ wiring

function wire() {
  for (const tab of document.querySelectorAll(".tabs [role='tab']")) {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
  }

  $("#add-form").addEventListener("submit", async (submitted) => {
    submitted.preventDefault();
    const form = submitted.target;
    const params = {};
    for (const [key, value] of new FormData(form)) {
      if (value.trim() === "") continue;
      if (key === "manual") params.manual = true;
      else if (key === "unsolicited") params.tasks = { enable_unsolicited: value.split(",").map(Number) };
      else params[key] = ["name", "host"].includes(key) ? value : Number(value);
    }
    $("#add-error").textContent = "";
    try {
      await api("add", params);
      note(`${params.name}: added`);
      $("#add-panel").open = false;
      form.elements.name.value = "";
    } catch (error) {
      $("#add-error").textContent = error.message;
      note(`${params.name}: ${error.message}`, true);
    }
    await refreshStatus();
    if (state.outstations.some((outstation) => outstation.name === params.name)) await select(params.name);
  });

  $("#connect-button").addEventListener("click", async () => {
    const outstation = current();
    if (!outstation) return;
    try {
      await ask(outstation.connected ? "disconnected" : "connected", outstation.connected ? "disconnect" : "connect");
    } catch (error) { /* already in the log */ }
    refreshStatus();
  });

  $("#remove-button").addEventListener("click", async () => {
    try { await ask("removed", "remove"); } catch (error) { /* already in the log */ }
    state.selected = null;
    select(null);
    refreshStatus();
  });

  for (const button of document.querySelectorAll("#scan-buttons [data-scan]")) {
    button.addEventListener("click", () => command(button.textContent, "scan", { kind: button.dataset.scan }));
  }

  $("#repeat-form").addEventListener("submit", async (submitted) => {
    submitted.preventDefault();
    const form = submitted.target;
    for (const kind of ["integrity", "events", "outputs"]) {
      const value = form.elements[kind].value;
      try {
        await ask(value === "" ? `${kind} scan no longer repeated` : `${kind} scan every ${value} s`,
          "repeat", { kind, interval: value === "" ? null : Number(value) });
      } catch (error) { /* already in the log */ }
    }
    refreshStatus();
  });

  $("#read-form").addEventListener("submit", (submitted) => {
    submitted.preventDefault();
    const form = submitted.target;
    const typed = form.elements.indices.value.trim();
    const indices = typed === "" || typed.toLowerCase() === "all"
      ? "all"
      : typed.split(/[\s,]+/).filter(Boolean).map(Number);
    const type = form.elements.type.value;
    command(`read ${TYPE_LABELS[type].toLowerCase()}`, "read", { points: { [type]: indices } });
  });

  $("#operate-form").elements.type.addEventListener("change", showOperateFields);
  showOperateFields();
  $("#operate-form").addEventListener("submit", (submitted) => {
    submitted.preventDefault();
    const fields = submitted.target.elements;
    const type = fields.type.value;
    operate(
      type,
      Number(fields.index.value),
      type === "bo" ? fields.operation.value : Number(fields.value.value),
      fields.mode.value,
      type === "ao" ? fields.variation.value : "",
      fields.readback.checked,
    );
  });

  const writes = {
    write_time: ["write the time", "write_time", {}],
    clear_restart: ["clear the restart indication", "clear_restart", {}],
    freeze: ["freeze counters", "freeze", { clear: false }],
    freeze_clear: ["freeze and clear counters", "freeze", { clear: true }],
  };
  for (const button of document.querySelectorAll("#write-buttons button")) {
    button.addEventListener("click", () => command(...writes[button.dataset.write]));
  }

  $("#unsolicited-form").addEventListener("submit", (submitted) => {
    submitted.preventDefault();
    const classes = [...submitted.target.querySelectorAll("[name='class']:checked")].map((box) => Number(box.value));
    const action = submitted.submitter.value;
    command(`${action === "enable_unsolicited" ? "enable" : "disable"} unsolicited for class ${classes.join(", ")}`, action, { classes });
  });

  $("#raw-form").addEventListener("submit", (submitted) => {
    submitted.preventDefault();
    const form = submitted.target;
    command(`${form.elements.function.value} request`, "request", {
      function: form.elements.function.value,
      body: form.elements.body.value.replace(/\s+/g, ""),
    });
  });

  $("#point-filter").addEventListener("input", renderPoints);
  $("#point-changed").addEventListener("change", renderPoints);
  $("#point-unreported").addEventListener("change", renderPoints);

  for (const button of document.querySelectorAll("#traffic-direction button")) {
    button.addEventListener("click", () => {
      for (const other of document.querySelectorAll("#traffic-direction button")) {
        other.setAttribute("aria-pressed", String(other === button));
      }
      renderTraffic();
    });
  }
  $("#traffic-application").addEventListener("change", renderTraffic);
  $("#traffic-clear").addEventListener("click", async () => {
    try { await ask("traffic cleared", "clear", { what: "trace" }); } catch (error) { return; }
    state.frames = [];
    state.frame = null;
    $("#frame-detail").replaceChildren(el("p", { class: "hint", text: "Select a frame to read it layer by layer." }));
    renderTraffic();
  });
  $("#events-clear").addEventListener("click", async () => {
    try { await ask("events cleared", "clear", { what: "events" }); } catch (error) { return; }
    state.events = [];
    renderEvents();
  });
  $("#log-clear").addEventListener("click", () => { state.log = []; renderLog(); });
}

document.body.append(tip);
document.addEventListener("scroll", followTip, true);
wire();
if (TABS.includes(location.hash.slice(1))) showTab(location.hash.slice(1));
listen();
refreshStatus().catch((error) => note(error.message, true));
setInterval(() => refreshStatus().catch(() => {}), 2000);
setInterval(() => { if (state.tab === "points") tickAges(); }, 1000);
