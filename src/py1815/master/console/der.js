// The DER tab of the Satori DNP3 master console.
//
// An IEEE 1815.2 DER as its profile names it: the nameplate, what it is
// measuring, each function with its settings and an enable switch, the curve
// the curve block shows, and what it serves against its Device Profile
// document. Like the rest of the console it holds no logic: it asks the
// service's der.* operations and shows what comes back. Scaling, the order a
// curve is written in, and whether a readback matches are the service's.
//
// It is loaded before console.js and declares only: what it uses of that
// script, it uses once the page is running.

"use strict";

const der = {
  outstation: null,   // the outstation the tab was last loaded for
  loading: false,
  nameplate: null,    // a der.read result, or an error message
  monitoring: null,
  functions: null,    // a der.functions result, or an error message
  settings: {},       // function key -> der.read result of its group
  open: new Set(),    // the functions whose settings are shown
  written: {},        // function key -> what came of the last write
  curve: null,        // a der.curve result, or an error message
  comparison: null,   // a der.compare result, or an error message
};

function derReset(name) {
  der.outstation = name;
  der.nameplate = der.monitoring = der.functions = der.curve = der.comparison = null;
  der.settings = {};
  der.open = new Set();
  der.written = {};
}

async function derAsk(label, op, params = {}) {
  try {
    return await ask(label, op, params);
  } catch (error) {
    return { error: error.message };
  }
}

// Everything the tab shows, read again: each a read, and nothing written.
async function derLoad() {
  const name = state.selected;
  der.loading = true;
  renderDer();
  const [nameplate, monitoring, functions, curve] = await Promise.all([
    derAsk("read the nameplate", "der.read", { group: "nameplate" }),
    derAsk("read what the DER is measuring", "der.read", { group: "monitoring" }),
    derAsk("read which functions are supported", "der.functions"),
    derAsk("read the curve block", "der.curve"),
  ]);
  if (state.selected !== name) return;
  Object.assign(der, { nameplate, monitoring, functions, curve, loading: false });
  for (const key of der.open) await derReadFunction(key);
  renderDer();
}

async function derReadFunction(key) {
  der.settings[key] = await derAsk(`read the ${key} function`, "der.read", { group: key });
}

// ------------------------------------------------------------------ pieces

function derValue(reading) {
  if (!reading || reading.quality === "not_reported") return "";
  if (reading.state) return reading.state;
  const text = formatValue(reading.value);
  return reading.units && typeof reading.value === "number" ? `${text} ${reading.units}` : text;
}

function derQuality(reading) {
  if (reading.quality === "good") return el("span", { class: "flag ONLINE", text: "ONLINE" });
  if (reading.quality === "not_reported") return el("span", { class: "flag none", text: "NOT REPORTED" });
  const titles = { offline: "Sent without ONLINE: a disabled function's value is not in effect" };
  return el("span", { class: "flag alarm", text: reading.quality.replace("_", " ").toUpperCase(), title: titles[reading.quality] || "" });
}

function derReadings(result, empty) {
  if (!result) return el("p", { class: "hint", text: der.loading ? "Reading…" : "" });
  if (result.error) return el("p", { class: "hint", text: result.error.includes("no function or group") ? empty : result.error });
  return el("div", { class: "table-wrap der-table" },
    el("table", {},
      el("thead", {}, el("tr", {},
        el("th", { class: "w-address", text: "Point" }), el("th", { text: "Name" }),
        el("th", { class: "num", text: "Value" }), el("th", { class: "w-quality", text: "Quality" }))),
      el("tbody", {}, result.points.map((reading) => el("tr", { "data-address": reading.address },
        el("td", { class: "mono", text: reading.address }),
        el("td", { class: "name", text: reading.label, title: reading.name }),
        el("td", { class: "num value", text: derValue(reading) }),
        el("td", {}, derQuality(reading)))))));
}

// --------------------------------------------------------------- functions

function derFunctionRow(fn) {
  const shown = der.open.has(fn.key);
  const toggle = el("input", {
    type: "checkbox",
    role: "switch",
    "data-function": fn.key,
    checked: fn.enabled === true,
    disabled: !state.allowControl || fn.enabled === null,
    "aria-label": `Enable ${fn.name}`,
    onchange: (event) => derSwitch(fn, event.target.checked),
  });
  const said = fn.enabled === null ? "Not reported" : (fn.enabled ? "Enabled" : "Disabled");
  return el("div", { class: "der-function", "data-key": fn.key },
    el("div", { class: "der-function-head" },
      el("label", { class: "check switch", title: state.allowControl ? "" : "Commanding is off" }, toggle,
        el("span", { class: `der-state ${fn.enabled ? "on" : ""}`, text: said })),
      el("span", { class: "der-function-name", text: fn.name }),
      el("span", { class: "hint mono", text: fn.enable }),
      el("div", { class: "spacer" }),
      el("button", { class: "quiet", text: shown ? "Hide settings" : "Settings", onclick: () => derToggle(fn.key) })),
    shown ? derSettings(fn) : null);
}

function derSettings(fn) {
  const result = der.settings[fn.key];
  const written = der.written[fn.key];
  const settable = fn.settings.filter((setting) => setting.type === "ao" || setting.type === "bo");
  const form = el("form", { class: "inline der-write", "data-function": fn.key, onsubmit: (event) => derWrite(event, fn) },
    el("fieldset", { class: "inline", disabled: !state.allowControl },
      el("label", {}, "Setting",
        el("select", { name: "point" }, settable.map((setting) => el("option", { value: setting.address },
          `${setting.label}${setting.units ? ` (${setting.units})` : ""}`)))),
      el("label", {}, "Value", el("input", { name: "value", required: true, class: "der-value" })),
      el("label", { class: "check" }, el("input", { type: "checkbox", name: "verify", checked: true }), "Read back and compare"),
      el("button", { type: "submit", class: "primary", text: "Write" })));
  return el("div", { class: "der-settings" },
    derReadings(result, "Nothing to read"),
    settable.length ? form : null,
    written ? derWritten(written) : null);
}

function derWritten(written) {
  if (written.error) return el("p", { class: "error", text: written.error });
  const verdict = written.accepted === true ? ["accepted", "Accepted"]
    : written.accepted === false ? ["refused", "Refused"] : ["unknown", "Not known"];
  return el("div", { class: "der-written" },
    el("span", { class: `verdict ${verdict[0]}`, text: verdict[1] }),
    written.points.map((point) => el("span", { class: "hint" },
      ` ${point.address}: sent ${formatValue(point.sent)} for ${formatValue(point.requested)}`,
      point.status && point.status !== "SUCCESS" ? `, ${point.status}` : "",
      point.matches === true ? ", read back the same" : "",
      point.matches === false ? `, read back ${derValue(point.readback) || "nothing"}` : "")));
}

async function derToggle(key) {
  if (der.open.has(key)) {
    der.open.delete(key);
  } else {
    der.open.add(key);
    renderDer();
    await derReadFunction(key);
  }
  renderDer();
}

async function derSwitch(fn, on) {
  const switched = await derAsk(`${on ? "enable" : "disable"} ${fn.name}`, on ? "der.enable" : "der.disable", { function: fn.key });
  if (switched.error) der.written[fn.key] = switched;
  der.functions = await derAsk("read which functions are supported", "der.functions");
  if (der.open.has(fn.key)) await derReadFunction(fn.key);
  renderDer();
}

async function derWrite(event, fn) {
  event.preventDefault();
  const fields = event.target.elements;
  const setting = fn.settings.find((each) => each.address === fields.point.value);
  const typed = fields.value.value.trim();
  const states = { true: true, on: true, 1: true, false: false, off: false, 0: false };
  const lower = typed.toLowerCase();
  // A binary setting takes true or false, or a state by the name the tables give it.
  const value = setting.type === "bo" ? (lower in states ? states[lower] : typed) : Number(typed);
  der.written[fn.key] = await derAsk(`write ${setting.address} (${typed})`, "der.write",
    { points: { [setting.address]: value }, verify: fields.verify.checked });
  await derReadFunction(fn.key);
  renderDer();
}

function derFunctions() {
  const result = der.functions;
  if (!result) return el("p", { class: "hint", text: der.loading ? "Reading…" : "" });
  if (result.error) return el("p", { class: "hint", text: result.error });
  const supported = result.functions.filter((fn) => fn.supported);
  const other = result.functions.filter((fn) => !fn.supported);
  return [
    state.allowControl ? null : el("p", { class: "hint", text: "Commanding is off: the switches and settings are shown, and cannot be changed. Start the console with --allow-control to change them." }),
    supported.length ? supported.map(derFunctionRow) : el("p", { class: "hint", text: "The outstation reports no function as supported." }),
    other.length ? el("p", { class: "hint der-unsupported" }, "Not supported: ", other.map((fn) => fn.name).join(", ")) : null,
  ];
}

// ------------------------------------------------------------------ curves

// The curve as a line through its points, in the numbers that travelled.
function derPlot(points) {
  const width = 360;
  const height = 200;
  const pad = 34;
  const xs = points.map((point) => point[0]);
  const ys = points.map((point) => point[1]).concat([0]);
  const [x0, x1] = [Math.min(...xs), Math.max(...xs)];
  const [y0, y1] = [Math.min(...ys), Math.max(...ys)];
  const sx = (x) => pad + (x1 === x0 ? (width - 2 * pad) / 2 : ((x - x0) / (x1 - x0)) * (width - 2 * pad));
  const sy = (y) => height - pad - (y1 === y0 ? (height - 2 * pad) / 2 : ((y - y0) / (y1 - y0)) * (height - 2 * pad));
  const ns = "http://www.w3.org/2000/svg";
  const make = (tag, attributes, text) => {
    const node = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const svg = make("svg", { viewBox: `0 0 ${width} ${height}`, class: "der-plot", role: "img", "aria-label": "The curve" });
  svg.append(
    make("line", { x1: pad, y1: sy(0), x2: width - pad, y2: sy(0), class: "axis" }),
    make("line", { x1: pad, y1: pad / 2, x2: pad, y2: height - pad, class: "axis" }),
    make("polyline", { points: points.map((point) => `${sx(point[0])},${sy(point[1])}`).join(" "), class: "line" }),
    ...points.map((point) => make("circle", { cx: sx(point[0]), cy: sy(point[1]), r: 3.5, class: "dot" })),
    make("text", { x: pad, y: height - pad + 16, class: "tick" }, formatValue(x0)),
    make("text", { x: width - pad, y: height - pad + 16, class: "tick end" }, formatValue(x1)),
    make("text", { x: pad - 6, y: sy(y1) + 4, class: "tick end" }, formatValue(y1)),
    make("text", { x: pad - 6, y: sy(y0) + 4, class: "tick end" }, formatValue(y0)));
  return svg;
}

function derCurve() {
  const result = der.curve;
  const form = el("form", { class: "inline", id: "der-curve-form", onsubmit: derShowCurve },
    el("fieldset", { class: "inline", disabled: !state.allowControl },
      el("label", {}, "Curve", el("input", { name: "number", type: "number", min: "1", step: "1", required: true })),
      el("button", { type: "submit", text: "Show" })),
    el("span", { class: "hint", text: state.allowControl ? "Showing another curve writes the selector." : "Showing another curve writes the selector, and commanding is off." }));
  if (!result) return [el("p", { class: "hint", text: der.loading ? "Reading…" : "" }), form];
  if (result.error) return [el("p", { class: "hint", text: result.error }), form];
  const curve = result.curve;
  const named = (number, name) => (number === null ? "not reported" : name ? `${number}: ${name}` : String(number));
  return [
    el("dl", { class: "facts" },
      el("dt", { text: "Curve" }), el("dd", { id: "der-curve-number", text: curve.number ?? "not reported" }),
      el("dt", { text: "Type" }), el("dd", { text: named(curve.type, curve.type_name) }),
      el("dt", { text: "X units" }), el("dd", { text: named(curve.x_units, curve.x_units_name) }),
      el("dt", { text: "Y units" }), el("dd", { text: named(curve.y_units, curve.y_units_name) }),
      el("dt", { text: "Named by a function" }), el("dd", { text: curve.referenced === null ? "not reported" : (curve.referenced ? "Yes" : "No") })),
    curve.points.length
      ? el("div", { class: "der-curve" },
        derPlot(curve.points),
        el("div", { class: "table-wrap" },
          el("table", { id: "der-curve-points" },
            el("thead", {}, el("tr", {}, el("th", { class: "num", text: "Point" }), el("th", { class: "num", text: "X" }), el("th", { class: "num", text: "Y" }))),
            el("tbody", {}, curve.points.map((point, position) => el("tr", {},
              el("td", { class: "num", text: position + 1 }),
              el("td", { class: "num value", text: formatValue(point[0]) }),
              el("td", { class: "num value", text: formatValue(point[1]) })))))))
      : el("p", { class: "hint", text: "This curve has no points." }),
    el("p", { class: "hint", text: "Values as they travel: the units the curve declares say how they scale." }),
    form,
  ];
}

async function derShowCurve(event) {
  event.preventDefault();
  const number = Number(event.target.elements.number.value);
  der.curve = await derAsk(`show curve ${number}`, "der.curve", { number });
  renderDer();
}

// -------------------------------------------------------------- comparison

async function derCompare(document) {
  const params = document === undefined ? {} : { document };
  der.comparison = await derAsk("compare with the Device Profile document", "der.compare", params);
  renderDer();
}

function derPointList(items, extra) {
  return el("div", { class: "table-wrap der-table" },
    el("table", {},
      el("thead", {}, el("tr", {}, el("th", { text: "Type" }), el("th", { class: "num", text: "Index" }), el("th", { text: "Name" }), extra ? el("th", { text: extra[0] }) : null)),
      el("tbody", {}, items.map((item) => el("tr", {},
        el("td", { text: TYPE_LABELS[item.type] || item.type }),
        el("td", { class: "num", text: item.index }),
        el("td", { class: "name", text: item.name || "" }),
        extra ? el("td", { text: extra[1](item) }) : null)))));
}

function derComparison() {
  const outstation = current();
  const offered = outstation && outstation.device_profile;
  const file = el("input", { type: "file", accept: ".xml,application/xml,text/xml", id: "der-compare-file",
    onchange: async (event) => {
      const chosen = event.target.files[0];
      if (chosen) await derCompare(await chosen.text());
    } });
  const controls = el("div", { class: "inline" },
    offered ? el("button", { id: "der-compare", text: "Compare with its Device Profile document", onclick: () => derCompare() }) : null,
    el("label", {}, offered ? "or with another document" : "Compare with a Device Profile document", file));
  const result = der.comparison;
  if (!result) return controls;
  if (result.error) return [controls, el("p", { class: "error", text: result.error })];
  const classes = ["none", "1", "2", "3"];
  return [
    controls,
    el("dl", { class: "facts der-summary" },
      el("dt", { text: "Declared" }), el("dd", { text: result.declared }),
      el("dt", { text: "Declared and served" }), el("dd", { text: result.served }),
      el("dt", { text: "Declared and absent" }), el("dd", { class: result.absent.length ? "bad" : "", text: result.absent.length }),
      el("dt", { text: "Served and undeclared" }), el("dd", { class: result.undeclared.length ? "bad" : "", text: result.undeclared.length }),
      el("dt", { text: "Class 0 not as declared" }), el("dd", { class: result.class_0.length ? "bad" : "", text: result.class_0.length })),
    result.absent.length ? [el("h4", { text: "Declared and absent" }), derPointList(result.absent)] : null,
    result.undeclared.length ? [el("h4", { text: "Served and undeclared" }), derPointList(result.undeclared)] : null,
    result.class_0.length ? [el("h4", { text: "Class 0 not as declared" }), derPointList(result.class_0,
      ["Class 0", (item) => (item.carried ? "carried, declared never" : "not carried, declared always")])] : null,
    el("details", { class: "der-declared" },
      el("summary", { text: "Class and deadband as declared" }),
      el("p", { class: "hint", text: "An outstation cannot be asked for a point's event class or deadband, so these are as the document declares them." }),
      derPointList(result.points, ["Class, deadband", (item) =>
        `${item.event_class === null ? "not stated" : classes[item.event_class]}${item.deadband === null ? "" : `, ${formatValue(item.deadband)}`}`])),
  ];
}

// ------------------------------------------------------------------ render

function renderDer() {
  const panel = $("#der-content");
  if (!panel || state.tab !== "der") return;
  if (der.outstation !== state.selected) {
    derReset(state.selected);
    if (state.selected) derLoad();
    return;
  }
  panel.replaceChildren(
    el("div", { class: "cards" },
      el("div", { class: "card", id: "der-nameplate" }, el("h3", { text: "Nameplate" }), derReadings(der.nameplate, "The profile names no nameplate points.")),
      el("div", { class: "card", id: "der-monitoring" }, el("h3", { text: "Monitoring" }), derReadings(der.monitoring, "The profile names no monitoring points."))),
    el("div", { class: "card spaced", id: "der-functions" }, el("h3", {}, "Functions ", el("span", { class: "hint", text: "as the outstation reports them" })), derFunctions()),
    el("div", { class: "card spaced", id: "der-curve" }, el("h3", {}, "Curve ", el("span", { class: "hint", text: "the one the curve block shows" })), derCurve()),
    el("div", { class: "card spaced", id: "der-comparison" }, el("h3", { text: "Device Profile document" }), derComparison()));
}

function wireDer() {
  $("#der-reload").addEventListener("click", () => { if (state.selected) derLoad(); });
}
