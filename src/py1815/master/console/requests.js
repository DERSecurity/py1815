// The Requests tab of the Satori DNP3 master console.
//
// Requests the reader saved, each a function code by name and its object
// headers in hexadecimal, to send once or to repeat. The list is the reader's
// own and is kept in this browser: it is not the master's state or the
// outstation's. Like the rest of the console the tab holds no logic. It
// builds no octets and reads no response: it sends what was typed to the
// service's request operation and shows the exchange that came back.
//
// It is loaded before console.js and declares only: what it uses of that
// script, it uses once the page is running.

"use strict";

// Where the list is kept. The key carries the address the console was opened
// at, so two consoles reached through one host keep a list each.
const REQUESTS_KEY = `py1815-master.requests:${location.origin}${location.pathname}`;
const REQUESTS_KEPT = 100;

// Seconds between the sends of a repeated request: what a new request starts
// with, and the least the page takes.
const REPEAT_SECONDS = 5;
const REPEAT_LEAST = 0.2;

// The list a browser starts with.
const STARTING_REQUESTS = [
  { name: "Integrity poll", function: "READ", body: "3C 02 06 3C 03 06 3C 04 06 3C 01 06" },
  { name: "Event poll (Class 1, 2, 3)", function: "READ", body: "3C 02 06 3C 03 06 3C 04 06" },
  { name: "Class 0", function: "READ", body: "3C 01 06" },
  { name: "Binary inputs, all", function: "READ", body: "01 00 06" },
];

const saved = {
  requests: null,       // the list, read from the browser when first needed
  editing: null,        // the id of the request the form is changing
  outstation: null,     // the outstation the results shown are of
  repeats: new Map(),   // request id -> the repeat under way
  last: new Map(),      // request id -> how its last send ended
};

// ----------------------------------------------------------------- storage

function requestEntry(given) {
  const interval = Number(given.interval);
  return {
    id: typeof given.id === "string" && given.id ? given.id : crypto.randomUUID(),
    name: String(given.name),
    function: String(given.function),
    body: String(given.body ?? ""),
    interval: interval >= REPEAT_LEAST ? interval : REPEAT_SECONDS,
  };
}

// The saved list. A browser that has kept none, or has kept something that
// is not a list of requests, starts with the starting list.
function requestsRead() {
  if (saved.requests) return saved.requests;
  let kept = null;
  try {
    kept = JSON.parse(localStorage.getItem(REQUESTS_KEY));
  } catch (error) {
    kept = null;
  }
  const usable = Array.isArray(kept) && kept.every((entry) => entry && typeof entry === "object"
    && typeof entry.name === "string" && typeof entry.function === "string");
  saved.requests = (usable ? kept : STARTING_REQUESTS).slice(0, REQUESTS_KEPT).map(requestEntry);
  return saved.requests;
}

function requestsWrite() {
  try {
    localStorage.setItem(REQUESTS_KEY, JSON.stringify(saved.requests));
  } catch (error) {
    note(`The saved requests could not be kept in this browser: ${error.message}`, true);
  }
}

// ------------------------------------------------------------------ render

function requestLastNodes(id) {
  const last = saved.last.get(id);
  const repeat = saved.repeats.get(id);
  if (!last) return repeat ? [el("span", { class: "hint", text: "Sending" })] : [];
  const count = repeat ? `, sent ${repeat.sent} time(s)` : "";
  return [
    last.error
      ? el("span", { class: "outcome failed", text: "failed" })
      : el("span", { class: `outcome ${last.outcome}`, text: last.outcome }),
    el("span", { class: "hint", text: ` at ${clockTime(last.at)}${count}` }),
    last.stopped ? el("span", { class: "hint request-stopped", text: " The repeat stopped." }) : null,
  ];
}

function requestRepeatNodes(request) {
  const repeat = saved.repeats.get(request.id);
  if (repeat) {
    return [
      el("span", { class: "request-repeating", text: `Every ${repeat.interval} s` }),
      el("button", { class: "quiet", "data-action": "stop", text: "Stop", "aria-label": `Stop repeating ${request.name}`, onclick: () => requestStop(request.id) }),
    ];
  }
  return [
    el("label", {}, "Every",
      el("input", {
        type: "number",
        min: REPEAT_LEAST,
        step: "any",
        value: request.interval,
        "aria-label": `Seconds between sends of ${request.name}`,
        onchange: (event) => requestInterval(request, event.target),
      }), "s"),
    el("button", { class: "quiet", "data-action": "repeat", text: "Repeat", "aria-label": `Repeat ${request.name}`, onclick: () => requestRepeat(request) }),
  ];
}

function renderRequests() {
  const requests = requestsRead();
  const body = $("#requests-table tbody");
  body.replaceChildren(...requests.map((request) => el("tr", { "data-request": request.id },
    el("td", { class: "name", text: request.name }),
    el("td", { class: "mono", text: request.function }),
    el("td", { class: "mono request-body" }, request.body || el("span", { class: "hint", text: "none" })),
    el("td", { class: "request-repeat" }, el("div", { class: "inline" }, requestRepeatNodes(request))),
    el("td", { class: "request-last" }, requestLastNodes(request.id)),
    el("td", { class: "act request-act" },
      el("button", { "data-action": "send", text: "Send", "aria-label": `Send ${request.name}`, onclick: () => requestSend(request) }),
      el("button", { class: "quiet", "data-action": "edit", text: "Edit", "aria-label": `Edit ${request.name}`, onclick: () => requestEdit(request) }),
      el("button", { class: "quiet", "data-action": "remove", text: "Remove", "aria-label": `Remove ${request.name}`, onclick: () => requestRemove(request) })))));
  if (!requests.length) {
    body.append(el("tr", {}, el("td", { colspan: "6", class: "hint", text: "None saved. Add one below." })));
  }
}

// Only the cell that says how the last send ended is drawn again after a
// send, so a repeat does not disturb a field somebody is typing in.
function requestLast(id) {
  const row = [...document.querySelectorAll("#requests-table tbody tr")].find((each) => each.dataset.request === id);
  if (row) row.querySelector(".request-last").replaceChildren(...requestLastNodes(id).filter(Boolean));
}

function requestShow(request, shown) {
  $("#request-result-card").hidden = false;
  $("#request-result-of").textContent = `of ${request.name}, at ${clockTime(shown.at)}`;
  $("#request-result").replaceChildren(...(shown.error
    ? [el("p", { class: "error", text: shown.error })]
    : exchangeNodes(shown.exchange)));
}

// ----------------------------------------------------------------- sending

// Send one saved request to the selected outstation and show what came of
// it. Returns whether the outstation answered it, or it needed no answer:
// a repeat goes on only then.
async function requestSend(request) {
  const name = state.selected;
  const shown = { at: Date.now() / 1000 };
  try {
    shown.exchange = await ask(`request "${request.name}" (${request.function})`, "request",
      { function: request.function, body: request.body.replace(/\s+/g, "") });
  } catch (error) {
    shown.error = error.message;
  }
  if (state.selected !== name) return false;
  const answered = !shown.error && ["complete", "sent"].includes(shown.exchange.outcome);
  saved.last.set(request.id, { at: shown.at, error: shown.error, outcome: shown.exchange?.outcome, stopped: false });
  requestShow(request, shown);
  requestLast(request.id);
  refreshStatus();
  return answered;
}

function requestInterval(request, field) {
  const seconds = Number(field.value);
  if (!(seconds >= REPEAT_LEAST)) return;
  request.interval = seconds;
  requestsWrite();
}

// Send a request now and then again every interval, from this page's own
// timer. A send that is refused, fails or is not answered ends the repeat.
function requestRepeat(request) {
  const error = $("#request-error");
  error.textContent = "";
  const field = [...document.querySelectorAll("#requests-table tbody tr")]
    .find((each) => each.dataset.request === request.id).querySelector("input[type='number']");
  const seconds = Number(field.value);
  if (!(seconds >= REPEAT_LEAST)) {
    error.textContent = `A request is repeated every ${REPEAT_LEAST} s or more.`;
    return;
  }
  request.interval = seconds;
  requestsWrite();
  const repeat = { interval: seconds, sent: 0, busy: false, timer: null };
  const send = async () => {
    // The send before this one has not ended: its turn is skipped.
    if (repeat.busy) return;
    repeat.busy = true;
    const answered = await requestSend(request);
    repeat.busy = false;
    if (saved.repeats.get(request.id) !== repeat) return;
    repeat.sent += 1;
    if (answered) requestLast(request.id);
    else requestStop(request.id, true);
  };
  repeat.timer = setInterval(send, seconds * 1000);
  saved.repeats.set(request.id, repeat);
  renderRequests();
  send();
}

// End a repeat. One the page ended itself, because a send was not answered,
// says so beside the request.
function requestStop(id, unanswered = false) {
  const repeat = saved.repeats.get(id);
  if (!repeat) return;
  clearInterval(repeat.timer);
  saved.repeats.delete(id);
  const last = saved.last.get(id);
  if (last) last.stopped = unanswered;
  renderRequests();
}

// A repeat is of one outstation. Selecting another ends every repeat, and
// puts away the results, which were the other outstation's.
function requestsSelected(name) {
  if (name === saved.outstation) return;
  saved.outstation = name;
  for (const id of [...saved.repeats.keys()]) requestStop(id);
  saved.last.clear();
  $("#request-result-card").hidden = true;
  renderRequests();
}

// ----------------------------------------------------------------- editing

function requestForm(request) {
  const form = $("#request-form");
  saved.editing = request ? request.id : null;
  form.elements.name.value = request ? request.name : "";
  form.elements.function.value = request ? request.function : "";
  form.elements.body.value = request ? request.body : "";
  $("#request-form-title").textContent = request ? "Change a request" : "Add a request";
  $("#request-save").textContent = request ? "Save" : "Add";
  $("#request-cancel").hidden = !request;
  $("#request-error").textContent = "";
}

function requestEdit(request) {
  requestForm(request);
  $("#request-form").elements.name.focus();
}

function requestRemove(request) {
  requestStop(request.id);
  saved.requests = requestsRead().filter((each) => each.id !== request.id);
  saved.last.delete(request.id);
  if (saved.editing === request.id) requestForm(null);
  requestsWrite();
  renderRequests();
}

function requestSubmit(submitted) {
  submitted.preventDefault();
  const fields = submitted.target.elements;
  const typed = {
    name: fields.name.value.trim(),
    function: fields.function.value.trim(),
    body: fields.body.value.trim(),
  };
  const requests = requestsRead();
  const editing = requests.find((each) => each.id === saved.editing);
  if (editing) {
    // The request as it was may be going out on a timer: that ends here.
    requestStop(editing.id);
    Object.assign(editing, typed);
    saved.last.delete(editing.id);
  } else if (requests.length >= REQUESTS_KEPT) {
    $("#request-error").textContent = `The page keeps ${REQUESTS_KEPT} requests. Remove one to add another.`;
    return;
  } else {
    requests.push(requestEntry(typed));
  }
  requestsWrite();
  requestForm(null);
  renderRequests();
}

function wireRequests() {
  $("#request-form").addEventListener("submit", requestSubmit);
  $("#request-cancel").addEventListener("click", () => requestForm(null));
}
