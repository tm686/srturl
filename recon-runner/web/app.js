/* recon-runner frontend — pure vanilla JS, no build step */
"use strict";

const API = "";  // same origin

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
    tools: {},
    activeProfile: "stealth",
    profileValues: {},
    targetType: "wildcard",
    running: false,
    activeTool: null,
    parsedCount: 0,
};

// ---------------------------------------------------------------------------
// DOM refs
// ---------------------------------------------------------------------------

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
    profileDisplay: $("#profile-display"),
    doctorStatus:   $("#doctor-status"),
    targetType:     $("#target-type"),
    target:         $("#target"),
    btnStart:       $("#btn-start"),
    btnStop:        $("#btn-stop"),
    profileSelect:  $("#profile-select"),
    toolButtons:    $("#tool-buttons"),
    outputPane:     $("#output-pane"),
    activeTool:     $("#active-tool"),
    activeRate:     $("#active-rate"),
    btnClear:       $("#btn-clear-output"),
    roiSection:     $("#roi-section"),
    findingsSection:$("#findings-section"),
    parsedCount:    $("#parsed-count"),
};

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function api(path, opts) {
    const res = await fetch(API + path, opts);
    return res.json();
}

async function apiPost(path, body) {
    return api(path, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body),
    });
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init() {
    await Promise.all([
        loadDoctor(),
        loadTools(),
        loadProfile(),
    ]);
    bindEvents();
    updateTargetTypeUI();
    connectSSE();
}

// ---------------------------------------------------------------------------
// SSE connection
// ---------------------------------------------------------------------------

let evtSource = null;

function connectSSE() {
    if (evtSource) evtSource.close();
    evtSource = new EventSource("/api/events");

    evtSource.addEventListener("tool_start", (e) => {
        const d = JSON.parse(e.data);
        state.running = true;
        state.activeTool = d.tool;
        state.parsedCount = 0;
        updateRunningUI();
        appendOutput(`\n[*] ${d.tool} started`, "output-info");
        appendOutput(`    cmd: ${d.cmd}`, "output-stderr");
        appendOutput(`    profile: ${d.profile} (rate:${d.values.rate} threads:${d.values.threads} delay:${d.values.delay}ms)`, "output-stderr");
    });

    evtSource.addEventListener("stdout", (e) => {
        const d = JSON.parse(e.data);
        if (d.type === "json") {
            state.parsedCount++;
            updateParsedCount();
            // Show summary or compact JSON
            if (d.summary) {
                appendOutput(`  ${d.summary}`, "output-json");
            } else {
                // Compact JSON line
                appendOutput(`  ${d.line}`, "output-json");
            }
        } else {
            appendOutput(d.line, "output-text");
        }
    });

    evtSource.addEventListener("stderr", (e) => {
        const d = JSON.parse(e.data);
        appendOutput(d.line, "output-stderr");
    });

    evtSource.addEventListener("tool_done", (e) => {
        const d = JSON.parse(e.data);
        state.running = false;
        state.activeTool = null;
        updateRunningUI();
        const status = d.exit_code === 0 ? "completed" : `exited (${d.exit_code})`;
        appendOutput(`\n[*] ${d.tool} ${status} — ${d.parsed} results parsed`, "output-info");
    });

    evtSource.addEventListener("error", (e) => {
        if (evtSource.readyState === EventSource.CLOSED) {
            // Reconnect after a delay
            setTimeout(connectSSE, 3000);
            return;
        }
        try {
            const d = JSON.parse(e.data);
            appendOutput(`[!] ${d.tool}: ${d.message}`, "output-error");
            state.running = false;
            state.activeTool = null;
            updateRunningUI();
        } catch {
            // SSE connection error, not a data event
        }
    });
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

async function loadDoctor() {
    try {
        const data = await api("/api/doctor");
        const ok = data.ok;
        dom.doctorStatus.textContent = ok ? "Doctor: PASS" : "Doctor: FAIL";
        dom.doctorStatus.style.color = ok
            ? "var(--green)" : "var(--red)";
    } catch {
        dom.doctorStatus.textContent = "Doctor: ERR";
        dom.doctorStatus.style.color = "var(--red)";
    }
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

async function loadTools() {
    try {
        const data = await api("/api/tools");
        state.tools = data.tools || {};
        renderToolButtons();
    } catch {
        dom.toolButtons.textContent = "Failed to load tools";
    }
}

function renderToolButtons() {
    dom.toolButtons.innerHTML = "";
    const targetType = state.targetType;

    // Group by phase
    const phases = {};
    for (const [name, info] of Object.entries(state.tools)) {
        if (!info.target_types.includes(targetType)) continue;
        const phase = info.phase || "other";
        if (!phases[phase]) phases[phase] = [];
        phases[phase].push({name, ...info});
    }

    const phaseOrder = ["recon", "enum", "collect", "param", "fuzz", "attack"];
    const phaseLabels = {
        recon: "Recon", enum: "Enum", collect: "Collect",
        param: "Params", fuzz: "Fuzz", attack: "Attack",
    };

    for (const phase of phaseOrder) {
        const tools = phases[phase];
        if (!tools || tools.length === 0) continue;

        const group = document.createElement("div");
        group.className = "tool-group";

        const label = document.createElement("span");
        label.className = "tool-group-label";
        label.textContent = phaseLabels[phase] || phase;
        group.appendChild(label);

        for (const tool of tools) {
            const btn = document.createElement("button");
            btn.textContent = tool.name;
            btn.dataset.tool = tool.name;

            if (!tool.enabled) {
                btn.className = "disabled";
                btn.title = tool.gated
                    ? "Gated — enable manually" : "Disabled";
            } else if (!tool.available) {
                btn.className = "missing";
                btn.title = "Binary not found";
            } else {
                btn.className = "available";
                btn.title = tool.path;
            }
            group.appendChild(btn);
        }
        dom.toolButtons.appendChild(group);
    }
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

async function loadProfile() {
    try {
        const data = await api("/api/profile");
        state.activeProfile = data.active;
        state.profileValues = data.values;
        dom.profileSelect.value = data.active;
        updateProfileDisplay();
    } catch {
        // ignore
    }
}

async function setProfile(name) {
    const data = await apiPost("/api/profile", {profile: name});
    state.activeProfile = data.active;
    state.profileValues = data.values || {};
    updateProfileDisplay();
}

function updateProfileDisplay() {
    const p = state.activeProfile;
    const v = state.profileValues;
    dom.profileDisplay.textContent = `Profile: ${p}`;
    if (v.rate !== undefined) {
        dom.activeRate.textContent = `rate:${v.rate} threads:${v.threads} delay:${v.delay}ms`;
    }
}

// ---------------------------------------------------------------------------
// Target type toggle
// ---------------------------------------------------------------------------

function updateTargetTypeUI() {
    state.targetType = dom.targetType.value;

    if (state.targetType === "wildcard") {
        dom.roiSection.classList.remove("hidden");
        dom.findingsSection.classList.add("hidden");
        dom.target.placeholder = "example.com";
    } else {
        dom.roiSection.classList.add("hidden");
        dom.findingsSection.classList.remove("hidden");
        dom.target.placeholder = "https://app.example.com";
    }

    renderToolButtons();
}

// ---------------------------------------------------------------------------
// Running state UI
// ---------------------------------------------------------------------------

function updateRunningUI() {
    if (state.running) {
        dom.activeTool.textContent = state.activeTool || "Running...";
        dom.btnStart.disabled = true;
        dom.btnStart.textContent = "Running...";
        dom.btnStop.classList.remove("hidden");
    } else {
        dom.activeTool.textContent = "Idle";
        dom.btnStart.disabled = false;
        dom.btnStart.textContent = "Run Workflow";
        dom.btnStop.classList.add("hidden");
        if (dom.parsedCount) dom.parsedCount.textContent = "";
    }
}

function updateParsedCount() {
    if (dom.parsedCount) {
        dom.parsedCount.textContent = `${state.parsedCount} parsed`;
    }
}

// ---------------------------------------------------------------------------
// Output pane
// ---------------------------------------------------------------------------

const MAX_OUTPUT_LINES = 5000;

function appendOutput(text, cls) {
    const line = document.createElement("span");
    if (cls) line.className = cls;
    line.textContent = text + "\n";
    dom.outputPane.appendChild(line);

    // Trim old lines
    while (dom.outputPane.childElementCount > MAX_OUTPUT_LINES) {
        dom.outputPane.removeChild(dom.outputPane.firstChild);
    }

    dom.outputPane.scrollTop = dom.outputPane.scrollHeight;
}

function clearOutput() {
    dom.outputPane.innerHTML = "";
    dom.activeTool.textContent = "Idle";
    state.parsedCount = 0;
    updateParsedCount();
}

// ---------------------------------------------------------------------------
// Run / Stop
// ---------------------------------------------------------------------------

async function runTool(toolName) {
    const target = dom.target.value.trim();
    if (!target) {
        appendOutput("[!] Enter a target first", "output-warn");
        return;
    }
    if (state.running) {
        appendOutput("[!] A tool is already running", "output-warn");
        return;
    }

    try {
        const data = await apiPost("/api/run", {
            tool: toolName,
            target: target,
            target_type: state.targetType,
            context: {target, host: target, url: target},
        });
        if (data.error) {
            appendOutput(`[!] ${data.error}`, "output-error");
        }
    } catch (err) {
        appendOutput(`[!] Failed to start ${toolName}: ${err.message}`, "output-error");
    }
}

async function stopTool() {
    try {
        await apiPost("/api/stop", {});
        appendOutput("[*] Stop signal sent", "output-warn");
    } catch {
        appendOutput("[!] Failed to send stop signal", "output-error");
    }
}

// ---------------------------------------------------------------------------
// Event bindings
// ---------------------------------------------------------------------------

function bindEvents() {
    dom.targetType.addEventListener("change", updateTargetTypeUI);
    dom.profileSelect.addEventListener("change", () => {
        setProfile(dom.profileSelect.value);
    });
    dom.btnClear.addEventListener("click", clearOutput);

    if (dom.btnStop) {
        dom.btnStop.addEventListener("click", stopTool);
    }

    // Tool buttons — individual run
    dom.toolButtons.addEventListener("click", (e) => {
        const btn = e.target.closest("button");
        if (!btn || !btn.dataset.tool) return;
        if (btn.classList.contains("missing")) {
            appendOutput(`[!] ${btn.dataset.tool}: binary not found`, "output-error");
            return;
        }
        if (btn.classList.contains("disabled")) {
            appendOutput(`[!] ${btn.dataset.tool} is disabled`, "output-warn");
            return;
        }
        runTool(btn.dataset.tool);
    });

    // Run workflow button — for now runs first available tool (full workflow in step 4)
    dom.btnStart.addEventListener("click", () => {
        const target = dom.target.value.trim();
        if (!target) {
            appendOutput("[!] Enter a target first", "output-warn");
            return;
        }
        if (state.running) {
            appendOutput("[!] A tool is already running", "output-warn");
            return;
        }
        appendOutput(`[*] Full workflow not yet implemented — use individual tool buttons`, "output-info");
    });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", init);
