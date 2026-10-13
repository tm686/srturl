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
    profileSelect:  $("#profile-select"),
    toolButtons:    $("#tool-buttons"),
    outputPane:     $("#output-pane"),
    activeTool:     $("#active-tool"),
    activeRate:     $("#active-rate"),
    btnClear:       $("#btn-clear-output"),
    roiSection:     $("#roi-section"),
    findingsSection:$("#findings-section"),
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
        // Filter by target type
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

    // Show/hide sections by type
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
// Output pane
// ---------------------------------------------------------------------------

function appendOutput(text, cls) {
    const line = document.createElement("span");
    if (cls) line.className = cls;
    line.textContent = text + "\n";
    dom.outputPane.appendChild(line);
    dom.outputPane.scrollTop = dom.outputPane.scrollHeight;
}

function clearOutput() {
    dom.outputPane.innerHTML = "";
    dom.activeTool.textContent = "Idle";
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

    // Tool buttons — individual run (step 2+)
    dom.toolButtons.addEventListener("click", (e) => {
        const btn = e.target.closest("button");
        if (!btn || btn.classList.contains("missing")) return;
        if (btn.classList.contains("disabled")) {
            appendOutput(`[!] ${btn.dataset.tool} is disabled`, "output-warn");
            return;
        }
        appendOutput(`[*] ${btn.dataset.tool} — runner not yet implemented`, "output-info");
    });

    // Run workflow (step 2+)
    dom.btnStart.addEventListener("click", () => {
        const target = dom.target.value.trim();
        if (!target) {
            appendOutput("[!] Enter a target first", "output-warn");
            return;
        }
        appendOutput(`[*] Workflow run not yet implemented (target: ${target}, type: ${state.targetType})`, "output-info");
    });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", init);
