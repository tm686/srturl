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
    pipeline: false,  // true when running a multi-step pipeline
    activeTool: null,
    parsedCount: 0,
    pipelineStep: 0,
    pipelineTotal: 0,
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
    pipelineSelect: $("#pipeline-select"),
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
        const status = d.exit_code === 0 ? "completed" : `exited (${d.exit_code})`;
        appendOutput(`\n[*] ${d.tool} ${status} — ${d.parsed} results parsed`, "output-info");
        // Only reset running state if NOT in a pipeline (pipeline_done handles that)
        if (!state.pipeline) {
            state.running = false;
            state.activeTool = null;
            updateRunningUI();
        }
    });

    // Pipeline events
    evtSource.addEventListener("pipeline_step", (e) => {
        const d = JSON.parse(e.data);
        state.pipeline = true;
        state.running = true;
        state.pipelineStep = d.step;
        state.pipelineTotal = d.total;
        appendOutput(`\n=== Step ${d.step}/${d.total}: ${d.label} ===`, "output-pipeline");
        updateRunningUI();
    });

    evtSource.addEventListener("pipeline_info", (e) => {
        const d = JSON.parse(e.data);
        appendOutput(`  [pipeline] ${d.message}`, "output-pipeline");
    });

    evtSource.addEventListener("pipeline_done", (e) => {
        const d = JSON.parse(e.data);
        state.pipeline = false;
        state.running = false;
        state.activeTool = null;
        updateRunningUI();
        appendOutput(`\n=== Pipeline complete (${d.steps} steps) ===`, "output-pipeline");
        // Refresh data tables
        loadSubdomains();
        loadUrls();
    });

    evtSource.addEventListener("error", (e) => {
        if (evtSource.readyState === EventSource.CLOSED) {
            setTimeout(connectSSE, 3000);
            return;
        }
        try {
            const d = JSON.parse(e.data);
            appendOutput(`[!] ${d.tool}: ${d.message}`, "output-error");
            if (!state.pipeline) {
                state.running = false;
                state.activeTool = null;
                updateRunningUI();
            }
        } catch {
            // SSE connection error
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
        dom.pipelineSelect.classList.remove("hidden");
    } else {
        dom.roiSection.classList.add("hidden");
        dom.findingsSection.classList.remove("hidden");
        dom.target.placeholder = "https://app.example.com";
        dom.pipelineSelect.classList.add("hidden");
    }

    renderToolButtons();
}

// ---------------------------------------------------------------------------
// Running state UI
// ---------------------------------------------------------------------------

function updateRunningUI() {
    if (state.running) {
        let label = state.activeTool || "Running...";
        if (state.pipeline) {
            label = `[${state.pipelineStep}/${state.pipelineTotal}] ${label}`;
        }
        dom.activeTool.textContent = label;
        dom.btnStart.disabled = true;
        dom.btnStart.textContent = state.pipeline ? `Pipeline ${state.pipelineStep}/${state.pipelineTotal}` : "Running...";
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

    // Run Workflow button — triggers selected pipeline
    dom.btnStart.addEventListener("click", () => {
        const target = dom.target.value.trim();
        if (!target) {
            appendOutput("[!] Enter a target first", "output-warn");
            return;
        }
        if (state.running) {
            appendOutput("[!] Already running", "output-warn");
            return;
        }
        if (state.targetType === "wildcard") {
            const pipeline = dom.pipelineSelect.value;
            runPipeline(pipeline, target);
        } else {
            appendOutput("[*] URL workflow not yet implemented — use individual tool buttons", "output-info");
        }
    });
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

async function runPipeline(name, target) {
    if (state.running) return;
    try {
        const data = await apiPost("/api/pipeline", {
            pipeline: name,
            target: target,
            target_type: state.targetType,
        });
        if (data.error) {
            appendOutput(`[!] ${data.error}`, "output-error");
        } else {
            appendOutput(`[*] Pipeline "${name}" started (scan ${data.scan_id})`, "output-info");
            appendOutput(`    steps: ${data.steps.join(" -> ")}`, "output-stderr");
        }
    } catch (err) {
        appendOutput(`[!] Failed to start pipeline: ${err.message}`, "output-error");
    }
}

// ---------------------------------------------------------------------------
// Data tables — subdomains + URLs (loaded after pipeline / on demand)
// ---------------------------------------------------------------------------

async function loadSubdomains() {
    try {
        const data = await api("/api/subdomains");
        renderSubdomainsTable(data.subdomains || []);
    } catch { /* ignore */ }
}

function renderSubdomainsTable(subs) {
    const container = $("#roi-table");
    if (!container) return;
    if (subs.length === 0) {
        container.innerHTML = '<span class="output-stderr">No subdomains yet</span>';
        return;
    }
    let html = `<div class="data-table-header">${subs.length} subdomains</div>`;
    html += '<table class="data-table"><thead><tr><th>FQDN</th><th>IP</th><th>Sources</th></tr></thead><tbody>';
    for (const s of subs) {
        let sources = "[]";
        try { sources = JSON.parse(s.sources).join(", "); } catch {}
        html += `<tr><td>${esc(s.fqdn)}</td><td>${esc(s.resolved_ip || "—")}</td><td>${esc(sources)}</td></tr>`;
    }
    html += '</tbody></table>';
    container.innerHTML = html;
}

async function loadUrls() {
    try {
        const data = await api("/api/urls");
        renderUrlsTable(data.urls || []);
    } catch { /* ignore */ }
}

function renderUrlsTable(urls) {
    // For wildcard mode, show in ROI section (below subdomains); for url mode, show in findings
    const container = state.targetType === "wildcard" ? $("#roi-table") : $("#findings-table");
    if (!container) return;
    if (urls.length === 0) return; // don't overwrite subdomains table if no URLs yet

    const hasScreenshots = urls.some(u => u.screenshot_path);
    let html = container.innerHTML || "";
    html += `<div class="data-table-header" style="margin-top:16px">${urls.length} live URLs</div>`;
    html += '<table class="data-table"><thead><tr>';
    if (hasScreenshots) html += '<th>Screenshot</th>';
    html += '<th>URL</th><th>Status</th><th>Title</th><th>Tech</th><th>Server</th></tr></thead><tbody>';
    for (const u of urls) {
        html += `<tr>`;
        if (hasScreenshots) {
            if (u.screenshot_path) {
                html += `<td class="screenshot-cell"><img src="/screenshots/${esc(u.screenshot_path)}" class="screenshot-thumb" loading="lazy" onclick="showScreenshot(this.src, '${esc(u.url)}')" title="Click to enlarge"></td>`;
            } else {
                html += `<td class="screenshot-cell"><span class="no-screenshot">—</span></td>`;
            }
        }
        html += `<td class="url-cell">${esc(u.url)}</td>`;
        html += `<td>${u.status_code || "—"}</td>`;
        html += `<td>${esc(u.title || "—")}</td>`;
        html += `<td>${esc(u.tech || "—")}</td>`;
        html += `<td>${esc(u.server || "—")}</td>`;
        html += `</tr>`;
    }
    html += '</tbody></table>';
    container.innerHTML = html;
}

function showScreenshot(src, url) {
    // Create fullscreen overlay for screenshot preview
    const overlay = document.createElement("div");
    overlay.className = "screenshot-overlay";
    overlay.innerHTML = `
        <div class="screenshot-overlay-content">
            <div class="screenshot-overlay-header">
                <span class="url-cell">${esc(url)}</span>
                <button onclick="this.closest('.screenshot-overlay').remove()">Close</button>
            </div>
            <img src="${src}" alt="Screenshot of ${esc(url)}">
        </div>
    `;
    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) overlay.remove();
    });
    document.body.appendChild(overlay);
}

function esc(s) {
    const el = document.createElement("span");
    el.textContent = s;
    return el.innerHTML;
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", init);
