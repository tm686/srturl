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
    findings: [],
    activeEngagement: null,
    triageFilterROI: "",
    triageFilterFindings: "",
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
    statsDisplay:   $("#stats-display"),
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
    initTheme();
    await Promise.all([
        loadDoctor(),
        loadTools(),
        loadProfile(),
        loadStats(),
        loadEngagements(),
    ]);
    bindEvents();
    updateTargetTypeUI();
    loadPromoted();
    loadROI();
    loadSnapshots();
    connectSSE();
}

// ---------------------------------------------------------------------------
// Feature 1: Dashboard Stats
// ---------------------------------------------------------------------------

async function loadStats() {
    try {
        const data = await api("/api/stats");
        const c = data.counts || {};
        if (!dom.statsDisplay) return;
        dom.statsDisplay.innerHTML =
            `<span class="stat-item"><b>${c.subdomains||0}</b> subs</span>` +
            `<span class="stat-item"><b>${c.urls||0}</b> urls</span>` +
            `<span class="stat-item"><b>${c.hosts||0}</b> hosts</span>` +
            `<span class="stat-item"><b>${c.findings||0}</b> findings</span>`;
    } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// Feature 2: Dark/Light Theme Toggle
// ---------------------------------------------------------------------------

function initTheme() {
    const saved = localStorage.getItem("recon-theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    updateThemeButton();
}

function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("recon-theme", next);
    updateThemeButton();
}

function updateThemeButton() {
    const btn = $("#btn-theme-toggle");
    if (!btn) return;
    const theme = document.documentElement.getAttribute("data-theme") || "dark";
    btn.textContent = theme === "dark" ? "Light" : "Dark";
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
        loadStats();
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
        // Refresh data tables + ROI + findings + stats
        loadSubdomains();
        loadUrls();
        loadROI();
        loadFindings();
        loadStats();
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
    const promotedSelect = $("#promoted-select");
    const urlPipelineSelect = $("#url-pipeline-select");
    const ipPipelineSelect = $("#ip-pipeline-select");
    const nucleiFilters = $("#nuclei-filters");
    const btnImport = $("#btn-import-urls");

    // Hide everything first
    dom.roiSection.classList.add("hidden");
    dom.findingsSection.classList.add("hidden");
    dom.pipelineSelect.classList.add("hidden");
    if (promotedSelect) promotedSelect.classList.add("hidden");
    if (urlPipelineSelect) urlPipelineSelect.classList.add("hidden");
    if (ipPipelineSelect) ipPipelineSelect.classList.add("hidden");
    if (nucleiFilters) nucleiFilters.classList.add("hidden");
    if (btnImport) btnImport.classList.add("hidden");

    if (state.targetType === "wildcard") {
        dom.roiSection.classList.remove("hidden");
        dom.target.placeholder = "example.com";
        dom.pipelineSelect.classList.remove("hidden");
    } else if (state.targetType === "url") {
        dom.findingsSection.classList.remove("hidden");
        dom.target.placeholder = "https://app.example.com";
        if (promotedSelect) {
            promotedSelect.classList.remove("hidden");
            loadPromoted();
        }
        if (urlPipelineSelect) urlPipelineSelect.classList.remove("hidden");
        if (nucleiFilters) nucleiFilters.classList.remove("hidden");
        if (btnImport) btnImport.classList.remove("hidden");
        loadFindings();
    } else if (state.targetType === "ip") {
        dom.target.placeholder = "192.168.1.0/24 or 10.0.0.1";
        if (ipPipelineSelect) ipPipelineSelect.classList.remove("hidden");
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
// Feature 5: Nuclei filter overrides
// ---------------------------------------------------------------------------

function getNucleiOverrides() {
    const checked = [...$$('input[name="nuclei-sev"]:checked')].map(cb => cb.value);
    const tags = ($("#nuclei-tags") || {}).value || "";
    const overrides = {};
    if (checked.length > 0 && checked.length < 5) {
        overrides.severity = checked.join(",");
    }
    if (tags.trim()) {
        overrides.tags = tags.trim();
    }
    return Object.keys(overrides).length > 0 ? overrides : null;
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

    const btnROI = $("#btn-recalculate-roi");
    if (btnROI) {
        btnROI.addEventListener("click", recalculateROI);
    }

    // Feature 2: Theme toggle
    const btnTheme = $("#btn-theme-toggle");
    if (btnTheme) btnTheme.addEventListener("click", toggleTheme);

    // Feature 4: Auto-promote
    const btnAutoPromote = $("#btn-auto-promote");
    if (btnAutoPromote) btnAutoPromote.addEventListener("click", autoPromote);

    // Export buttons
    const btnExportJson = $("#btn-export-json");
    const btnExportCsv = $("#btn-export-csv");
    if (btnExportJson) btnExportJson.addEventListener("click", () => exportFindings("json"));
    if (btnExportCsv) btnExportCsv.addEventListener("click", () => exportFindings("csv"));

    // Evidence viewer (event delegation on findings table)
    const findingsTable = $("#findings-table");
    if (findingsTable) {
        findingsTable.addEventListener("click", (e) => {
            const btn = e.target.closest(".btn-evidence");
            if (!btn) return;
            const id = parseInt(btn.dataset.findingId, 10);
            if (id) showEvidence(id);
        });
    }

    // Attack confirm modal
    const btnConfirm = $("#btn-confirm-attack");
    const btnCancel = $("#btn-cancel-attack");
    if (btnConfirm) btnConfirm.addEventListener("click", confirmAttack);
    if (btnCancel) btnCancel.addEventListener("click", cancelAttack);

    // Promote buttons in ROI table (event delegation)
    const roiTable = $("#roi-table");
    if (roiTable) {
        roiTable.addEventListener("click", (e) => {
            const btn = e.target.closest(".btn-promote");
            if (!btn) return;
            const url = btn.dataset.url;
            if (url) promoteUrl(url);
        });
    }

    // Promoted target selector — fill target input on selection
    const promotedSelect = $("#promoted-select");
    if (promotedSelect) {
        promotedSelect.addEventListener("change", () => {
            const val = promotedSelect.value;
            if (val) dom.target.value = val;
        });
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
        } else if (state.targetType === "ip") {
            runIpPipeline(target);
        } else {
            const pipeline = ($("#url-pipeline-select") || {}).value || "url";
            runUrlPipeline(pipeline, target);
        }
    });

    // Feature 6: Engagement controls
    const engSelect = $("#engagement-select");
    if (engSelect) engSelect.addEventListener("change", () => activateEngagement(engSelect.value));
    const btnNewEng = $("#btn-new-engagement");
    if (btnNewEng) btnNewEng.addEventListener("click", createEngagement);
    const btnClearEng = $("#btn-clear-engagement");
    if (btnClearEng) btnClearEng.addEventListener("click", clearEngagement);

    // Feature 8: Import URLs
    const btnImport = $("#btn-import-urls");
    if (btnImport) btnImport.addEventListener("click", showImportModal);
    const btnSubmitImport = $("#btn-submit-import");
    if (btnSubmitImport) btnSubmitImport.addEventListener("click", submitImport);
    const btnCancelImport = $("#btn-cancel-import");
    if (btnCancelImport) btnCancelImport.addEventListener("click", () => {
        $("#import-urls-modal").classList.add("hidden");
    });

    // Feature 9: Snapshot/diff controls
    const btnSaveSnap = $("#btn-save-snapshot");
    if (btnSaveSnap) btnSaveSnap.addEventListener("click", createSnapshot);
    const btnRunDiff = $("#btn-run-diff");
    if (btnRunDiff) btnRunDiff.addEventListener("click", runDiff);

    // Feature 3: Triage filters
    const triageFilterROI = $("#triage-filter-roi");
    if (triageFilterROI) triageFilterROI.addEventListener("change", () => {
        state.triageFilterROI = triageFilterROI.value;
        loadROI();
    });
    const triageFilterFindings = $("#triage-filter-findings");
    if (triageFilterFindings) triageFilterFindings.addEventListener("change", () => {
        state.triageFilterFindings = triageFilterFindings.value;
        loadFindings();
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
// URL workflow pipeline
// ---------------------------------------------------------------------------

async function runUrlPipeline(name, target) {
    if (state.running) return;
    try {
        const body = {
            pipeline: name,
            target: target,
            target_type: "url",
        };
        const overrides = getNucleiOverrides();
        if (overrides) body.nuclei_overrides = overrides;

        const data = await apiPost("/api/pipeline", body);
        if (data.needs_confirm) {
            // Show attack confirmation modal
            showAttackConfirm(data.pipeline, data.target, data.attack_tools);
        } else if (data.error) {
            appendOutput(`[!] ${data.error}`, "output-error");
        } else {
            appendOutput(`[*] URL pipeline "${name}" started (scan ${data.scan_id})`, "output-info");
            appendOutput(`    steps: ${data.steps.join(" -> ")}`, "output-stderr");
        }
    } catch (err) {
        appendOutput(`[!] Failed to start URL pipeline: ${err.message}`, "output-error");
    }
}

// ---------------------------------------------------------------------------
// Feature 7: IP/CIDR pipeline
// ---------------------------------------------------------------------------

async function runIpPipeline(target) {
    if (state.running) return;
    try {
        const data = await apiPost("/api/pipeline", {
            pipeline: "ip",
            target: target,
            target_type: "ip",
        });
        if (data.error) {
            appendOutput(`[!] ${data.error}`, "output-error");
        } else {
            appendOutput(`[*] IP pipeline started (scan ${data.scan_id})`, "output-info");
            appendOutput(`    steps: ${data.steps.join(" -> ")}`, "output-stderr");
        }
    } catch (err) {
        appendOutput(`[!] Failed to start IP pipeline: ${err.message}`, "output-error");
    }
}

function showAttackConfirm(pipeline, target, tools) {
    const modal = $("#attack-confirm-modal");
    const targetSpan = $("#confirm-target");
    const toolsSpan = $("#confirm-tools");
    if (!modal || !targetSpan || !toolsSpan) return;

    targetSpan.textContent = target;
    toolsSpan.textContent = tools.join(", ");
    modal.classList.remove("hidden");

    // Store for confirm handler
    state.pendingAttack = {pipeline, target};
}

async function confirmAttack() {
    const modal = $("#attack-confirm-modal");
    if (modal) modal.classList.add("hidden");
    if (!state.pendingAttack) return;

    const {pipeline, target} = state.pendingAttack;
    state.pendingAttack = null;

    try {
        const body = {
            pipeline: pipeline,
            target: target,
            target_type: "url",
            confirmed: true,
        };
        const overrides = getNucleiOverrides();
        if (overrides) body.nuclei_overrides = overrides;

        const data = await apiPost("/api/pipeline", body);
        if (data.error) {
            appendOutput(`[!] ${data.error}`, "output-error");
        } else {
            appendOutput(`[*] URL pipeline "${pipeline}" started with attack phase (scan ${data.scan_id})`, "output-info");
            appendOutput(`    steps: ${data.steps.join(" -> ")}`, "output-stderr");
        }
    } catch (err) {
        appendOutput(`[!] Failed to start pipeline: ${err.message}`, "output-error");
    }
}

function cancelAttack() {
    const modal = $("#attack-confirm-modal");
    if (modal) modal.classList.add("hidden");
    state.pendingAttack = null;
    appendOutput("[*] Attack cancelled", "output-warn");
}

// ---------------------------------------------------------------------------
// Findings (Feature 10: dedup)
// ---------------------------------------------------------------------------

async function loadFindings() {
    try {
        const data = await api("/api/findings");
        renderFindings(data.findings || [], data.total_count || 0);
    } catch { /* ignore */ }
}

function renderFindings(findings, totalCount) {
    const container = $("#findings-table");
    if (!container) return;

    // Apply triage filter
    const filter = state.triageFilterFindings;
    if (filter) {
        if (filter === "none") {
            findings = findings.filter(f => !f.triage);
        } else {
            findings = findings.filter(f => f.triage === filter);
        }
    }

    // Show/hide export buttons and triage filter bar
    const exportGroup = $("#export-group");
    if (exportGroup) exportGroup.classList.toggle("hidden", findings.length === 0);
    const triageBar = $("#triage-filter-findings-bar");
    if (triageBar) triageBar.classList.toggle("hidden", findings.length === 0 && !filter);

    if (findings.length === 0) {
        container.innerHTML = '<span class="output-stderr">No findings yet — run a URL workflow</span>';
        return;
    }

    // Summary by severity (Feature 10: unique vs total)
    const counts = {};
    for (const f of findings) {
        const sev = (f.severity || "info").toLowerCase();
        counts[sev] = (counts[sev] || 0) + 1;
    }
    let html = '<div class="findings-summary">';
    html += `<span class="data-table-header">${findings.length} unique findings`;
    if (totalCount && totalCount > findings.length) {
        html += ` (${totalCount} total)`;
    }
    html += `</span>`;
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
        if (counts[sev]) {
            html += ` <span class="severity-badge severity-${sev}">${counts[sev]} ${sev}</span>`;
        }
    }
    html += '</div>';

    html += '<table class="data-table"><thead><tr>';
    html += '<th>Severity</th><th>URL</th><th>Vector</th><th>Template</th><th>Tool</th><th>Count</th><th>Triage</th><th>Notes</th><th>Evidence</th>';
    html += '</tr></thead><tbody>';

    for (const f of findings) {
        const sevCls = `severity-${(f.severity || "info").toLowerCase()}`;
        const hasEvidence = f.request || f.response;
        const dupeCount = f.dupe_count || 1;
        html += `<tr>`;
        html += `<td><span class="severity-badge ${sevCls}">${esc(f.severity || "info")}</span></td>`;
        html += `<td class="url-cell">${esc(f.url)}</td>`;
        html += `<td>${esc(f.vector || "\u2014")}</td>`;
        html += `<td>${esc(f.template_id || "\u2014")}</td>`;
        html += `<td>${esc(f.tool || "\u2014")}</td>`;
        html += `<td>${dupeCount > 1 ? `<span class="dupe-badge">${dupeCount}x</span>` : "1"}</td>`;
        html += `<td><select class="triage-select" onchange="window.saveNote('findings',${f.id},'triage',this.value)">`;
        for (const [val, label] of [["","—"],["interesting","Interesting"],["investigated","Investigated"],["false_positive","False Positive"]]) {
            html += `<option value="${val}"${f.triage === val ? " selected" : ""}>${label}</option>`;
        }
        html += `</select></td>`;
        html += `<td><input class="note-input" value="${esc(f.notes || "")}" onchange="window.saveNote('findings',${f.id},'notes',this.value)" placeholder="notes"></td>`;
        if (hasEvidence) {
            html += `<td><button class="btn-evidence" data-finding-id="${f.id}">View</button></td>`;
        } else {
            html += `<td><span class="output-stderr">\u2014</span></td>`;
        }
        html += `</tr>`;
    }
    html += '</tbody></table>';
    container.innerHTML = html;

    // Store findings for evidence viewer
    state.findings = findings;
}

// Feature 3: Save note/triage
window.saveNote = async function(table, id, field, value) {
    try {
        const body = {table, id};
        body[field] = value;
        await apiPost("/api/notes", body);
    } catch { /* ignore */ }
};

function showEvidence(findingId) {
    const finding = (state.findings || []).find(f => f.id === findingId);
    if (!finding) return;

    const overlay = document.createElement("div");
    overlay.className = "screenshot-overlay";
    overlay.innerHTML = `
        <div class="evidence-modal">
            <div class="screenshot-overlay-header">
                <span class="url-cell">${esc(finding.url)}</span>
                <span class="severity-badge severity-${(finding.severity||"info").toLowerCase()}">${esc(finding.severity||"info")}</span>
                <button onclick="this.closest('.screenshot-overlay').remove()">Close</button>
            </div>
            <div class="evidence-body">
                <div class="evidence-section">
                    <h4>Request</h4>
                    <pre class="evidence-pre">${esc(finding.request || "(no request captured)")}</pre>
                </div>
                <div class="evidence-section">
                    <h4>Response</h4>
                    <pre class="evidence-pre">${esc(finding.response || "(no response captured)")}</pre>
                </div>
            </div>
        </div>
    `;
    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) overlay.remove();
    });
    document.body.appendChild(overlay);
}

function exportFindings(format) {
    // Trigger download via navigating to export URL
    window.location.href = `/api/export/${format}`;
    appendOutput(`[*] Exporting ${format.toUpperCase()}...`, "output-info");
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
        html += `<tr><td>${esc(s.fqdn)}</td><td>${esc(s.resolved_ip || "\u2014")}</td><td>${esc(sources)}</td></tr>`;
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

    // Remove any previously rendered URLs table to prevent duplicates
    const existingUrlsTable = container.querySelector(".urls-table-block");
    if (existingUrlsTable) existingUrlsTable.remove();

    const hasScreenshots = urls.some(u => u.screenshot_path);
    let html = `<div class="urls-table-block">`;
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
                html += `<td class="screenshot-cell"><span class="no-screenshot">\u2014</span></td>`;
            }
        }
        html += `<td class="url-cell">${esc(u.url)}</td>`;
        html += `<td>${u.status_code || "\u2014"}</td>`;
        html += `<td>${esc(u.title || "\u2014")}</td>`;
        html += `<td>${esc(u.tech || "\u2014")}</td>`;
        html += `<td>${esc(u.server || "\u2014")}</td>`;
        html += `</tr>`;
    }
    html += '</tbody></table></div>';
    container.insertAdjacentHTML("beforeend", html);
}

// Exposed on window for inline onclick in rendered HTML
window.showScreenshot = showScreenshot;
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
// ROI Report (with Feature 3: notes/triage columns)
// ---------------------------------------------------------------------------

async function loadROI() {
    try {
        const data = await api("/api/roi");
        renderROI(data.roi || []);
    } catch { /* ignore */ }
}

async function recalculateROI() {
    try {
        const data = await apiPost("/api/roi/recalculate", {});
        if (data.ok) {
            appendOutput(`[*] ${data.message}`, "output-info");
            renderROI(data.roi || []);
        }
    } catch (err) {
        appendOutput(`[!] ROI recalculation failed: ${err.message}`, "output-error");
    }
}

function roiTier(score) {
    if (score >= 80) return { label: "HIGH", cls: "roi-high" };
    if (score >= 40) return { label: "MED", cls: "roi-med" };
    if (score > 0)   return { label: "LOW", cls: "roi-low" };
    return { label: "\u2014", cls: "roi-none" };
}

function renderROI(results) {
    const summary = $("#roi-summary");
    const table = $("#roi-table");
    if (!summary || !table) return;

    // Apply triage filter
    const filter = state.triageFilterROI;
    if (filter) {
        if (filter === "none") {
            results = results.filter(r => !r.triage);
        } else {
            results = results.filter(r => r.triage === filter);
        }
    }

    // Show triage filter bar if we have results
    const triageBar = $("#triage-filter-bar");
    if (triageBar) triageBar.classList.toggle("hidden", results.length === 0 && !filter);

    if (results.length === 0) {
        summary.innerHTML = '<span class="output-stderr">No ROI data yet — run a pipeline first</span>';
        table.innerHTML = "";
        return;
    }

    // Summary stats
    const high = results.filter(r => r.score >= 80).length;
    const med = results.filter(r => r.score >= 40 && r.score < 80).length;
    const low = results.filter(r => r.score > 0 && r.score < 40).length;
    const topScore = results[0]?.score || 0;

    summary.innerHTML = `
        <div class="roi-stats">
            <span class="roi-stat"><span class="roi-badge roi-high">${high}</span> High</span>
            <span class="roi-stat"><span class="roi-badge roi-med">${med}</span> Med</span>
            <span class="roi-stat"><span class="roi-badge roi-low">${low}</span> Low</span>
            <span class="roi-stat">${results.length} total — top score: ${topScore}</span>
        </div>
    `;

    // Ranked table with triage/notes columns
    let html = '<table class="data-table"><thead><tr>';
    html += '<th>ROI</th><th>URL</th><th>Status</th><th>Title</th><th>Breakdown</th><th>Triage</th><th>Notes</th><th>Action</th>';
    html += '</tr></thead><tbody>';

    for (const r of results) {
        const tier = roiTier(r.score);
        const breakdownParts = [];
        for (const [key, val] of Object.entries(r.breakdown || {})) {
            breakdownParts.push(`${key}:${val}`);
        }
        const breakdownStr = breakdownParts.join(" ") || "\u2014";

        html += `<tr>`;
        html += `<td><span class="roi-badge ${tier.cls}">${r.score}</span></td>`;
        html += `<td class="url-cell">${esc(r.url)}</td>`;
        html += `<td>${r.status_code || "\u2014"}</td>`;
        html += `<td>${esc(r.title || "\u2014")}</td>`;
        html += `<td class="roi-breakdown">${esc(breakdownStr)}</td>`;
        html += `<td><select class="triage-select" onchange="window.saveNote('urls','${esc(r.url)}','triage',this.value)">`;
        for (const [val, label] of [["","\u2014"],["interesting","Interesting"],["investigated","Investigated"],["false_positive","False Positive"]]) {
            html += `<option value="${val}"${r.triage === val ? " selected" : ""}>${label}</option>`;
        }
        html += `</select></td>`;
        html += `<td><input class="note-input" value="${esc(r.notes || "")}" onchange="window.saveNote('urls','${esc(r.url)}','notes',this.value)" placeholder="notes"></td>`;
        if (r.promoted_to_target) {
            html += `<td><span class="promoted-badge">Promoted</span></td>`;
        } else {
            html += `<td><button class="btn-promote" data-url="${esc(r.url)}">Promote</button></td>`;
        }
        html += `</tr>`;
    }
    html += '</tbody></table>';
    table.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Promote to URL target
// ---------------------------------------------------------------------------

async function promoteUrl(url) {
    try {
        const data = await apiPost("/api/promote", {url});
        if (data.ok) {
            appendOutput(`[*] Promoted ${url} to URL target`, "output-info");
            loadROI();
            loadPromoted();
        } else {
            appendOutput(`[!] Promote failed: ${data.error}`, "output-error");
        }
    } catch (err) {
        appendOutput(`[!] Promote failed: ${err.message}`, "output-error");
    }
}

async function loadPromoted() {
    const sel = $("#promoted-select");
    if (!sel) return;
    try {
        const data = await api("/api/promoted");
        const promoted = data.promoted || [];
        sel.innerHTML = '<option value="">— select promoted target —</option>';
        for (const p of promoted) {
            const opt = document.createElement("option");
            opt.value = p.url;
            opt.textContent = `[${p.roi_score}] ${p.url}`;
            sel.appendChild(opt);
        }
    } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// Feature 4: Auto-promote
// ---------------------------------------------------------------------------

async function autoPromote() {
    try {
        const data = await apiPost("/api/auto-promote", {});
        if (data.ok) {
            appendOutput(`[*] Auto-promoted ${data.promoted} URLs (threshold >= ${data.threshold})`, "output-info");
            loadROI();
            loadPromoted();
            loadStats();
        }
    } catch (err) {
        appendOutput(`[!] Auto-promote failed: ${err.message}`, "output-error");
    }
}

// ---------------------------------------------------------------------------
// Feature 6: Engagement management
// ---------------------------------------------------------------------------

async function loadEngagements() {
    const sel = $("#engagement-select");
    if (!sel) return;
    try {
        const data = await api("/api/engagements");
        const engs = data.engagements || [];
        sel.innerHTML = '<option value="">— none —</option>';
        for (const e of engs) {
            const opt = document.createElement("option");
            opt.value = e.id;
            opt.textContent = e.name;
            sel.appendChild(opt);
        }
        if (data.active_id) {
            sel.value = data.active_id;
            state.activeEngagement = data.active_id;
        }
    } catch { /* ignore */ }
}

async function activateEngagement(id) {
    try {
        const engId = id ? parseInt(id, 10) : null;
        const data = await apiPost("/api/engagement/activate", {id: engId});
        if (data.ok) {
            state.activeEngagement = data.active_id;
            appendOutput(`[*] Engagement: ${data.name || "none"}`, "output-info");
        }
    } catch { /* ignore */ }
}

function createEngagement() {
    const name = prompt("Engagement name:");
    if (!name) return;
    apiPost("/api/engagement", {name}).then(data => {
        if (data.ok) {
            appendOutput(`[*] Created engagement: ${name}`, "output-info");
            loadEngagements();
            activateEngagement(data.id);
        } else {
            appendOutput(`[!] ${data.error}`, "output-error");
        }
    });
}

function clearEngagement() {
    const msg = state.activeEngagement
        ? "Clear all data for the active engagement?"
        : "Clear ALL data from the database?";
    if (!confirm(msg)) return;
    apiPost("/api/engagement/clear", {}).then(data => {
        if (data.ok) {
            appendOutput(`[*] Data cleared (${data.cleared})`, "output-info");
            loadStats();
            loadROI();
            loadFindings();
            loadSubdomains();
        }
    });
}

// ---------------------------------------------------------------------------
// Feature 8: Bulk URL import
// ---------------------------------------------------------------------------

function showImportModal() {
    const modal = $("#import-urls-modal");
    if (modal) modal.classList.remove("hidden");
}

async function submitImport() {
    const textarea = $("#import-urls-textarea");
    const modal = $("#import-urls-modal");
    if (!textarea) return;
    const raw = textarea.value.trim();
    if (!raw) return;

    try {
        const data = await apiPost("/api/import/urls", {raw});
        if (data.ok) {
            appendOutput(`[*] Imported ${data.imported} URLs (${data.skipped} skipped)`, "output-info");
            textarea.value = "";
            if (modal) modal.classList.add("hidden");
            loadUrls();
            loadStats();
        }
    } catch (err) {
        appendOutput(`[!] Import failed: ${err.message}`, "output-error");
    }
}

// ---------------------------------------------------------------------------
// Feature 9: Scan Diffing
// ---------------------------------------------------------------------------

async function createSnapshot() {
    const name = prompt("Snapshot name:", `snap-${new Date().toISOString().slice(0,16).replace("T","-")}`);
    if (!name) return;
    try {
        const data = await apiPost("/api/snapshot", {name});
        if (data.ok) {
            appendOutput(`[*] Snapshot saved: ${name} (id ${data.id})`, "output-info");
            loadSnapshots();
        }
    } catch (err) {
        appendOutput(`[!] Snapshot failed: ${err.message}`, "output-error");
    }
}

async function loadSnapshots() {
    const selA = $("#snapshot-select-a");
    const selB = $("#snapshot-select-b");
    if (!selA) return;
    try {
        const data = await api("/api/snapshots");
        const snaps = data.snapshots || [];
        selA.innerHTML = '<option value="">— snapshot A —</option>';
        if (selB) selB.innerHTML = '<option value="">— current —</option>';
        for (const s of snaps) {
            const optA = document.createElement("option");
            optA.value = s.id;
            optA.textContent = `${s.name} (${s.created_at})`;
            selA.appendChild(optA);
            if (selB) {
                const optB = document.createElement("option");
                optB.value = s.id;
                optB.textContent = `${s.name} (${s.created_at})`;
                selB.appendChild(optB);
            }
        }
    } catch { /* ignore */ }
}

async function runDiff() {
    const aId = ($("#snapshot-select-a") || {}).value;
    const bId = ($("#snapshot-select-b") || {}).value;
    if (!aId) {
        appendOutput("[!] Select snapshot A to compare", "output-warn");
        return;
    }
    try {
        let url = `/api/diff?a=${aId}`;
        if (bId) url += `&b=${bId}`;
        const data = await api(url);
        renderDiff(data.diff || {});
    } catch (err) {
        appendOutput(`[!] Diff failed: ${err.message}`, "output-error");
    }
}

function renderDiff(diff) {
    const container = $("#diff-results");
    if (!container) return;

    let html = "";
    for (const category of ["subdomains", "urls", "hosts", "findings"]) {
        const d = diff[category] || {added: [], removed: []};
        const added = d.added || [];
        const removed = d.removed || [];
        if (added.length === 0 && removed.length === 0) continue;

        html += `<div class="diff-category">`;
        html += `<h3>${category} <span class="output-stderr">(+${added.length} / -${removed.length})</span></h3>`;
        if (added.length > 0) {
            html += `<ul class="diff-list diff-added">`;
            for (const item of added.slice(0, 100)) {
                const label = typeof item === "string" ? item : `${item.url} [${item.template_id}]`;
                html += `<li>+ ${esc(label)}</li>`;
            }
            if (added.length > 100) html += `<li class="output-stderr">... and ${added.length - 100} more</li>`;
            html += `</ul>`;
        }
        if (removed.length > 0) {
            html += `<ul class="diff-list diff-removed">`;
            for (const item of removed.slice(0, 100)) {
                const label = typeof item === "string" ? item : `${item.url} [${item.template_id}]`;
                html += `<li>- ${esc(label)}</li>`;
            }
            if (removed.length > 100) html += `<li class="output-stderr">... and ${removed.length - 100} more</li>`;
            html += `</ul>`;
        }
        html += `</div>`;
    }

    if (!html) {
        html = '<span class="output-stderr">No differences found</span>';
    }
    container.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", init);
