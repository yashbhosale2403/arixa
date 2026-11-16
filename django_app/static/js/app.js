/**
 * ARIXA Forensic Timeline - Client Controller (Django Edition)
 */

document.addEventListener("DOMContentLoaded", () => {
  // Theme Management
  const themeToggle = document.getElementById("theme-toggle");
  const savedTheme = localStorage.getItem("arixa_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcon(savedTheme);

  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("arixa_theme", next);
      updateThemeIcon(next);
      if (window.timelineChart) {
        updateChartTheme(next);
      }
    });
  }

  function updateThemeIcon(theme) {
    if (!themeToggle) return;
    themeToggle.innerHTML = theme === "dark" ? "&#9728;&#65039; Light mode" : "&#127769; Dark mode";
  }

  // Navigation Tabs
  const navItems = document.querySelectorAll(".nav-item");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navItems.forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-tab");
      navItems.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.style.display = "none");

      btn.classList.add("active");
      const activePane = document.getElementById(`tab-${target}`);
      if (activePane) {
        activePane.style.display = "block";
      }

      if (target === "overview") {
        renderInteractiveAttackGraph();
      }
      if (target === "timeline") {
        fetchTimelineEvents();
      }
    });
  });

  // Filter State
  const searchInput = document.getElementById("filter-search");
  const ipSelect = document.getElementById("filter-ip");
  const userSelect = document.getElementById("filter-user");
  const sourceSelect = document.getElementById("filter-source");
  const sevPills = document.querySelectorAll(".sev-pill");
  const btnReset = document.getElementById("btn-reset-filters");

  let activeSeverities = [];

  // Apply live filters across Timeline, Detections, and Overview
  function applyLiveFilters(autoSwitchTab = true) {
    if (autoSwitchTab) {
      const activeNav = document.querySelector('.nav-item.active');
      const activeTab = activeNav ? activeNav.getAttribute('data-tab') : '';
      // If user is on overview or evidence or validation, switch to timeline so they instantly see filtered events!
      if (activeTab === 'overview' || activeTab === 'evidence' || activeTab === 'validation' || activeTab === 'parsing') {
        const timelineNav = document.querySelector('.nav-item[data-tab="timeline"]');
        if (timelineNav) timelineNav.click();
      }
    }
    fetchTimelineEvents();
    filterDetectionsLive();
    filterOverviewLive();
  }

  // Live filter for Detections Tab (Table & Cards)
  function filterDetectionsLive() {
    const q = (searchInput ? searchInput.value : "").trim().toLowerCase();
    const selectedIp = (ipSelect ? ipSelect.value : "").trim().toLowerCase();
    const selectedUser = (userSelect ? userSelect.value : "").trim().toLowerCase();
    const qDetections = (document.getElementById("detection-quick-filter") ? document.getElementById("detection-quick-filter").value : "").trim().toLowerCase();

    // 1. Filter table rows in Tab Detections
    const rows = document.querySelectorAll(".detection-table-row");
    let visibleCount = 0;
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      let match = true;

      // Severity check
      if (activeSeverities.length > 0) {
        const rowHasSev = activeSeverities.some(s => row.classList.contains(`table-row-${s.toLowerCase()}`) || text.includes(s.toLowerCase()));
        if (!rowHasSev) match = false;
      }
      // IP check
      if (match && selectedIp && !text.includes(selectedIp)) match = false;
      // User check
      if (match && selectedUser && !text.includes(selectedUser)) match = false;
      // Search query check (from sidebar or detections search)
      if (match && q && !text.includes(q)) match = false;
      if (match && qDetections && !text.includes(qDetections)) match = false;

      row.style.display = match ? "" : "none";
      if (match) visibleCount++;
    });

    // 2. Filter card items in Tab Detections
    const cards = document.querySelectorAll(".detection-card");
    cards.forEach(card => {
      const text = card.textContent.toLowerCase();
      let match = true;
      if (activeSeverities.length > 0) {
        const cardHasSev = activeSeverities.some(s => card.classList.contains(`card-sev-${s.toLowerCase()}`) || text.includes(s.toLowerCase()));
        if (!cardHasSev) match = false;
      }
      if (match && selectedIp && !text.includes(selectedIp)) match = false;
      if (match && selectedUser && !text.includes(selectedUser)) match = false;
      if (match && q && !text.includes(q)) match = false;
      if (match && qDetections && !text.includes(qDetections)) match = false;

      card.style.display = match ? "block" : "none";
    });

    // 3. Update detection count badge
    const countEl = document.getElementById("detection-count-badge");
    if (countEl) {
      countEl.textContent = `${visibleCount} alert${visibleCount === 1 ? '' : 's'}`;
    }
  }

  // Live filter for Overview Tab
  function filterOverviewLive() {
    const q = (searchInput ? searchInput.value : "").trim().toLowerCase();
    const selectedIp = (ipSelect ? ipSelect.value : "").trim().toLowerCase();
    const selectedUser = (userSelect ? userSelect.value : "").trim().toLowerCase();

    // Filter overview detections table
    const rows = document.querySelectorAll(".overview-detection-row");
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      let match = true;
      if (activeSeverities.length > 0) {
        const rowHasSev = activeSeverities.some(s => row.classList.contains(`table-row-${s.toLowerCase()}`) || text.includes(s.toLowerCase()));
        if (!rowHasSev) match = false;
      }
      if (match && selectedIp && !text.includes(selectedIp)) match = false;
      if (match && selectedUser && !text.includes(selectedUser)) match = false;
      if (match && q && !text.includes(q)) match = false;

      row.style.display = match ? "" : "none";
    });
  }

  sevPills.forEach(pill => {
    pill.addEventListener("click", () => {
      pill.classList.toggle("active");
      const sev = pill.getAttribute("data-sev");
      if (pill.classList.contains("active")) {
        activeSeverities.push(sev);
      } else {
        activeSeverities = activeSeverities.filter(s => s !== sev);
      }
      applyLiveFilters(true);
    });
  });

  let searchTimeout = null;
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => applyLiveFilters(true), 300);
    });
  }

  if (ipSelect) ipSelect.addEventListener("change", () => applyLiveFilters(true));
  if (userSelect) userSelect.addEventListener("change", () => applyLiveFilters(true));
  if (sourceSelect) sourceSelect.addEventListener("change", () => applyLiveFilters(true));

  if (btnReset) {
    btnReset.addEventListener("click", () => {
      clearAllTimelineFilters();
    });
  }

  // Globally accessible filter cut & clear functions
  window.removeFilter = function(type, val) {
    if (type === "ip" && ipSelect) {
      ipSelect.value = "";
    } else if (type === "user" && userSelect) {
      userSelect.value = "";
    } else if (type === "q" && searchInput) {
      searchInput.value = "";
    } else if (type === "source" && sourceSelect) {
      sourceSelect.value = "";
    } else if (type === "sev") {
      if (val) {
        activeSeverities = activeSeverities.filter(s => s !== val);
        sevPills.forEach(p => {
          if (p.getAttribute("data-sev") === val) p.classList.remove("active");
        });
      } else {
        activeSeverities = [];
        sevPills.forEach(p => p.classList.remove("active"));
      }
    }
    applyLiveFilters(false);
  };

  window.clearAllTimelineFilters = function() {
    if (searchInput) searchInput.value = "";
    if (ipSelect) ipSelect.value = "";
    if (userSelect) userSelect.value = "";
    if (sourceSelect) sourceSelect.value = "";
    activeSeverities = [];
    sevPills.forEach(p => p.classList.remove("active"));
    applyLiveFilters(false);
  };

  // Fetch Timeline Events with Filters
  function fetchTimelineEvents() {
    const params = new URLSearchParams();
    if (searchInput && searchInput.value.trim()) params.set("q", searchInput.value.trim());
    if (ipSelect && ipSelect.value) params.set("ip", ipSelect.value);
    if (userSelect && userSelect.value) params.set("user", userSelect.value);
    if (sourceSelect && sourceSelect.value) params.set("source", sourceSelect.value);
    if (activeSeverities.length > 0) params.set("sev", activeSeverities.join(","));

    // Update filter chip count
    let filterCount = 0;
    if (searchInput && searchInput.value.trim()) filterCount++;
    if (ipSelect && ipSelect.value) filterCount++;
    if (userSelect && userSelect.value) filterCount++;
    if (sourceSelect && sourceSelect.value) filterCount++;
    filterCount += activeSeverities.length;

    const filterChip = document.getElementById("chip-filters");
    if (filterChip) {
      if (filterCount > 0) {
        filterChip.style.display = "inline-flex";
        filterChip.innerText = `${filterCount} filter(s) active \u2715`;
      } else {
        filterChip.style.display = "none";
      }
    }

    // Render Timeline Active Filters Bar with individual Cut buttons
    const banner = document.getElementById("timeline-filter-banner");
    const chipsContainer = document.getElementById("timeline-active-chips");
    const statusTag = document.getElementById("timeline-filter-status-tag");
    const quickClearBtn = document.getElementById("btn-quick-clear-timeline");

    const chips = [];
    if (ipSelect && ipSelect.value) {
      chips.push(`
        <span class="filter-cut-chip">
          <span style="color:var(--accent)">\uD83C\uDF10 IP:</span> <b>${escapeHtml(ipSelect.value)}</b>
          <button type="button" class="chip-cut-btn" onclick="removeFilter('ip')" title="Remove IP filter">&times;</button>
        </span>
      `);
    }
    if (userSelect && userSelect.value) {
      chips.push(`
        <span class="filter-cut-chip">
          <span style="color:#EC4899">\uD83D\uDC64 User:</span> <b>${escapeHtml(userSelect.value)}</b>
          <button type="button" class="chip-cut-btn" onclick="removeFilter('user')" title="Remove User filter">&times;</button>
        </span>
      `);
    }
    if (searchInput && searchInput.value.trim()) {
      chips.push(`
        <span class="filter-cut-chip">
          <span>\uD83D\uDD0D Query:</span> <i>"${escapeHtml(searchInput.value.trim())}"</i>
          <button type="button" class="chip-cut-btn" onclick="removeFilter('q')" title="Remove Search filter">&times;</button>
        </span>
      `);
    }
    if (sourceSelect && sourceSelect.value) {
      const sf = sourceSelect.value.split("/").pop();
      chips.push(`
        <span class="filter-cut-chip">
          <span>\uD83D\uDCC1 File:</span> <b>${escapeHtml(sf)}</b>
          <button type="button" class="chip-cut-btn" onclick="removeFilter('source')" title="Remove Source File filter">&times;</button>
        </span>
      `);
    }
    if (activeSeverities.length > 0) {
      activeSeverities.forEach(s => {
        chips.push(`
          <span class="filter-cut-chip">
            <span class="sev sev-${s.toLowerCase()}" style="font-size:0.68rem;padding:1px 5px">${escapeHtml(s)}</span>
            <button type="button" class="chip-cut-btn" onclick="removeFilter('sev', '${s}')" title="Remove ${s} filter">&times;</button>
          </span>
        `);
      });
    }

    if (banner && chipsContainer) {
      if (chips.length > 0) {
        banner.style.display = "flex";
        chipsContainer.innerHTML = chips.join("");
        if (statusTag) statusTag.style.display = "inline-block";
        if (quickClearBtn) quickClearBtn.style.display = "inline-flex";
      } else {
        banner.style.display = "none";
        chipsContainer.innerHTML = "";
        if (statusTag) statusTag.style.display = "none";
        if (quickClearBtn) quickClearBtn.style.display = "none";
      }
    }

    const tableBody = document.getElementById("timeline-table-body");
    const countSpan = document.getElementById("timeline-count");
    if (tableBody) {
      tableBody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--muted)">Loading timeline events...</td></tr>';
    }

    fetch(`/api/events/?${params.toString()}`)
      .then(r => r.json())
      .then(data => {
        if (countSpan) countSpan.innerText = `${data.count} of ${data.total} events`;

        if (!tableBody) return;
        if (!data.events || data.events.length === 0) {
          tableBody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:28px;color:var(--muted)">No events match the current filters.</td></tr>';
          return;
        }

        let html = "";
        data.events.forEach(e => {
          const sevClass = `sev-${(e.severity || "info").toLowerCase()}`;
          const rowClass = `table-row-${(e.severity || "info").toLowerCase()}`;
          const sourceBasename = e.source_file ? e.source_file.split("/").pop() : "";
          html += `
            <tr class="${rowClass}" onclick="openEventDetail(${e.id})">
              <td class="cell-id" style="text-align:center">#${e.id}</td>
              <td class="cell-time">
                <div style="font-weight:700;font-family:Consolas,monospace;color:var(--text);font-size:0.80rem">${e.timestamp_utc || ""}</div>
                <div style="font-size:0.71rem;display:flex;align-items:center;gap:6px;margin-top:3px;white-space:nowrap">
                  <span style="font-family:Consolas,monospace;color:#D97706;font-weight:600" title="Raw local log timestamp">${e.raw_time || ""}</span>
                  <span class="geo-pill" title="${escapeHtml(e.location || e.country || '')}">${e.flag || "🌐"} ${escapeHtml(e.country_short || e.country || "")}</span>
                </div>
              </td>
              <td style="width:88px;min-width:88px;text-align:center;white-space:nowrap"><span class="sev ${sevClass}">${e.severity || "INFO"}</span></td>
              <td style="max-width:180px;word-break:break-word" title="${escapeHtml(e.source_file || "")}">
                <div style="font-weight:600;font-size:0.78rem;color:var(--text);display:flex;align-items:center;gap:4px">
                  <span>${e.flag || "🌐"}</span>
                  <span>${escapeHtml(e.location || sourceBasename)}</span>
                </div>
                <div style="font-size:0.70rem;color:var(--muted);display:flex;align-items:center;gap:4px;margin-top:2px;flex-wrap:wrap">
                  <span style="overflow:hidden;text-overflow:ellipsis">${escapeHtml(sourceBasename)}</span>
                  ${e.log_format ? `<span style="font-size:0.65rem;padding:1px 4px;background:var(--surface);border:1px solid var(--border);border-radius:3px">${escapeHtml(e.log_format)}</span>` : ""}
                </div>
              </td>
              <td class="cell-ip">${e.source_ip || "-"}</td>
              <td class="cell-user">${e.username || "-"}</td>
              <td style="font-size:0.83rem;line-height:1.45;word-break:break-word">${escapeHtml(e.event_summary || e.raw_log || "")}</td>
            </tr>
          `;
        });
        tableBody.innerHTML = html;

        // Render Chart
        renderTimelineChart(data.buckets);
      })
      .catch(err => {
        console.error("Error fetching timeline events:", err);
        if (tableBody) {
          tableBody.innerHTML = `<tr><td colspan="8" style="color:var(--s-crit);text-align:center;padding:20px">Error loading events: ${err}</td></tr>`;
        }
      });
  }

  // Chart Rendering
  function renderTimelineChart(buckets) {
    const canvas = document.getElementById("timeline-chart");
    if (!canvas || !window.Chart) return;

    if (!buckets || buckets.length === 0) {
      canvas.style.display = "none";
      return;
    }
    canvas.style.display = "block";

    const labels = buckets.map(b => b.time.replace("T", " ").replace(":00Z", "Z"));
    const critical = buckets.map(b => b.CRITICAL || 0);
    const high = buckets.map(b => b.HIGH || 0);
    const warn = buckets.map(b => b.WARN || 0);
    const info = buckets.map(b => b.INFO || 0);

    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    const gridColor = isLight ? "rgba(0,0,0,0.06)" : "rgba(255,255,255,0.06)";
    const textColor = isLight ? "#475569" : "#94A3B8";

    if (window.timelineChart) {
      window.timelineChart.destroy();
    }

    const ctx = canvas.getContext("2d");
    window.timelineChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          { label: "CRITICAL", data: critical, backgroundColor: "#EF4444", borderRadius: 2 },
          { label: "HIGH", data: high, backgroundColor: "#F97316", borderRadius: 2 },
          { label: "WARN", data: warn, backgroundColor: "#EAB308", borderRadius: 2 },
          { label: "INFO", data: info, backgroundColor: "#64748B", borderRadius: 2 },
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: { color: textColor, font: { family: "Inter", size: 11 } }
          },
          tooltip: { mode: "index", intersect: false }
        },
        scales: {
          x: {
            stacked: true,
            grid: { color: gridColor },
            ticks: { color: textColor, font: { family: "Consolas", size: 10 } }
          },
          y: {
            stacked: true,
            grid: { color: gridColor },
            ticks: { color: textColor, precision: 0 }
          }
        }
      }
    });
  }

  function updateChartTheme(theme) {
    if (!window.timelineChart) return;
    const isLight = theme === "light";
    const gridColor = isLight ? "rgba(0,0,0,0.06)" : "rgba(255,255,255,0.06)";
    const textColor = isLight ? "#475569" : "#94A3B8";

    window.timelineChart.options.scales.x.grid.color = gridColor;
    window.timelineChart.options.scales.x.ticks.color = textColor;
    window.timelineChart.options.scales.y.grid.color = gridColor;
    window.timelineChart.options.scales.y.ticks.color = textColor;
    window.timelineChart.options.plugins.legend.labels.color = textColor;
    window.timelineChart.update();
  }

  // Interactive Threat Actor Attack Graph (Canvas with Drag & Drop stretching lines)
  let attackNetwork = null;
  let isPhysicsEnabled = true;

  function renderInteractiveAttackGraph() {
    const container = document.getElementById("attack-graph-canvas");
    if (!container || !window.vis) return;

    fetch("/api/attack-graph-data/")
      .then(r => r.json())
      .then(data => {
        if (!data.nodes || data.nodes.length === 0) {
          container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted);font-size:0.9rem">No attacker activity in current view.</div>';
          return;
        }

        const nodes = new vis.DataSet(data.nodes);
        const edges = new vis.DataSet(data.edges);

        const isLight = document.documentElement.getAttribute("data-theme") === "light";
        const edgeFontBg = isLight ? "#FFFFFF" : "#0F172A";
        const edgeFontColor = isLight ? "#1E293B" : "#E2E8F0";

        // Update edge fonts based on theme
        data.edges.forEach(e => {
          if (e.font) {
            e.font.background = edgeFontBg;
            e.font.color = edgeFontColor;
          }
        });

        const options = {
          autoResize: true,
          interaction: {
            hover: true,
            dragNodes: true,
            dragView: true,
            zoomView: true,
            navigationButtons: false,
            keyboard: false,
          },
          physics: {
            enabled: isPhysicsEnabled,
            solver: "barnesHut",
            barnesHut: {
              gravitationalConstant: -4000,
              centralGravity: 0.22,
              springLength: 170,
              springConstant: 0.04,
              damping: 0.12,
              avoidOverlap: 0.4
            },
            stabilization: {
              iterations: 150,
              updateInterval: 25
            }
          },
          nodes: {
            shape: "box",
            borderWidth: 2,
            shadow: true,
            chosen: {
              node: (values, id, selected, hovering) => {
                values.borderWidth = 3;
                values.shadow = true;
              }
            }
          },
          edges: {
            width: 2,
            shadow: true,
            arrows: {
              to: { enabled: true, scaleFactor: 0.85 }
            },
            selectionWidth: 3,
            hoverWidth: 2.5
          }
        };

        if (attackNetwork) {
          attackNetwork.destroy();
        }

        attackNetwork = new vis.Network(container, { nodes, edges }, options);

        // Zoom limits (Min: 0.35x, Max: 2.0x)
        const MIN_ZOOM = 0.35;
        const MAX_ZOOM = 2.0;

        let isAdjustingZoom = false;
        attackNetwork.on("zoom", function(params) {
          if (isAdjustingZoom) return;
          if (params.scale < MIN_ZOOM) {
            isAdjustingZoom = true;
            attackNetwork.moveTo({ scale: MIN_ZOOM });
            setTimeout(() => { isAdjustingZoom = false; }, 50);
          } else if (params.scale > MAX_ZOOM) {
            isAdjustingZoom = true;
            attackNetwork.moveTo({ scale: MAX_ZOOM });
            setTimeout(() => { isAdjustingZoom = false; }, 50);
          }
        });

        // Click handler for threat actor graph elements (Nodes & Edges)
        attackNetwork.on("click", function(params) {
          if (params.nodes && params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            openGraphElementDetail({ type: "node", id: nodeId });
          } else if (params.edges && params.edges.length > 0) {
            const edgeId = params.edges[0];
            const edgeObj = edges.get(edgeId);
            if (edgeObj) {
              openGraphElementDetail({ type: "edge", from: edgeObj.from, to: edgeObj.to });
            }
          }
        });

        // Bind interactive canvas control buttons
        const btnFit = document.getElementById("btn-graph-fit");
        const btnZoomIn = document.getElementById("btn-graph-zoom-in");
        const btnZoomOut = document.getElementById("btn-graph-zoom-out");
        const btnPhysics = document.getElementById("btn-graph-physics");

        if (btnFit) {
          btnFit.onclick = () => {
            attackNetwork.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } });
          };
        }

        if (btnZoomIn) {
          btnZoomIn.onclick = () => {
            const currentScale = attackNetwork.getScale();
            const nextScale = Math.min(currentScale * 1.25, MAX_ZOOM);
            attackNetwork.moveTo({ scale: nextScale, animation: { duration: 200 } });
          };
        }

        if (btnZoomOut) {
          btnZoomOut.onclick = () => {
            const currentScale = attackNetwork.getScale();
            const nextScale = Math.max(currentScale * 0.8, MIN_ZOOM);
            attackNetwork.moveTo({ scale: nextScale, animation: { duration: 200 } });
          };
        }

        if (btnPhysics) {
          btnPhysics.onclick = () => {
            isPhysicsEnabled = !isPhysicsEnabled;
            attackNetwork.setOptions({ physics: { enabled: isPhysicsEnabled } });
            btnPhysics.innerHTML = isPhysicsEnabled ? "&#9889; Physics: On" : "&#128204; Fixed: Physics Off";
            btnPhysics.style.color = isPhysicsEnabled ? "var(--text)" : "var(--s-warn)";
          };
        }
      })
      .catch(err => {
        console.error("Error loading interactive attack graph:", err);
        container.innerHTML = `<div class="note" style="border-left-color:#EF4444">Error loading attack graph: ${err}</div>`;
      });
  }

  // Event Detail Drawer / Modal
  window.openEventDetail = function(eventId) {
    const drawer = document.getElementById("event-drawer");
    const drawerContent = document.getElementById("drawer-content");
    if (!drawer || !drawerContent) return;

    drawer.classList.add("active");
    drawerContent.innerHTML = '<div style="color:var(--muted);padding:20px;text-align:center">Loading event details...</div>';

    fetch(`/api/event/${eventId}/`)
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          drawerContent.innerHTML = `<div class="note" style="border-left-color:#EF4444">${data.error}</div>`;
          return;
        }

        const e = data.event;
        const sevClass = `sev-${(e.severity || "info").toLowerCase()}`;

        let linkedDetectionsHtml = "";
        if (data.linked_detections && data.linked_detections.length > 0) {
          data.linked_detections.forEach(d => {
            linkedDetectionsHtml += `
              <div style="margin-bottom:8px;padding:8px;background:var(--surface2);border-radius:6px;border:1px solid var(--border)">
                <span class="sev sev-${(d.severity || "info").toLowerCase()}">${d.severity}</span>
                <span class="mitre" style="margin-left:6px">${d.mitre}</span>
                <span style="font-weight:600;margin-left:6px">${escapeHtml(d.title)}</span>
                <div style="font-size:0.78rem;color:var(--muted);margin-top:4px">${escapeHtml(d.description)}</div>
              </div>
            `;
          });
        } else {
          linkedDetectionsHtml = '<div style="font-size:0.8rem;color:var(--muted)">None (normal event)</div>';
        }

        drawerContent.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:12px">
            <h3 style="font-size:1.15rem;font-weight:700">Event #${e.id} &nbsp;<span class="sev ${sevClass}">${e.severity}</span></h3>
            <button onclick="closeDrawer()" class="btn btn-secondary" style="padding:4px 10px">&times;</button>
          </div>

          <div class="time-origin-card">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <span class="section" style="margin:0;color:var(--text);font-weight:700">Forensic Timestamps</span>
              <span class="geo-badge">${e.flag || "🌐"} ${escapeHtml(e.country || "Global")}</span>
            </div>

            <div class="time-card-grid">
              <div class="time-box time-utc">
                <div class="time-lbl"><span>🌐</span> Normalized (UTC)</div>
                <div class="time-val">${escapeHtml(e.timestamp_utc || "—")}</div>
                <div class="time-sub" style="font-family:Consolas,monospace;font-size:0.75rem">${escapeHtml(e.formula || "Cross-system timeline aligned")}</div>
              </div>

              <div class="time-box time-raw">
                <div class="time-lbl"><span>🕒</span> Raw Local Log Time</div>
                <div class="time-val">${escapeHtml(e.raw_time || "—")}</div>
                <div class="time-sub">${escapeHtml(e.offset || "Local system time")}${e.raw_offset_badge ? ` &bull; ${escapeHtml(e.raw_offset_badge)}` : ""}</div>
              </div>
            </div>

            <div class="geo-meta-row">
              <div class="geo-meta-item">
                <div class="geo-meta-label">Collection Location</div>
                <div class="geo-meta-val">${e.flag || "🌐"} ${escapeHtml(e.location || e.country || "Unknown")}</div>
              </div>
              <div class="geo-meta-item">
                <div class="geo-meta-label">Configured Timezone</div>
                <div class="geo-meta-val">${escapeHtml(e.timezone || "UTC")}</div>
              </div>
              <div class="geo-meta-item">
                <div class="geo-meta-label">Clock Skew / Drift</div>
                <div class="geo-meta-val" style="color:${e.skew_text && e.skew_text.startsWith("+") ? "var(--s-warn)" : "var(--ok-fg)"}">
                  ${escapeHtml(e.skew_text || "0s (Synchronized)")}
                </div>
              </div>
              <div class="geo-meta-item">
                <div class="geo-meta-label">Target Host</div>
                <div class="geo-meta-val" style="font-family:Consolas,monospace;font-weight:700;color:var(--text)">${escapeHtml(e.host || "—")}</div>
              </div>
            </div>

            ${e.tz_note ? `
            <div style="margin-top:10px;padding:6px 10px;border-radius:6px;font-size:0.78rem;display:flex;align-items:center;gap:6px;background:${e.tz_verified ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)'};border:1px solid ${e.tz_verified ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'};color:${e.tz_verified ? 'var(--ok-fg)' : 'var(--s-crit)'}">
              <span>${escapeHtml(e.tz_note)}</span>
            </div>
            ` : ''}
          </div>

          <div class="kv" style="margin-top:12px">
            <div class="k">Severity</div><div class="v"><span class="sev ${sevClass}">${e.severity}</span></div>
            <div class="k">Source IP</div><div class="v" style="color:var(--accent);font-weight:600">${e.source_ip || "—"}</div>
            <div class="k">Username</div><div class="v" style="font-weight:600">${e.username || "—"}</div>
            <div class="k">Program</div><div class="v">${e.program || "—"}</div>
            <div class="k">PID</div><div class="v">${e.pid || "—"}</div>
            <div class="k">Source File</div><div class="v" style="font-size:0.75rem">${escapeHtml(e.source_file || "—")}</div>
          </div>

          <div class="section" style="margin-top:14px;margin-bottom:6px">&#128269; Event Summary</div>
          <div style="padding:10px 14px;background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;font-size:0.86rem;line-height:1.5;font-weight:500;color:var(--text)">
            ${escapeHtml(e.event_summary || "")}
          </div>

          <div class="raw-log-header">
            <div class="raw-log-title">
              <span class="raw-log-icon">&#128220;</span>
              <span>Raw Log Line</span>
              <span class="raw-log-badge">${(e.raw_log || "").length} chars</span>
              ${e.log_format ? `<span class="raw-log-badge raw-log-badge-format">${escapeHtml(e.log_format)}</span>` : ""}
            </div>
            <button type="button" class="btn-copy-raw" onclick="copyRawLogToClipboard(this)" title="Copy pristine raw log line to clipboard">
              <span class="copy-icon">&#128203;</span> <span class="copy-text">Copy</span>
            </button>
          </div>
          <div class="raw-log-box">
            <code class="raw-log-code" id="drawer-raw-log-content">${escapeHtml(e.raw_log || "")}</code>
          </div>

          <div class="section" style="margin-top:14px">Part of Detections</div>
          ${linkedDetectionsHtml}

          <div class="section" style="margin-top:14px">Pivot the Dashboard</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            ${e.source_ip ? `<button onclick="pivotFilter('ip', '${e.source_ip}')" class="btn btn-secondary" style="font-size:0.78rem">&#128269; Filter on IP: ${e.source_ip}</button>` : ""}
            ${e.username ? `<button onclick="pivotFilter('user', '${e.username}')" class="btn btn-secondary" style="font-size:0.78rem">&#128269; Filter on User: ${e.username}</button>` : ""}
          </div>
        `;
      });
  };

  window.closeDrawer = function() {
    const drawer = document.getElementById("event-drawer");
    if (drawer) drawer.classList.remove("active");
  };

  window.copyRawLogToClipboard = function(btn) {
    const codeEl = document.getElementById("drawer-raw-log-content");
    if (!codeEl) return;
    const text = codeEl.textContent;
    const doSuccess = () => {
      const icon = btn.querySelector(".copy-icon");
      const lbl = btn.querySelector(".copy-text");
      if (lbl) lbl.textContent = "Copied!";
      if (icon) icon.innerHTML = "&#10003;";
      btn.style.color = "var(--ok-fg)";
      btn.style.borderColor = "var(--ok-fg)";
      setTimeout(() => {
        if (lbl) lbl.textContent = "Copy";
        if (icon) icon.innerHTML = "&#128203;";
        btn.style.color = "";
        btn.style.borderColor = "";
      }, 2000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(doSuccess).catch(() => {
        fallbackCopy(text, doSuccess);
      });
    } else {
      fallbackCopy(text, doSuccess);
    }
  };

  function fallbackCopy(text, cb) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      cb();
    } catch (err) {
      console.warn("Copy fallback failed:", err);
    }
    document.body.removeChild(ta);
  }

  const drawerOverlay = document.getElementById("event-drawer");
  if (drawerOverlay) {
    drawerOverlay.addEventListener("click", function(e) {
      if (e.target === drawerOverlay) closeDrawer();
    });
  }

  window.pivotFilter = function(key, val) {
    if (key === "ip" && ipSelect) ipSelect.value = val;
    if (key === "user" && userSelect) userSelect.value = val;
    closeDrawer();

    // Switch to timeline tab
    const timelineNav = document.querySelector('.nav-item[data-tab="timeline"]');
    if (timelineNav) timelineNav.click();
    fetchTimelineEvents();
  };

  window.searchHost = function(hostname) {
    if (searchInput) searchInput.value = hostname;
    closeDrawer();
    const timelineNav = document.querySelector('.nav-item[data-tab="timeline"]');
    if (timelineNav) timelineNav.click();
    fetchTimelineEvents();
  };

  // Detailed Intelligence Drawer for Attack Graph Elements (Nodes & Edges)
  window.openGraphElementDetail = function(params) {
    const drawer = document.getElementById("event-drawer");
    const drawerContent = document.getElementById("drawer-content");
    if (!drawer || !drawerContent) return;

    drawer.classList.add("active");
    drawerContent.innerHTML = '<div style="color:var(--muted);padding:30px 20px;text-align:center"><div class="loading-spin" style="margin:0 auto 10px;width:24px;height:24px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%"></div>Loading threat intelligence...</div>';

    let url = "/api/attack-graph-element/?";
    if (params.type === "node") {
      url += "node_id=" + encodeURIComponent(params.id);
    } else if (params.type === "edge") {
      url += "edge_from=" + encodeURIComponent(params.from) + "&edge_to=" + encodeURIComponent(params.to);
    }

    fetch(url)
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          drawerContent.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:12px">
              <h3 style="font-size:1.15rem;font-weight:700">Threat Element Details</h3>
              <button onclick="closeDrawer()" class="btn btn-secondary" style="padding:4px 10px">&times;</button>
            </div>
            <div class="note" style="border-left-color:#EF4444;margin-top:14px">${escapeHtml(data.error)}</div>
          `;
          return;
        }

        if (data.type === "edge") {
          renderEdgeDetail(data, drawerContent);
        } else {
          renderNodeDetail(data, drawerContent);
        }
      })
      .catch(err => {
        console.error("Error fetching graph element detail:", err);
        drawerContent.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:12px">
            <h3 style="font-size:1.15rem;font-weight:700">Threat Element Details</h3>
            <button onclick="closeDrawer()" class="btn btn-secondary" style="padding:4px 10px">&times;</button>
          </div>
          <div class="note" style="border-left-color:#EF4444;margin-top:14px">Failed to load details: ${escapeHtml(err.message || String(err))}</div>
        `;
      });
  };

  function renderNodeDetail(data, container) {
    const kindBadges = {
      attacker: { label: "🚨 Attacker IP", sevClass: "sev-critical" },
      pivot: { label: "🏢 Internal Pivot", sevClass: "sev-high" },
      target: { label: "💻 Target Host", sevClass: "sev-warn" },
      privileged: { label: "👑 Privileged Account", sevClass: "sev-critical" },
      compromised: { label: "👤 User Account", sevClass: "sev-high" },
      shell: { label: "🐚 Malicious Web Shell", sevClass: "sev-critical" },
    };
    const badge = kindBadges[data.kind] || { label: "Threat Element", sevClass: "sev-info" };
    const displayLabel = data.label ? data.label.replace(/\n/g, " - ") : data.id;

    // Relationships HTML
    let relsHtml = "";
    if (data.relationships && data.relationships.length > 0) {
      data.relationships.forEach(rel => {
        const actionsHtml = (rel.actions || []).map(a => `<span style="display:inline-block;padding:2px 7px;background:var(--surface);border-radius:4px;border:1px solid var(--border);margin:2px 4px 2px 0;font-size:0.75rem">${escapeHtml(a)}</span>`).join("");
        relsHtml += `
          <div style="padding:8px 10px;background:var(--surface2);border-radius:6px;border:1px solid var(--border);margin-bottom:6px">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <div>
                <span style="font-weight:700;color:var(--accent);font-size:0.8rem">${rel.direction}</span>
                <span style="font-family:Consolas,monospace;font-size:0.82rem;font-weight:600;margin-left:6px">${escapeHtml(rel.other_node.replace(/\n/g, ' '))}</span>
              </div>
              <span class="sev sev-${(rel.severity || "info").toLowerCase()}">${rel.severity}</span>
            </div>
            ${actionsHtml ? `<div style="margin-top:4px">${actionsHtml}</div>` : ""}
          </div>
        `;
      });
    } else {
      relsHtml = '<div style="font-size:0.8rem;color:var(--muted)">No additional direct hops.</div>';
    }

    // Detections HTML
    let detsHtml = "";
    if (data.detections && data.detections.length > 0) {
      data.detections.forEach(d => {
        detsHtml += `
          <div style="margin-bottom:8px;padding:8px;background:var(--surface2);border-radius:6px;border:1px solid var(--border)">
            <span class="sev sev-${(d.severity || "info").toLowerCase()}">${d.severity}</span>
            <span class="mitre" style="margin-left:6px">${d.mitre}</span>
            <span style="font-weight:600;margin-left:6px;font-size:0.83rem">${escapeHtml(d.title)}</span>
            <div style="font-size:0.78rem;color:var(--muted);margin-top:4px">${escapeHtml(d.description)}</div>
          </div>
        `;
      });
    } else {
      detsHtml = '<div style="font-size:0.8rem;color:var(--muted)">No direct MITRE detection rules triggered.</div>';
    }

    // Sample Events Table HTML
    let eventsHtml = "";
    if (data.sample_events && data.sample_events.length > 0) {
      eventsHtml = `
        <div style="max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;background:var(--surface2)">
          <table style="width:100%;border-collapse:collapse;font-size:0.78rem">
            <thead>
              <tr style="border-bottom:1px solid var(--border);background:var(--surface);color:var(--muted);text-align:left">
                <th style="padding:6px 8px">ID</th>
                <th style="padding:6px 8px">Time (UTC)</th>
                <th style="padding:6px 8px">Sev</th>
                <th style="padding:6px 8px">Summary</th>
              </tr>
            </thead>
            <tbody>
              ${data.sample_events.map(ev => `
                <tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="openEventDetail(${ev.id})" title="Click to view full event #${ev.id}">
                  <td style="padding:6px 8px;color:var(--accent);font-weight:700">#${ev.id}</td>
                  <td style="padding:6px 8px;white-space:nowrap;font-family:Consolas,monospace">${escapeHtml(ev.timestamp_utc || ev.time || "")}</td>
                  <td style="padding:6px 8px"><span class="sev sev-${(ev.severity || "info").toLowerCase()}">${ev.severity}</span></td>
                  <td style="padding:6px 8px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(ev.event_summary || "")}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else {
      eventsHtml = '<div style="font-size:0.8rem;color:var(--muted)">No matching timeline events.</div>';
    }

    // Geo Card
    let geoHtml = "";
    if (data.geo && (data.geo.country || data.geo.location)) {
      geoHtml = `
        <div class="time-origin-card" style="margin-top:12px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span class="section" style="margin:0;color:var(--text);font-weight:700">Geographic & System Origin</span>
            <span class="geo-badge">${data.geo.flag || "🌐"} ${escapeHtml(data.geo.country || "Global")}</span>
          </div>
          <div class="geo-meta-row" style="margin-top:8px">
            <div class="geo-meta-item">
              <div class="geo-meta-label">Location</div>
              <div class="geo-meta-val">${data.geo.flag || "🌐"} ${escapeHtml(data.geo.location || data.geo.country || "Unknown")}</div>
            </div>
            <div class="geo-meta-item">
              <div class="geo-meta-label">Timezone</div>
              <div class="geo-meta-val">${escapeHtml(data.geo.timezone || "UTC")}</div>
            </div>
            <div class="geo-meta-item">
              <div class="geo-meta-label">Activity Window</div>
              <div class="geo-meta-val" style="font-size:0.75rem">${escapeHtml(data.first_seen)} &rarr; ${escapeHtml(data.last_seen)}</div>
            </div>
            <div class="geo-meta-item">
              <div class="geo-meta-label">Correlated Events</div>
              <div class="geo-meta-val" style="font-weight:700;color:var(--accent)">${data.events_count}</div>
            </div>
          </div>
        </div>
      `;
    }

    // Pivot buttons
    let pivotBtns = "";
    if (data.prefix === "ip") {
      const pureIp = data.id.replace("ip:", "");
      pivotBtns += `<button onclick="pivotFilter('ip', '${pureIp}')" class="btn btn-secondary" style="font-size:0.78rem">&#128269; Filter Timeline on IP: ${pureIp}</button>`;
    } else if (data.prefix === "acct") {
      const pureUser = data.id.split(":").pop();
      pivotBtns += `<button onclick="pivotFilter('user', '${pureUser}')" class="btn btn-secondary" style="font-size:0.78rem">&#128269; Filter Timeline on User: ${pureUser}</button>`;
    } else if (data.prefix === "host") {
      const pureHost = data.label.split("\n")[0].trim();
      pivotBtns += `<button onclick="searchHost('${pureHost}')" class="btn btn-secondary" style="font-size:0.78rem">&#128269; Search Timeline for Host: ${pureHost}</button>`;
    }

    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid var(--border);padding-bottom:12px">
        <div>
          <div style="display:flex;align-items:center;gap:8px">
            <span class="sev ${badge.sevClass}">${badge.label}</span>
          </div>
          <h3 style="font-size:1.15rem;font-weight:700;margin-top:6px;font-family:Consolas,monospace;word-break:break-all">
            ${escapeHtml(displayLabel)}
          </h3>
        </div>
        <button onclick="closeDrawer()" class="btn btn-secondary" style="padding:4px 10px">&times;</button>
      </div>

      <div style="margin-top:12px;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;font-size:0.82rem;line-height:1.5">
        ${escapeHtml(data.role_description)}
      </div>

      ${geoHtml}

      <div class="section" style="margin-top:14px">Attack Graph Relationships (${(data.relationships || []).length})</div>
      ${relsHtml}

      <div class="section" style="margin-top:14px">Triggered Detections (${(data.detections || []).length})</div>
      ${detsHtml}

      <div class="section" style="margin-top:14px">Correlated Events (${data.events_count} total, showing ${Math.min(15, (data.sample_events || []).length)})</div>
      ${eventsHtml}

      ${pivotBtns ? `
        <div class="section" style="margin-top:14px">Forensic Investigation Actions</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${pivotBtns}
        </div>
      ` : ""}
    `;
  }

  function renderEdgeDetail(data, container) {
    const sevClass = `sev-${(data.severity || "info").toLowerCase()}`;

    // Detections HTML
    let detsHtml = "";
    if (data.detections && data.detections.length > 0) {
      data.detections.forEach(d => {
        detsHtml += `
          <div style="margin-bottom:8px;padding:8px;background:var(--surface2);border-radius:6px;border:1px solid var(--border)">
            <span class="sev sev-${(d.severity || "info").toLowerCase()}">${d.severity}</span>
            <span class="mitre" style="margin-left:6px">${d.mitre}</span>
            <span style="font-weight:600;margin-left:6px;font-size:0.83rem">${escapeHtml(d.title)}</span>
            <div style="font-size:0.78rem;color:var(--muted);margin-top:4px">${escapeHtml(d.description)}</div>
          </div>
        `;
      });
    } else {
      detsHtml = '<div style="font-size:0.8rem;color:var(--muted)">No specific MITRE rule associated with this edge hop.</div>';
    }

    // Events HTML
    let eventsHtml = "";
    if (data.events && data.events.length > 0) {
      eventsHtml = `
        <div style="max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;background:var(--surface2)">
          <table style="width:100%;border-collapse:collapse;font-size:0.78rem">
            <thead>
              <tr style="border-bottom:1px solid var(--border);background:var(--surface);color:var(--muted);text-align:left">
                <th style="padding:6px 8px">ID</th>
                <th style="padding:6px 8px">Time (UTC)</th>
                <th style="padding:6px 8px">Sev</th>
                <th style="padding:6px 8px">Summary</th>
              </tr>
            </thead>
            <tbody>
              ${data.events.map(ev => `
                <tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="openEventDetail(${ev.id})" title="Click to view full event #${ev.id}">
                  <td style="padding:6px 8px;color:var(--accent);font-weight:700">#${ev.id}</td>
                  <td style="padding:6px 8px;white-space:nowrap;font-family:Consolas,monospace">${escapeHtml(ev.timestamp_utc || ev.time || "")}</td>
                  <td style="padding:6px 8px"><span class="sev sev-${(ev.severity || "info").toLowerCase()}">${ev.severity}</span></td>
                  <td style="padding:6px 8px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(ev.event_summary || "")}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else {
      eventsHtml = '<div style="font-size:0.8rem;color:var(--muted)">No direct timeline events matched.</div>';
    }

    const labelsHtml = (data.labels || []).map(l => `<span class="badge" style="background:var(--surface);border:1px solid var(--border);padding:3px 8px;border-radius:4px;font-size:0.78rem;font-weight:600">${escapeHtml(l)}</span>`).join(" ");

    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid var(--border);padding-bottom:12px">
        <div>
          <span class="sev ${sevClass}">Attack Vector / Action</span>
          <h3 style="font-size:1.05rem;font-weight:700;margin-top:6px;word-break:break-all">
            <span style="font-family:Consolas,monospace;color:var(--accent)">${escapeHtml(data.source_label.replace(/\n/g, ' '))}</span>
            &nbsp;&rarr;&nbsp;
            <span style="font-family:Consolas,monospace">${escapeHtml(data.target_label.replace(/\n/g, ' '))}</span>
          </h3>
        </div>
        <button onclick="closeDrawer()" class="btn btn-secondary" style="padding:4px 10px">&times;</button>
      </div>

      <div class="kv" style="margin-top:12px">
        <div class="k">Severity</div><div class="v"><span class="sev ${sevClass}">${data.severity}</span></div>
        <div class="k">Attack Actions</div><div class="v">${labelsHtml || "—"}</div>
        <div class="k">Linked Events</div><div class="v" style="font-weight:700;color:var(--accent)">${data.total_linked_events}</div>
      </div>

      <div class="section" style="margin-top:14px">Associated Detections (${(data.detections || []).length})</div>
      ${detsHtml}

      <div class="section" style="margin-top:14px">Correlated Evidence Events (${data.total_linked_events} total, showing ${Math.min(15, (data.events || []).length)})</div>
      ${eventsHtml}
    `;
  }

  // =========================================================================
  // Draggable Loading Modal & Live AI Analysis Pipeline
  // =========================================================================
  const loadingOverlay = document.getElementById("loading-overlay");
  const loadingModal = document.getElementById("loading-modal");
  const loadingHandle = document.getElementById("loading-drag-handle");
  const progressBar = document.getElementById("loading-progress-bar");
  const progressPercent = document.getElementById("loading-percentage");
  const stageText = document.getElementById("loading-stage-text");
  const aiSummaryText = document.getElementById("ai-live-summary-text");
  const aiChipEvents = document.getElementById("ai-chip-events");
  const aiChipAlerts = document.getElementById("ai-chip-alerts");
  const aiChipStatus = document.getElementById("ai-chip-status");

  // Draggable logic for loading modal
  if (loadingModal && loadingHandle) {
    makeDraggable(loadingModal, loadingHandle);
  }

  function makeDraggable(element, handle) {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
    handle.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
      e.preventDefault();
      pos3 = e.clientX;
      pos4 = e.clientY;
      document.onmouseup = closeDragElement;
      document.onmousemove = elementDrag;
    }

    function elementDrag(e) {
      e.preventDefault();
      pos1 = pos3 - e.clientX;
      pos2 = pos4 - e.clientY;
      pos3 = e.clientX;
      pos4 = e.clientY;
      element.style.top = (element.offsetTop - pos2) + "px";
      element.style.left = (element.offsetLeft - pos1) + "px";
      element.style.position = "fixed";
    }

    function closeDragElement() {
      document.onmouseup = null;
      document.onmousemove = null;
    }
  }

  function setStepStatus(stepId, status) {
    const el = document.getElementById(stepId);
    if (!el) return;
    el.classList.remove("active", "done");
    const icon = el.querySelector(".step-icon");
    if (status === "active") {
      el.classList.add("active");
      if (icon) icon.innerHTML = "&#9679;";
    } else if (status === "done") {
      el.classList.add("done");
      if (icon) icon.innerHTML = "&#10004;";
    } else {
      if (icon) icon.innerHTML = "&#9675;";
    }
  }

  function runForensicAnalysisSequence(fetchPromise, contextType) {
    if (!loadingOverlay) return;

    // Show overlay
    loadingOverlay.style.display = "flex";
    if (loadingModal) {
      loadingModal.style.top = "50%";
      loadingModal.style.left = "50%";
      loadingModal.style.transform = "translate(-50%, -50%)";
    }

    // Reset progress
    if (progressBar) progressBar.style.width = "6%";
    if (progressPercent) progressPercent.innerText = "6%";
    if (stageText) stageText.innerText = "Initializing forensic pipeline...";
    ["step-hash", "step-parse", "step-time", "step-detect", "step-graph"].forEach(id => setStepStatus(id, "pending"));

    if (aiChipEvents) aiChipEvents.innerText = "Events: analyzing...";
    if (aiChipAlerts) aiChipAlerts.innerText = "Detections: correlating...";
    if (aiChipStatus) aiChipStatus.innerText = "Integrity: Checking...";

    // Stage 1: Hashing
    setTimeout(() => {
      if (progressBar) progressBar.style.width = "22%";
      if (progressPercent) progressPercent.innerText = "22%";
      if (stageText) stageText.innerText = "Step 1/5: Hashing evidence & sealing read-only copies...";
      setStepStatus("step-hash", "active");
      if (aiSummaryText) {
        aiSummaryText.innerHTML = "<b>Zero-trust intake started.</b> Calculating 256-bit SHA-256 cryptographic hashes for log evidence and applying operating system read-only permissions...";
      }
    }, 120);

    // Stage 2: Parsing
    setTimeout(() => {
      if (progressBar) progressBar.style.width = "48%";
      if (progressPercent) progressPercent.innerText = "48%";
      if (stageText) stageText.innerText = "Step 2/5: Parsing Linux auth.log & Nginx access.log records...";
      setStepStatus("step-hash", "done");
      setStepStatus("step-parse", "active");
      if (aiSummaryText) {
        aiSummaryText.innerHTML = "<b>Stream parsing logs.</b> Tokenizing user authentication, SSH sessions, sudo commands, and HTTP request URIs. Tracking unparseable lines into parsing gaps...";
      }
    }, 600);

    // Stage 3: UTC Time Normalisation
    setTimeout(() => {
      if (progressBar) progressBar.style.width = "72%";
      if (progressPercent) progressPercent.innerText = "72%";
      if (stageText) stageText.innerText = "Step 3/5: Normalising timestamps to UTC & correcting clock drift...";
      setStepStatus("step-parse", "done");
      setStepStatus("step-time", "active");
      if (aiSummaryText) {
        aiSummaryText.innerHTML = "<b>Time synchronisation active.</b> Converting multi-server logs to standard UTC time. Compensating for server clock-drift offsets to place all actions in true physical order...";
      }
    }, 1100);

    // Stage 4: MITRE ATT&CK Rules & AI Live Insight
    setTimeout(() => {
      if (progressBar) progressBar.style.width = "90%";
      if (progressPercent) progressPercent.innerText = "90%";
      if (stageText) stageText.innerText = "Step 4/5: Correlating 8 MITRE ATT&CK detection rules...";
      setStepStatus("step-time", "done");
      setStepStatus("step-detect", "active");

      if (aiSummaryText) {
        if (contextType === "ssh") {
          aiSummaryText.innerHTML = "<b>Live Anomaly:</b> High-density streak of 15 failed SSH logins from <code>203.0.113.45</code> detected. Successful break-in on user <code>deploy</code> followed by <code>/etc/shadow</code> dump and backdoor account creation.";
        } else if (contextType === "web") {
          aiSummaryText.innerHTML = "<b>Live Anomaly:</b> Web scanning detected across 14 paths. Exploitation confirmed: SQL injection (<code>UNION SELECT</code>), path traversal, and malicious PHP webshell execution on <code>/uploads/shell.php</code>.";
        } else if (contextType === "multi") {
          aiSummaryText.innerHTML = "<b>Live Anomaly:</b> Cross-server lateral movement detected. London web shell activity followed by internal SSH login to New York database server and database exfiltration (<code>mysqldump</code>).";
        } else if (contextType === "clean") {
          aiSummaryText.innerHTML = "<b>Live Status:</b> Routine corporate server operations. Admins logged in via public keys, cron jobs ran cleanly. Zero anomalies or unauthorized access detected.";
        } else {
          aiSummaryText.innerHTML = "<b>Live Threat Correlation:</b> Evaluating sliding windows across event stream. Identifying brute force streaks, web exploit payloads, lateral movement, and privilege escalation...";
        }
      }
    }, 1600);

    // Backend completion
    fetchPromise
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          loadingOverlay.style.display = "none";
          alert("Ingest error: " + data.error);
          return;
        }

        const stats = data.stats || {};
        if (progressBar) progressBar.style.width = "100%";
        if (progressPercent) progressPercent.innerText = "100%";
        if (stageText) stageText.innerText = "Step 5/5: Threat graph generated & chain of custody signed!";
        ["step-hash", "step-parse", "step-time", "step-detect", "step-graph"].forEach(id => setStepStatus(id, "done"));

        if (aiChipEvents) aiChipEvents.innerText = `Events: ${stats.events || 0}`;
        if (aiChipAlerts) aiChipAlerts.innerText = `Detections: ${stats.detections || 0}`;
        if (aiChipStatus) aiChipStatus.innerText = "Integrity: VERIFIED";

        if (aiSummaryText) {
          if ((stats.detections || 0) > 0) {
            aiSummaryText.innerHTML = `<b>Analysis Complete:</b> Ingested <b>${stats.events} events</b> across <b>${stats.sources || 1} source(s)</b>. Correlated <b>${stats.detections} MITRE ATT&CK alert(s)</b>. Attack graph and audit report synthesized.`;
          } else {
            aiSummaryText.innerHTML = `<b>Analysis Complete:</b> Ingested <b>${stats.events} events</b>. All activity verified normal &mdash; zero security alerts found (0 false alarms).`;
          }
        }

        // Delay 700ms so user comfortably reads the live summary before view transition
        setTimeout(() => {
          window.location.reload();
        }, 750);
      })
      .catch(err => {
        loadingOverlay.style.display = "none";
        alert("Pipeline error: " + err);
      });
  }

  window.loadScenario = function(name) {
    const promise = fetch(`/api/load-scenario/${name}/`, { method: "POST" });
    runForensicAnalysisSequence(promise, name);
  };

  // =========================================================================
  // Live Evidence Tamper Detection, Verification, and Instant Restoration
  // =========================================================================
  function showForensicToast(msg, type = "info") {
    let container = document.getElementById("forensic-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "forensic-toast-container";
      container.style.cssText = "position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:10px;pointer-events:none;";
      document.body.appendChild(container);
    }
    const toast = document.createElement("div");
    const colors = {
      success: { bg: "#064E3B", border: "#10B981", text: "#A7F3D0", icon: "&#10004;" },
      danger: { bg: "#7F1D1D", border: "#EF4444", text: "#FECACA", icon: "&#128680;" },
      warning: { bg: "#78350F", border: "#F59E0B", text: "#FDE68A", icon: "&#9888;&#65039;" },
      info: { bg: "#1E293B", border: "#3B82F6", text: "#BFDBFE", icon: "&#8505;&#65039;" }
    };
    const c = colors[type] || colors.info;
    toast.style.cssText = `background:${c.bg};border:1.5px solid ${c.border};color:${c.text};padding:12px 18px;border-radius:8px;font-size:0.84rem;font-weight:600;box-shadow:0 10px 25px rgba(0,0,0,0.4);pointer-events:auto;display:flex;align-items:center;gap:10px;transition:all 0.3s cubic-bezier(0.16, 1, 0.3, 1);transform:translateY(20px);opacity:0;`;
    toast.innerHTML = `<span>${c.icon}</span> <span>${escapeHtml(msg)}</span>`;
    container.appendChild(toast);
    requestAnimationFrame(() => {
      toast.style.transform = "translateY(0)";
      toast.style.opacity = "1";
    });
    setTimeout(() => {
      toast.style.transform = "translateY(20px)";
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  function updateEvidenceUi(data) {
    if (!data) return;

    // 1. Update Header Chip
    const chipEvidence = document.getElementById("chip-evidence");
    if (chipEvidence) {
      if (data.all_ok) {
        chipEvidence.className = "chip ok";
        chipEvidence.innerHTML = `&#10004; ${data.total_files || (data.checks ? data.checks.length : 0)} evidence files intact`;
        chipEvidence.setAttribute("title", "Chain of Custody verified: all evidence files match original SHA-256 hashes");
      } else {
        chipEvidence.className = "chip bad";
        chipEvidence.innerHTML = `&#9888; TAMPER DETECTED (${data.tampered_count || 1})`;
        chipEvidence.setAttribute("title", "CRITICAL: Hash mismatch detected on evidence files on disk! Unauthorized modification.");
      }
    }

    // 2. Update Overview KPI Card
    const kpiVal = document.getElementById("kpi-evidence-val");
    const kpiSub = document.getElementById("kpi-evidence-sub");
    if (kpiVal) kpiVal.textContent = data.total_files || (data.manifest ? data.manifest.length : (data.checks ? data.checks.length : 0));
    if (kpiSub) {
      if (data.all_ok) {
        kpiSub.innerHTML = "SHA-256 verified";
        kpiSub.style.color = "";
      } else {
        kpiSub.innerHTML = `<span style="color:#EF4444;font-weight:700">&#9888; ${data.tampered_count || 1} TAMPERED</span>`;
      }
    }

    // 3. Update Evidence Integrity Status Banner
    const banner = document.getElementById("evidence-integrity-banner");
    if (banner) {
      if (data.all_ok) {
        banner.innerHTML = `
          <div class="note" style="border-left-color:var(--ok-fg);background:rgba(16,185,129,0.08);color:var(--text);padding:12px 16px;border-radius:8px">
            <span style="color:var(--ok-fg);font-weight:700">&#10004; Cryptographic Verification: 100% Intact</span> &mdash; All ${data.total_files || (data.checks ? data.checks.length : 0)} evidence files match their original SHA-256 manifest. Chain of Custody is tamper-free.
          </div>
        `;
      } else {
        banner.innerHTML = `
          <div class="note" style="border-left-color:var(--bad-fg);background:rgba(239,68,68,0.12);color:var(--text);padding:14px 18px;border-radius:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
            <div>
              <div style="color:var(--bad-fg);font-weight:800;font-size:0.95rem;display:flex;align-items:center;gap:6px">
                <span>&#9888;&#65039;</span> CRITICAL: EVIDENCE TAMPER DETECTED!
              </div>
              <div style="font-size:0.82rem;color:var(--text);margin-top:4px">
                ${data.tampered_count || 1} evidence file(s) fail SHA-256 verification against the ingestion manifest. Forensic integrity violation logged to Chain of Custody.
              </div>
            </div>
            <button onclick="restoreEvidenceFile('')" class="btn btn-primary" style="background:#10B981;border-color:#10B981;font-weight:700;padding:6px 14px">
              &#128737;&#65039; Fix Tamper &amp; Restore Pristine Files
            </button>
          </div>
        `;
      }
    }

    // 4. Update Evidence Manifest Table
    const manifestTbody = document.getElementById("evidence-manifest-tbody");
    if (manifestTbody && data.manifest && data.manifest.length > 0) {
      manifestTbody.innerHTML = data.manifest.map(m => {
        const isOk = m.status === "OK";
        const rowBg = isOk ? "" : "background:rgba(239,68,68,0.06)";
        const statusHtml = isOk
          ? `<span class="sev" style="background:rgba(16,185,129,0.15);color:#10B981;border-color:rgba(16,185,129,0.3);font-weight:700;padding:3px 8px;display:inline-block">&#10004; OK</span><div style="font-size:0.68rem;color:var(--muted);margin-top:4px">Verified Intact</div>`
          : `<span class="sev" style="background:#EF4444;color:#FFFFFF;border-color:#EF4444;font-weight:800;padding:3px 8px;display:inline-block">&#10006; TAMPER</span>
             <div style="font-size:0.68rem;color:#EF4444;font-weight:700;margin-top:4px">Hash Mismatch</div>
             <button type="button" class="btn btn-secondary btn-sm" onclick="restoreEvidenceFile('${escapeHtml(m.evidence_file)}')" style="margin-top:6px;padding:2px 8px;font-size:0.7rem;color:var(--ok-fg);border-color:var(--ok-bd);font-weight:600" title="Restore this pristine file">&#128737;&#65039; Restore</button>`;

        const shaHtml = isOk
          ? `<div style="background:var(--surface2);padding:7px 10px;border-radius:6px;border:1px solid var(--border);word-break:break-all;font-family:Consolas,monospace;font-size:0.73rem;line-height:1.45;color:var(--text);letter-spacing:0.02em">
               <div style="font-size:0.67rem;color:var(--muted);text-transform:uppercase;font-weight:700;margin-bottom:2px">SHA-256 Checksum</div>
               ${escapeHtml(m.sha256)}
             </div>`
          : `<div style="background:rgba(239,68,68,0.1);padding:8px 10px;border-radius:6px;border:1.5px solid rgba(239,68,68,0.4);word-break:break-all;font-family:Consolas,monospace;font-size:0.73rem;line-height:1.45">
               <div style="font-size:0.67rem;color:#EF4444;text-transform:uppercase;font-weight:800;margin-bottom:2px">&#9888; Expected (Manifest):</div>
               <div style="color:var(--text)">${escapeHtml(m.sha256)}</div>
               <div style="font-size:0.67rem;color:#EF4444;text-transform:uppercase;font-weight:800;margin-top:5px;margin-bottom:2px">&#10006; Actual on Disk (Altered):</div>
               <div style="color:#EF4444;font-weight:700">${escapeHtml(m.actual_sha256 || "TAMPERED FILE CONTENT")}</div>
             </div>`;

        return `
          <tr class="evidence-row" data-file="${escapeHtml(m.evidence_file)}" style="${rowBg}">
            <td style="text-align:center;vertical-align:middle">${statusHtml}</td>
            <td>
              <div style="font-family:Consolas,monospace;font-weight:700;font-size:0.83rem;color:var(--text);word-break:break-all;line-height:1.4">
                ${escapeHtml(m.source_label)}
              </div>
              <div style="font-family:Consolas,monospace;font-size:0.73rem;color:var(--muted);margin-top:5px;word-break:break-all;line-height:1.35">
                <span style="color:var(--accent);font-weight:600">&#128193; Read-Only Evidence Copy:</span> ${escapeHtml(m.evidence_file)}
              </div>
            </td>
            <td>${shaHtml}</td>
            <td>
              <div style="font-family:Consolas,monospace;font-size:0.74rem;line-height:1.35">
                <div style="color:var(--muted);font-size:0.67rem;text-transform:uppercase;font-weight:600">Collected (UTC)</div>
                <div>${escapeHtml(m.ingested_utc || "")}</div>
                <div style="color:var(--muted);font-size:0.67rem;text-transform:uppercase;font-weight:600;margin-top:5px">File Size</div>
                <div style="font-weight:600">${m.size_bytes} bytes</div>
              </div>
            </td>
          </tr>
        `;
      }).join("");
    }

    // 5. Update Custody Log Table
    const custodyTbody = document.getElementById("custody-log-tbody");
    if (custodyTbody && data.custody && data.custody.length > 0) {
      custodyTbody.innerHTML = data.custody.map(c => {
        let actionBadge = `<span style="color:var(--accent)">${escapeHtml(c.action)}</span>`;
        let rowStyle = "";
        if (c.action === "TAMPER_ALERT") {
          actionBadge = `<span style="color:#EF4444;font-weight:800;background:rgba(239,68,68,0.15);padding:2px 8px;border-radius:4px;border:1px solid rgba(239,68,68,0.3)">&#128680; TAMPER_ALERT</span>`;
          rowStyle = "background:rgba(239,68,68,0.08)";
        } else if (c.action === "EVIDENCE_RESTORED") {
          actionBadge = `<span style="color:#10B981;font-weight:800;background:rgba(16,185,129,0.15);padding:2px 8px;border-radius:4px;border:1px solid rgba(16,185,129,0.3)">&#128737;&#65039; EVIDENCE_RESTORED</span>`;
          rowStyle = "background:rgba(16,185,129,0.08)";
        } else if (c.action === "TAMPER_SIMULATED") {
          actionBadge = `<span style="color:#F59E0B;font-weight:700">&#9888;&#65039; TAMPER_SIMULATED</span>`;
        } else if (c.action === "EVIDENCE_VERIFIED") {
          actionBadge = `<span style="color:var(--accent);font-weight:600">&#10004; EVIDENCE_VERIFIED</span>`;
        }
        return `
          <tr style="${rowStyle}">
            <td class="cell-time">${escapeHtml(c.time)}</td>
            <td style="font-weight:600">${actionBadge}</td>
            <td class="code-cell-break" style="color:var(--muted);word-break:break-all;font-size:0.75rem;line-height:1.4">${escapeHtml(c.details)}</td>
          </tr>
        `;
      }).join("");
    }
  }

  // Live Evidence Tamper Demo Button
  const btnTamper = document.getElementById("btn-tamper-demo");
  if (btnTamper) {
    btnTamper.addEventListener("click", () => {
      btnTamper.disabled = true;
      btnTamper.innerHTML = `<span>&#9203;</span> Simulating tamper...`;

      fetch("/api/tamper/", { method: "POST" })
        .then(r => r.json())
        .then(data => {
          btnTamper.disabled = false;
          btnTamper.innerHTML = `&#9888;&#65039; Simulate Tamper (Demo)`;
          updateEvidenceUi(data);
          showForensicToast(`Tamper detected! File ${data.tampered_file} modified on disk. Audit alert logged to Chain of Custody.`, "danger");
        })
        .catch(err => {
          btnTamper.disabled = false;
          btnTamper.innerHTML = `&#9888;&#65039; Simulate Tamper (Demo)`;
          showForensicToast("Error simulating tamper: " + err, "danger");
        });
    });
  }

  // Restore Original Evidence Button
  const btnRestore = document.getElementById("btn-restore-evidence");
  if (btnRestore) {
    btnRestore.addEventListener("click", () => {
      restoreEvidenceFile("");
    });
  }

  window.restoreEvidenceFile = function(fileName) {
    const btnRestore = document.getElementById("btn-restore-evidence");
    if (btnRestore) {
      btnRestore.disabled = true;
      btnRestore.innerHTML = `<span>&#9203;</span> Restoring pristine evidence...`;
    }

    const body = fileName ? `file=${encodeURIComponent(fileName)}` : "";
    fetch("/api/restore-evidence/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body
    })
      .then(r => r.json())
      .then(data => {
        if (btnRestore) {
          btnRestore.disabled = false;
          btnRestore.innerHTML = `&#128737;&#65039; Restore Original Evidence`;
        }
        updateEvidenceUi(data);
        showForensicToast("✔ Pristine evidence restored! All SHA-256 hashes verified intact.", "success");
      })
      .catch(err => {
        if (btnRestore) {
          btnRestore.disabled = false;
          btnRestore.innerHTML = `&#128737;&#65039; Restore Original Evidence`;
        }
        showForensicToast("Error restoring evidence: " + err, "danger");
      });
  };

  // Verify Evidence Now Button
  const btnVerify = document.getElementById("btn-verify-now");
  if (btnVerify) {
    btnVerify.addEventListener("click", () => {
      btnVerify.disabled = true;
      btnVerify.innerHTML = `<span>&#9203;</span> Verifying hashes...`;
      fetch("/api/verify/")
        .then(r => r.json())
        .then(data => {
          btnVerify.disabled = false;
          btnVerify.innerHTML = `&#9989; Verify Evidence Now`;
          updateEvidenceUi(data);
          if (data.all_ok) {
            showForensicToast("✔ All evidence copies match their SHA-256 manifest! Status: 100% OK.", "success");
          } else {
            showForensicToast(`⚠️ CRITICAL: ${data.tampered_count || 1} evidence file(s) failed hash verification!`, "danger");
          }
        })
        .catch(err => {
          btnVerify.disabled = false;
          btnVerify.innerHTML = `&#9989; Verify Evidence Now`;
          showForensicToast("Verification error: " + err, "danger");
        });
    });
  }

  // Load Sample Scenarios
  const btnLoadSamples = document.getElementById("btn-load-samples");
  if (btnLoadSamples) {
    btnLoadSamples.addEventListener("click", () => {
      const promise = fetch("/api/load-samples/", { method: "POST" });
      runForensicAnalysisSequence(promise, "all");
    });
  }

  // File Upload & Analysis
  const uploadForm = document.getElementById("upload-form");
  const fileInput = document.getElementById("file-input");
  const btnAnalyse = document.getElementById("btn-analyse");
  const uploadDropzone = document.getElementById("upload-dropzone");
  const selectedFilesContainer = document.getElementById("selected-files-list");

  if (uploadDropzone && fileInput) {
    uploadDropzone.addEventListener("click", () => fileInput.click());
    uploadDropzone.addEventListener("dragover", e => { e.preventDefault(); uploadDropzone.classList.add("dragover"); });
    uploadDropzone.addEventListener("dragleave", () => uploadDropzone.classList.remove("dragover"));
    uploadDropzone.addEventListener("drop", e => {
      e.preventDefault();
      uploadDropzone.classList.remove("dragover");

      const dt = new DataTransfer();
      if (fileInput.files) {
        for (let i = 0; i < fileInput.files.length; i++) {
          dt.items.add(fileInput.files[i]);
        }
      }
      if (e.dataTransfer.files) {
        for (let i = 0; i < e.dataTransfer.files.length; i++) {
          dt.items.add(e.dataTransfer.files[i]);
        }
      }
      fileInput.files = dt.files;
      renderSelectedFiles();
    });
    fileInput.addEventListener("change", renderSelectedFiles);
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function renderSelectedFiles() {
    if (!uploadDropzone || !fileInput || !selectedFilesContainer) return;
    const files = fileInput.files;

    if (!files || files.length === 0) {
      selectedFilesContainer.style.display = "none";
      selectedFilesContainer.innerHTML = "";
      uploadDropzone.querySelector(".dropzone-text").innerText = "Drop auth.log / access.log here";
      return;
    }

    selectedFilesContainer.style.display = "flex";
    uploadDropzone.querySelector(".dropzone-text").innerText = `${files.length} file(s) selected`;

    let html = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px">
        <span class="section" style="margin:0;font-size:0.68rem">Selected (${files.length})</span>
        <button type="button" onclick="clearSelectedFiles()" style="background:none;border:none;color:var(--s-crit);font-size:0.7rem;cursor:pointer;text-decoration:underline">Clear all</button>
      </div>
    `;

    Array.from(files).forEach((file, index) => {
      html += `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:5px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;font-size:0.75rem">
          <div style="display:flex;align-items:center;gap:6px;overflow:hidden;margin-right:6px">
            <span style="font-size:0.85rem">&#128196;</span>
            <span style="font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
            <span style="color:var(--muted);font-size:0.68rem;white-space:nowrap">(${formatBytes(file.size)})</span>
          </div>
          <button type="button" onclick="removeSelectedFile(${index})" style="background:none;border:none;color:var(--muted);font-size:1.1rem;cursor:pointer;line-height:1;padding:0 4px" title="Remove file">&times;</button>
        </div>
      `;
    });

    selectedFilesContainer.innerHTML = html;
  }

  window.removeSelectedFile = function(index) {
    if (!fileInput) return;
    const dt = new DataTransfer();
    const files = fileInput.files;
    for (let i = 0; i < files.length; i++) {
      if (i !== index) {
        dt.items.add(files[i]);
      }
    }
    fileInput.files = dt.files;
    renderSelectedFiles();
  };

  window.clearSelectedFiles = function() {
    if (!fileInput) return;
    fileInput.value = "";
    renderSelectedFiles();
  };

  // Timezone Preference Persistence & Auto-Sync
  const tzSelects = document.querySelectorAll("#upload-tz, select[name='timezone']");
  const savedTz = localStorage.getItem("arixa_server_timezone") || "UTC";
  tzSelects.forEach(sel => {
    if (savedTz && Array.from(sel.options).some(o => o.value === savedTz)) {
      sel.value = savedTz;
    }
    sel.addEventListener("change", () => {
      localStorage.setItem("arixa_server_timezone", sel.value);
      tzSelects.forEach(other => { if (other !== sel) other.value = sel.value; });
    });
  });

  if (uploadForm) {
    uploadForm.addEventListener("submit", e => {
      e.preventDefault();
      const uploadTz = document.getElementById("upload-tz");
      if (uploadTz) {
        localStorage.setItem("arixa_server_timezone", uploadTz.value);
      }

      if (!fileInput.files || fileInput.files.length === 0) {
        const hasEvidence = document.querySelector("#kpi-evidence-val");
        if (hasEvidence && parseInt(hasEvidence.textContent || "0") > 0) {
          const formData = new FormData(uploadForm);
          const promise = fetch("/api/ingest/", { method: "POST", body: formData });
          runForensicAnalysisSequence(promise, "reanalyze");
          return;
        }
        alert("Please select at least one log file or pick a quick sample scenario.");
        return;
      }

      const formData = new FormData(uploadForm);
      const promise = fetch("/api/ingest/", { method: "POST", body: formData });
      runForensicAnalysisSequence(promise, "upload");
    });
  }

  // Reset Case Modal
  const modalReset = document.getElementById("modal-reset");
  const btnOpenReset = document.getElementById("btn-open-reset");
  const btnConfirmReset = document.getElementById("btn-confirm-reset");

  if (btnOpenReset && modalReset) {
    btnOpenReset.addEventListener("click", () => modalReset.classList.add("active"));
  }
  if (btnConfirmReset) {
    btnConfirmReset.addEventListener("click", () => {
      btnConfirmReset.innerText = "Wiping...";
      fetch("/api/reset/", { method: "POST" })
        .then(r => r.json())
        .then(() => window.location.reload());
    });
  }

  // Export Case Modal
  const modalExport = document.getElementById("modal-export");
  const btnOpenExport = document.getElementById("btn-open-export");
  if (btnOpenExport && modalExport) {
    btnOpenExport.addEventListener("click", () => modalExport.classList.add("active"));
  }

  // Generic modal close
  document.querySelectorAll(".modal-close, .modal-cancel").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
    });
  });

  // AI Copilot Actions
  const btnAiNarrative = document.getElementById("btn-ai-narrative");
  const aiNarrativeResult = document.getElementById("ai-narrative-result");

  if (btnAiNarrative && aiNarrativeResult) {
    btnAiNarrative.addEventListener("click", () => {
      btnAiNarrative.disabled = true;
      btnAiNarrative.innerText = "Generating narrative with Gemini...";
      aiNarrativeResult.innerHTML = '<div style="color:var(--muted)">Querying Gemini AI with redacted tokens (IPs/Users masked)...</div>';

      fetch("/api/ai/narrative/", { method: "POST" })
        .then(async r => {
          const contentType = r.headers.get("content-type") || "";
          if (contentType.includes("application/json")) {
            return r.json();
          }
          const text = await r.text();
          throw new Error(text || `Server returned status ${r.status}`);
        })
        .then(data => {
          btnAiNarrative.disabled = false;
          btnAiNarrative.innerText = "\u2728 Generate Incident Story";
          if (data.error) {
            aiNarrativeResult.innerHTML = `<div class="note" style="border-left-color:#EF4444">${escapeHtml(data.error)}</div>`;
          } else {
            aiNarrativeResult.innerHTML = `
              <div class="card" style="margin-top:12px;background:var(--surface2);border:1px solid var(--border)">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
                  <div style="font-weight:700;font-size:1.1rem;color:var(--text)">${escapeHtml(data.headline || "Guarded AI Incident Narrative")}</div>
                  <div class="hl-legend">
                    <span><span class="hl-ip">&#9679; IP</span> Yellow</span>
                    <span><span class="hl-user">&#9679; User</span> Red</span>
                    <span><span class="hl-event">#ID</span> Clickable</span>
                  </div>
                </div>
                <div class="ai-story-box">
                  ${formatAiIncidentText(data.narrative || data.text || "")}
                </div>
                <div class="ailabel" style="margin-top:14px;border-top:1px solid var(--border);padding-top:8px">
                  &#9888;&#65039; AI-generated &middot; analyst verification required. (Model: ${escapeHtml(data.model || "Gemini")})
                </div>
              </div>
            `;
          }
        })
        .catch(err => {
          btnAiNarrative.disabled = false;
          btnAiNarrative.innerText = "\u2728 Generate Incident Story";
          aiNarrativeResult.innerHTML = `<div class="note" style="border-left-color:#EF4444">Error: ${escapeHtml(err.message || String(err))}</div>`;
        });
    });
  }

  const btnAiAsk = document.getElementById("btn-ai-ask");
  const aiAskInput = document.getElementById("ai-ask-input");
  const aiAskResult = document.getElementById("ai-ask-result");

  if (btnAiAsk && aiAskInput && aiAskResult) {
    btnAiAsk.addEventListener("click", () => {
      const q = aiAskInput.value.trim();
      if (!q) return;

      btnAiAsk.disabled = true;
      btnAiAsk.innerText = "Thinking...";
      aiAskResult.innerHTML = '<div style="color:var(--muted)">Searching timeline with guarded AI...</div>';

      fetch(`/api/ai/ask/?q=${encodeURIComponent(q)}`)
        .then(async r => {
          const contentType = r.headers.get("content-type") || "";
          if (contentType.includes("application/json")) {
            return r.json();
          }
          const text = await r.text();
          throw new Error(text || `Server returned status ${r.status}`);
        })
        .then(data => {
          btnAiAsk.disabled = false;
          btnAiAsk.innerText = "Ask";
          if (data.error) {
            aiAskResult.innerHTML = `<div class="note" style="border-left-color:#EF4444">${escapeHtml(data.error)}</div>`;
          } else {
            aiAskResult.innerHTML = `
              <div class="card" style="margin-top:12px;background:var(--surface2);border:1px solid var(--border)">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
                  <div style="font-weight:700;font-size:1rem;color:var(--text)">AI Search Results</div>
                  <div class="hl-legend">
                    <span><span class="hl-ip">&#9679; IP</span> Yellow</span>
                    <span><span class="hl-user">&#9679; User</span> Red</span>
                    <span><span class="hl-event">#ID</span> Clickable</span>
                  </div>
                </div>
                <div class="ai-story-box">
                  ${formatAiIncidentText(data.answer || "")}
                </div>
                <div class="ailabel" style="margin-top:12px;border-top:1px solid var(--border);padding-top:8px">
                  &#9888;&#65039; AI-generated &middot; analyst verification required.
                </div>
              </div>
            `;
          }
        })
        .catch(err => {
          btnAiAsk.disabled = false;
          btnAiAsk.innerText = "Ask";
          aiAskResult.innerHTML = `<div class="note" style="border-left-color:#EF4444">Error: ${escapeHtml(err.message || String(err))}</div>`;
        });
    });
  }

  // Format pre-existing AI narrative on page load if present
  const rawNarrativeEl = document.querySelector(".ai-narrative-raw");
  if (rawNarrativeEl) {
    const raw = rawNarrativeEl.textContent;
    rawNarrativeEl.innerHTML = formatAiIncidentText(raw);
  }

  // Detections View Mode Toggle (Table View vs Incident Cards Feed)
  window.setDetectionsView = function(mode) {
    const tableContainer = document.getElementById("detections-table-container");
    const cardContainer = document.getElementById("detections-card-container");
    const btnTable = document.getElementById("view-mode-table");
    const btnCards = document.getElementById("view-mode-cards");

    if (mode === "cards") {
      if (tableContainer) tableContainer.style.display = "none";
      if (cardContainer) cardContainer.style.display = "block";
      if (btnCards) btnCards.classList.add("active");
      if (btnTable) btnTable.classList.remove("active");
    } else {
      if (tableContainer) tableContainer.style.display = "block";
      if (cardContainer) cardContainer.style.display = "none";
      if (btnTable) btnTable.classList.add("active");
      if (btnCards) btnCards.classList.remove("active");
    }
  };

  // Real-time quick filter for Detections
  const detectionFilterInput = document.getElementById("detection-quick-filter");
  if (detectionFilterInput) {
    detectionFilterInput.addEventListener("input", function() {
      const q = this.value.trim().toLowerCase();

      // Filter table rows
      const rows = document.querySelectorAll(".detection-table-row");
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(q) ? "" : "none";
      });

      // Filter card items
      const cards = document.querySelectorAll(".detection-card");
      cards.forEach(card => {
        const text = card.textContent.toLowerCase();
        card.style.display = text.includes(q) ? "block" : "none";
      });

      // Update visible count badge
      const countEl = document.getElementById("detection-count-badge");
      if (countEl) {
        let visibleCount = 0;
        rows.forEach(r => { if (r.style.display !== "none") visibleCount++; });
        countEl.textContent = `${visibleCount} alert${visibleCount === 1 ? '' : 's'}`;
      }
    });
  }

  // =========================================================================
  // Live UTC Clock (Real-Time Forensic Timekeeper)
  // =========================================================================
  function updateLiveUtcClock() {
    const chipTime = document.getElementById("chip-time");
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, "0");
    const day = String(now.getUTCDate()).padStart(2, "0");
    const hours = String(now.getUTCHours()).padStart(2, "0");
    const mins = String(now.getUTCMinutes()).padStart(2, "0");
    const secs = String(now.getUTCSeconds()).padStart(2, "0");
    const liveUtcString = `${year}-${month}-${day}T${hours}:${mins}:${secs}Z UTC`;

    if (chipTime) {
      chipTime.innerHTML = `<span class="clock-icon">&#128337;</span> <span class="clock-digits">${liveUtcString}</span>`;
      chipTime.setAttribute("title", "Live UTC Forensic Clock — updates every second");
    }

    const secondaryClocks = document.querySelectorAll(".live-utc-clock-text");
    secondaryClocks.forEach(el => {
      el.textContent = liveUtcString;
    });
  }

  // Start live clock ticking immediately every second
  updateLiveUtcClock();
  setInterval(updateLiveUtcClock, 1000);

  // Initial render on page load
  renderInteractiveAttackGraph();
  fetchTimelineEvents();
});

// Format AI Narrative with colorful highlights (Yellow IP, Red Users/Threats, Clickable Events)
function formatAiIncidentText(raw) {
  if (!raw) return "";

  // 1. Initial sanitization of raw text (do not replace single quote here so regex matches naturally)
  let t = String(raw)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // 2. IP Addresses -> Vibrant Yellow Badges
  t = t.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '<span class="hl-ip" title="IP Address">$&</span>');

  // 3. Event citations: #12, #24 -> Clickable Blue Chips
  t = t.replace(/#(\d+)/g, '<span class="hl-event" onclick="openEventDetail($1)" title="Click to inspect event #$1 in forensic detail">#$1</span>');

  // 4. File paths and system commands -> Cyan Code Badges
  t = t.replace(/(\/(?:etc|usr|bin|sbin|var|home|tmp)\/[a-zA-Z0-9_\-\.\/]+|[a-zA-Z0-9_\-\.]+\.php|\b(?:pg_dump|whoami|cat|useradd|sudo)\b)/g, '<span class="hl-cmd">$&</span>');

  // 5. Threat & Attack Keywords -> Red Underline / Badge
  const threats = [
    "brute-force attack", "brute-force activity", "brute-force campaign",
    "brute-force wave", "brute-force attacks", "brute-force", "brute force",
    "failed login attempts", "login failures", "failed logins", "failed attempts",
    "failed login", "login failed", "SQL injection", "local file inclusion",
    "web shell", "lateral movement", "database dump", "sensitive password hashes",
    "password hashes", "reconnaissance", "exploitation attempts",
    "HTTP 404 responses", "404 errors", "404 responses"
  ];
  const threatRegex = new RegExp(`\\b(${threats.join("|")})\\b`, "gi");
  t = t.replace(threatRegex, '<span class="hl-threat">$&</span>');

  // 6. Usernames & targeted accounts in RED
  // Only replace in text segments outside of HTML tags (<...>) to protect class names
  const knownUsers = [
    "admin", "root", "test", "oracle", "deploy", "ubuntu", "dbadmin",
    "alice", "postgres", "backupsvc", "support2", "sysupdate", "anna", "ben"
  ];
  const userRegex = new RegExp(`\\b(${knownUsers.join("|")})\\b`, "gi");

  const segments = t.split(/(<[^>]+>)/g);
  for (let i = 0; i < segments.length; i++) {
    if (i % 2 === 0) {
      // Quoted usernames: 'deploy' -> '<span class="hl-user">deploy</span>'
      segments[i] = segments[i].replace(/'([a-zA-Z0-9_\-]+)'/g, '\'<span class="hl-user" title="User Account">$1</span>\'');
      // Known usernames
      segments[i] = segments[i].replace(userRegex, '<span class="hl-user" title="User Account">$&</span>');
    }
  }
  t = segments.join("");

  // 7. Format multi-paragraph text cleanly with generous line spacing
  const paragraphs = t.split(/\n\s*\n/);
  if (paragraphs.length > 1) {
    return paragraphs.map(p => `<p>${p.trim()}</p>`).join("");
  }
  return `<p>${t.trim()}</p>`;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

