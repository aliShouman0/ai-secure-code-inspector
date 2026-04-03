

const OWASP_COLORS = {
  A01: "#e74c3c",   // Broken Access Control
  A02: "#e67e22",   // Cryptographic Failures
  A03: "#f1c40f",   // Injection
  A04: "#3498db",   // Insecure Design
  A05: "#2980b9",   // Security Misconfiguration
  A06: "#636e72",   // Vulnerable Components
  A07: "#27ae60",   // Auth Failures
  A08: "#9b59b6",   // Integrity Failures
  A09: "#b2bec3",   // Logging Failures
  A10: "#16a085",   // SSRF
};

// Return    hex color for an OWASP category string (e.g. "A03 - Injection")
function getCategoryColor(category) {
  for (const [key, color] of Object.entries(OWASP_COLORS)) {
    if ((category || "").includes(key)) return color;
  }
  return "#636e72"; // default gray
}

// Toggle between Juice Shop path and upload section
$("input[name=source]").on("change", function () {
  const isUpload = $(this).val() === "upload";
  $("#path-section, #mode-section, #scope-list").toggleClass("d-none", isUpload);
  $("#upload-section").toggleClass("d-none", !isUpload);
});

// Scope list: hide files when Test Mode is selected
$("input[name=mode]").on("change", function () {
  const isTestMode = $(this).val() === "test";
  $("#scope-list .scope-item").each(function () {
    const fileIndex = parseInt($(this).data("index"));
    $(this).toggle(!isTestMode || fileIndex < 3);
  });
});

//Clear  button reset UI to welcome state
$("#clear-btn").on("click", function () {
  $("#welcome-panel").show();
  $("#progress-panel, #results-area").addClass("d-none");
  $("#log-box").text("");
  $("#progress-bar").css("width", "0%");
});

//  Run Scan button
$("#run-btn").on("click", function () {
  const source  = $("input[name=source]:checked").val();
  const apiKey  = $("#api-key").val().trim();

  if (!apiKey) {
    alert("Please enter your Anthropic API key before running a scan.");
    $("#api-key").focus();
    return;
  }

  if (source === "upload" && $("#upload-input")[0].files.length === 0) {
    alert("Please select at least one file to upload.");
    $("#upload-input").focus();
    return;
  }

  //  Switch to progress view
  $("#welcome-panel").hide();
  $("#results-area").addClass("d-none");
  $("#progress-panel").removeClass("d-none");
  $("#log-box").text("");
  $("#progress-bar")
    .css("width", "0%")
    .removeClass("bg-success bg-danger")
    .addClass("bg-primary progress-bar-animated");
  $("#run-btn").prop("disabled", true);

  // If upload mode: POST files first, then start SSE with returned path
  if (source === "upload") {
    const formData = new FormData();
    $.each($("#upload-input")[0].files, function (_i, file) {
      formData.append("files", file);
    });
    $("#upload-status").text("⬆️ Uploading files...");
    appendLog("⬆️ Uploading files...");

    $.ajax({
      url: "/upload",
      type: "POST",
      data: formData,
      processData: false,
      contentType: false,
      success: function (res) {
        $("#upload-status").text(`✅ ${res.files.length} file(s) uploaded`);
        appendLog(`✅ Uploaded: ${res.files.join(", ")}`);
        startScan(res.path, "upload", apiKey, res.files.length);
      },
      error: function () {
        appendLog("❌ Upload failed.");
        $("#run-btn").prop("disabled", false);
      }
    });
    return;
  }

  // Juice Shop path mode
  const targetPath = $("#target-path").val().trim();
  const scanMode   = $("input[name=mode]:checked").val();
  const fileCount  = scanMode === "full" ? 10 : 3;
  startScan(targetPath, scanMode, apiKey, fileCount);
});

function startScan(targetPath, scanMode, apiKey, fileCount) {
  //  Open SSE stream — Flask will push events as files are analyzed
  const eventSource = new EventSource(
    `/scan?path=${encodeURIComponent(targetPath)}&mode=${scanMode}&key=${encodeURIComponent(apiKey)}`,
  );

  eventSource.onmessage = function (event) {
    const msg = JSON.parse(event.data);

    if (msg.type === "log") {
      appendLog(msg.msg);
      $("#progress-bar").css("width", msg.pct + "%");
    }

    if (msg.type === "error") {
      appendLog("\n❌ ERROR: " + msg.msg);
      $("#progress-bar")
        .removeClass("progress-bar-animated")
        .addClass("bg-danger");
      eventSource.close();
      $("#run-btn").prop("disabled", false);
    }

    if (msg.type === "done") {
      eventSource.close();
      $("#progress-bar")
        .removeClass("progress-bar-animated")
        .addClass("bg-success");
      $("#run-btn").prop("disabled", false);
      // Fetch verified findings and render the results section
      $.getJSON("/results", function (findings) {
        renderResults(findings, fileCount, msg.raw);
      });
    }
  };

  eventSource.onerror = function () {
    appendLog("\n❌ Connection error.");
    eventSource.close();
    $("#run-btn").prop("disabled", false);
  };
}



//  Append a  line to the log box and auto-scroll to bottom
function appendLog(text) {
  const box = document.getElementById("log-box");
  box.textContent += text + "\n";
  box.scrollTop = box.scrollHeight;
}


//Render results section
function renderResults(findings, filesScanned, rawCount) {
  $("#progress-panel").addClass("d-none");
  $("#results-area").removeClass("d-none");

  renderMetrics(findings.length, rawCount, filesScanned);
  renderChart(findings);

  renderFilterDropdown(findings);

  $("#findings-title").text(`🔎 Findings (${findings.length} total)`);
  renderFindings(findings, "all");
}



function renderMetrics(verifiedCount, rawCount, filesScanned) {
  const cards = [
    { value: verifiedCount, label: "Verified Findings", color: "text-white" },
    { value: rawCount, label: "Raw Findings", color: "text-white" },
    {
      value: rawCount - verifiedCount,
      label: "False Positives Removed",
      color: "text-warning",
    },
    { value: filesScanned, label: "Files Scanned", color: "text-info" },
  ];

  const html = cards
    .map(function (card) {
      return `
            <div class="col-6 col-xl-3">
                <div class="card text-center">
                    <div class="card-body py-3">
                        <div class="metric-value ${card.color}">${card.value}</div>
                        <div class="metric-label">${card.label}</div>
                    </div>
                </div>
            </div>`;
    })
    .join("");

  $("#metrics-row").html(html);
}



//OWASP bar chart

function renderChart(findings) {
  // Count findings per OWASP category
  const categoryCounts = {};
  findings.forEach(function (finding) {
    const cat = finding.owasp_category || "Unknown";
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  });

  const maxCount = Math.max(...Object.values(categoryCounts), 1);


  const bars = Object.entries(categoryCounts)
    .sort((a, b) => b[1] - a[1]) // sort highest first
    .map(function ([category, count]) {
      const widthPct = Math.round((count / maxCount) * 100);
      const color = getCategoryColor(category);
      return `
                <div class="d-flex align-items-center gap-2 mb-2">
                    <div style="min-width:220px; font-size:.82rem" class="text-truncate">${category}</div>
                    <div class="flex-grow-1">
                        <div class="progress" style="height:22px;">
                            <div class="progress-bar fw-semibold"
                                 style="width:${widthPct}%; background:${color}; font-size:.78rem;">
                                ${count}
                            </div>
                        </div>
                    </div>
                </div>`;
    })
    .join("");

  $("#chart").html(bars);
}


//Category filter dropdown
function renderFilterDropdown(findings) {
  const categories = {};
  findings.forEach(function (f) {
    const cat = f.owasp_category || "Unknown";
    categories[cat] = (categories[cat] || 0) + 1;
  });

  const dropdown = $("#cat-filter")
    .empty()
    .append('<option value="all">All Categories</option>');
  Object.keys(categories)
    .sort()
    .forEach(function (cat) {
      dropdown.append(
        `<option value="${cat}">${cat} (${categories[cat]})</option>`,
      );
    });

  dropdown.off("change").on("change", function () {
    renderFindings(findings, $(this).val());
  });
}


//Findings list

function renderFindings(findings, filterCategory) {

  const filtered =
    filterCategory === "all"
      ? findings
      : findings.filter(function (f) {
          return f.owasp_category === filterCategory;
        });

  const container = $("#findings-list").empty();



  if (filtered.length === 0) {
    container.html(
      '<p class="text-muted small">No findings for this category.</p>',
    );
    return;
  }


  filtered.forEach(function (finding, index) {

    const confidence = parseFloat(finding.confidence || 0);
    const level =
      confidence >= 0.85
        ? "🔴 High"
        : confidence >= 0.6
          ? "🟠 Medium"
          : "🟢 Low";
    const color = getCategoryColor(finding.owasp_category);

    container.append(`

            <details ${index === 0 ? "open" : ""}>
                <summary>

                    <span class="badge" style="background:${color}">${finding.owasp_category || "N/A"}</span>
                    <code class="small">${finding.file || "N/A"}</code>

                    <span class="text-muted small">lines ${finding.line_range || "N/A"}</span>
                    <span class="ms-auto text-muted small">${level} (${confidence.toFixed(2)})</span>
                </summary>
                <div class="detail-body">
                    <p class="text-muted small mb-2">
                        File: <code>${finding.file || "N/A"}</code>
                        — Lines: <code>${finding.line_range || "N/A"}</code>
                    </p>
                    <div class="alert alert-danger  py-2 px-3 mb-2 small">🔴 ${finding.risk_summary || "N/A"}</div>
                    <div class="alert alert-success py-2 px-3 mb-0 small">🔧 ${finding.fix || "N/A"}</div>
                </div>
            </details>`);
  });
}




