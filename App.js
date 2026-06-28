const urlInput = document.getElementById("urlInput");
const checkBtn = document.getElementById("checkBtn");
const errorDiv = document.getElementById("error");
const loader = document.getElementById("loader");
const results = document.getElementById("results");

urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") checkURL();
});

function showError(msg) {
  errorDiv.textContent = msg;
  errorDiv.classList.remove("hidden");
}

function hideError() {
  errorDiv.classList.add("hidden");
}

function setLoading(on) {
  checkBtn.disabled = on;
  checkBtn.textContent = on ? "Checking…" : "Check";
  loader.classList.toggle("hidden", !on);
  if (on) results.classList.add("hidden");
}

async function checkURL() {
  const url = urlInput.value.trim();
  if (!url) { showError("Please enter a URL."); return; }
  hideError();
  setLoading(true);

  try {
    const resp = await fetch("/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await resp.json();

    if (!resp.ok) {
      throw new Error(data.detail || "Server error");
    }

    renderResults(data);
  } catch (e) {
    showError("Error: " + e.message);
  } finally {
    setLoading(false);
  }
}

function renderResults(data) {
  const trust = data.trust || {};
  const ssl = data.ssl || {};
  const whois = data.whois || {};
  const redirects = data.redirects || {};
  const pattern_warnings = data.pattern_warnings || [];
  const domain = data.domain || "";
  const checked_at = data.checked_at || new Date().toISOString();

  // Score card
  const scoreCard = document.getElementById("scoreCard");
  scoreCard.className = "card score-card score-" + (trust.color || "green");
  document.getElementById("scoreNumber").textContent = trust.score != null ? trust.score : "?";
  document.getElementById("scoreLevel").textContent = trust.level || "–";
  document.getElementById("scoreDomain").textContent = domain;
  document.getElementById("scoreChecked").textContent =
    "Checked at " + new Date(checked_at).toLocaleTimeString();

  // Flags
  const flagsList = document.getElementById("flagsList");
  flagsList.innerHTML = "";
  const flags = trust.flags || [];
  if (flags.length === 0) {
    flagsList.innerHTML = '<li class="no-flags">✅ No risk flags detected</li>';
  } else {
    flags.forEach((f) => {
      const li = document.createElement("li");
      li.textContent = f;
      flagsList.appendChild(li);
    });
  }

  document.getElementById("sslDetails").innerHTML = buildSSL(ssl);
  document.getElementById("whoisDetails").innerHTML = buildWhois(whois);
  document.getElementById("redirectDetails").innerHTML = buildRedirects(redirects);
  document.getElementById("patternDetails").innerHTML = buildPatterns(pattern_warnings);

  results.classList.remove("hidden");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function row(label, valueHTML) {
  return `<div class="detail-row">
    <span class="detail-label">${label}</span>
    <span class="detail-value">${valueHTML}</span>
  </div>`;
}

function badge(text, color) {
  return `<span class="badge badge-${color}">${text}</span>`;
}

function buildSSL(ssl) {
  if (!ssl.valid) {
    return row("Status", badge("Invalid", "red")) +
           row("Reason", `<span style="color:var(--muted);font-size:0.82rem">${ssl.reason || "Unknown"}</span>`);
  }
  const days = ssl.days_left;
  const daysColor = days < 14 ? "orange" : "green";
  return row("Status", badge("Valid", "green")) +
         row("Expires", ssl.expiry || "–") +
         row("Days Left", badge(days + " days", daysColor));
}

function buildWhois(whois) {
  if (!whois.found) {
    return row("Status", badge("Not Found", "red")) +
           row("Reason", `<span style="color:var(--muted);font-size:0.82rem">${whois.reason || "–"}</span>`);
  }
  const age = whois.age_days;
  const ageColor = age < 30 ? "red" : age < 180 ? "orange" : "green";
  return row("Registered", whois.creation_date || "–") +
         row("Expires", whois.expiry_date || "–") +
         row("Domain Age", badge(age + " days", ageColor)) +
         row("Registrar", `<span style="font-size:0.82rem">${whois.registrar || "–"}</span>`);
}

function buildRedirects(r) {
  const countColor = r.redirect_count === 0 ? "green" : r.suspicious ? "red" : "orange";
  let html = row("Redirects", badge(r.redirect_count, countColor));
  if (r.chain && r.chain.length > 0) {
    const listItems = r.chain.map((url, i) => {
      const isFinal = i === r.chain.length - 1;
      const arrow = i === 0 ? "→" : "↪";
      return `<li class="${isFinal ? "final" : ""}">
        <span class="arrow">${arrow}</span>
        <span>${url}</span>
      </li>`;
    });
    html += `<ul class="redirect-chain" style="margin-top:0.75rem">${listItems.join("")}</ul>`;
  }
  return html;
}

function buildPatterns(warnings) {
  if (!warnings || warnings.length === 0) {
    return `<div class="no-flags" style="font-size:0.88rem">✅ No suspicious patterns detected</div>`;
  }
  return warnings.map((w) =>
    `<div class="detail-row"><span style="color:var(--orange);font-size:0.85rem">⚠ ${w}</span></div>`
  ).join("");
}
