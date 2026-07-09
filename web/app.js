const $ = (id) => document.getElementById(id);
const urlEl = $("url"), runEl = $("run"), verdictEl = $("verdict");
const candsEl = $("cands"), logEl = $("log");

function log(msg, isErr) {
  const line = document.createElement("div");
  if (isErr) line.className = "e";
  line.textContent = msg;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function setVerdict(kind, html) {
  verdictEl.className = kind;
  verdictEl.innerHTML = html;
}

function addRow(c) {
  if (candsEl.querySelector(".empty")) candsEl.innerHTML = "";
  const tr = document.createElement("tr");
  const type = c.type || "?";
  tr.innerHTML =
    `<td class="type ${type}">${type}</td>` +
    `<td>${c.protocol || "-"}</td>` +
    `<td>${c.address || "-"}</td>` +
    `<td>${c.port ?? "-"}</td>`;
  candsEl.appendChild(tr);
}

let pc = null;

async function test() {
  if (pc) { pc.close(); pc = null; }
  candsEl.innerHTML = `<tr><td class="empty" colspan="4">Gathering…</td></tr>`;
  logEl.innerHTML = "";

  const urls = urlEl.value.split("\n").map(s => s.trim()).filter(Boolean);
  if (!urls.length) { setVerdict("bad", "Enter at least one STUN URL."); return; }

  runEl.disabled = true;
  setVerdict("run", "⏳ Gathering ICE candidates…");
  log("iceServers: " + JSON.stringify(urls));

  let sawReflexive = false;
  let sawError = false;

  pc = new RTCPeerConnection({ iceServers: [{ urls }], iceCandidatePoolSize: 0 });
  // A data channel gives ICE something to gather for.
  pc.createDataChannel("probe");

  pc.onicecandidate = (e) => {
    if (!e.candidate) { log("gathering complete"); finish(); return; }
    const c = e.candidate;
    if (!c.candidate) return; // end-of-candidates marker
    log(c.candidate);
    addRow(c);
    if (c.type === "srflx") {
      sawReflexive = true;
      setVerdict("ok",
        `✓ STUN server works. Public address: <span id="reflexive">${c.address}:${c.port}</span>`);
    }
  };

  pc.onicecandidateerror = (e) => {
    // 701 = STUN server unreachable / no response for a candidate.
    sawError = true;
    log(`icecandidateerror ${e.errorCode} ${e.errorText || ""} (${e.url || ""})`, true);
  };

  function finish() {
    runEl.disabled = false;
    if (sawReflexive) return; // verdict already set to ok
    if (sawError) {
      setVerdict("bad", "✗ No reflexive candidate. Server unreachable or not responding — see log.");
    } else {
      setVerdict("bad", "✗ No reflexive candidate gathered. Is the server running and reachable?");
    }
  }

  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
  } catch (err) {
    runEl.disabled = false;
    setVerdict("bad", "✗ " + err.message);
    log(String(err), true);
    return;
  }

  // Safety net: browsers usually fire the null candidate, but cap the wait.
  setTimeout(() => { if (runEl.disabled) finish(); }, 8000);
}

runEl.addEventListener("click", test);
urlEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) test();
});
