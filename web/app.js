/* Is This a Scam? web client. No build step, no dependencies. */
(function () {
  "use strict";
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const T = window.I18N;
  const LANGS = ["en", "hi", "bn"];

  // ---- per-browser conveniences (never required: everything works if storage is blocked) ----
  function store(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, value);
    } catch (e) { return null; }
  }
  function newId() {
    try { return crypto.randomUUID(); } catch (e) { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
  }
  const clientId = store("itas_client") || (() => { const id = newId(); store("itas_client", id); return id; })();
  const params = new URLSearchParams(location.search);
  const ref = params.get("ref") === "share" ? "share" : null;
  // A/B test (PRD): verdict first vs explanation first, split by anonymous browser ID.
  function hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return Math.abs(h); }
  const variant = ["verdict_first", "explanation_first"].includes(params.get("variant"))
    ? params.get("variant") : (hash(clientId) % 2 ? "explanation_first" : "verdict_first");

  let lang = params.get("lang") || store("itas_lang") || guessLang();
  if (!LANGS.includes(lang)) lang = "en";
  let config = { urgent_steps: null, model_available: true };
  let tab = "text";
  let image = null;            // {b64, mime, url}
  let lastRequest = null;
  let lastCard = null;
  const call = { claimed: null, asked: [], threat: null, video_or_secret: null, safe_account: null };

  function guessLang() {
    const n = (navigator.languages || [navigator.language || "en"]).join(",").toLowerCase();
    if (/\bbn/.test(n)) return "bn";
    if (/\bhi/.test(n)) return "hi";
    return "en";
  }
  const t = (key) => key.split(".").reduce((o, k) => (o || {})[k], T[lang]) || key.split(".").reduce((o, k) => (o || {})[k], T.en) || "";

  // ---- rendering the static interface ----
  function applyLang() {
    document.documentElement.lang = lang;
    $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    $$("[data-i18n-placeholder]").forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    $$(".langs button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === lang)));
    renderChips();
    renderUrgent();
    document.title = t("title") + " · Is This a Scam?";
  }

  function renderChips() {
    $$(".chips").forEach((box) => {
      const q = box.dataset.q, mode = box.dataset.mode;
      const options = mode === "bool" ? [["true", t("yes")], ["false", t("no")]] : Object.entries(t(q));
      box.innerHTML = "";
      options.forEach(([value, label]) => {
        const b = document.createElement("button");
        b.type = "button"; b.className = "chip"; b.textContent = label; b.dataset.value = value;
        const current = call[q];
        const on = mode === "multi" ? current.includes(value) : String(current) === value;
        b.setAttribute("aria-pressed", String(on));
        b.addEventListener("click", () => {
          if (mode === "multi") {
            call[q] = on ? current.filter((v) => v !== value) : current.filter((v) => v !== "nothing" || value === "nothing").concat(value);
            if (value === "nothing" && !on) call[q] = ["nothing"];
          } else if (mode === "bool") {
            call[q] = String(current) === value ? null : value === "true";
          } else {
            call[q] = current === value ? null : value;
          }
          renderChips();
        });
        box.appendChild(b);
      });
    });
  }

  function renderUrgent() {
    const steps = (config.urgent_steps || {})[lang] || [];
    $("#urgentSteps").innerHTML = "";
    steps.forEach((s) => { const li = document.createElement("li"); li.textContent = s; $("#urgentSteps").appendChild(li); });
  }

  function setTab(next) {
    tab = next;
    $("#tabMsg").setAttribute("aria-selected", String(next === "text"));
    $("#tabCall").setAttribute("aria-selected", String(next === "call"));
    $("#paneMsg").hidden = next !== "text";
    $("#paneCall").hidden = next !== "call";
  }

  // ---- screenshot handling: downscale big images in the browser before upload ----
  function readImage(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = reject;
      reader.onload = () => {
        const img = new Image();
        img.onerror = reject;
        img.onload = () => {
          const max = 1600, scale = Math.min(1, max / Math.max(img.width, img.height));
          if (scale === 1 && file.size < 3.5e6) {
            resolve({ b64: String(reader.result).split(",")[1], mime: file.type || "image/png", url: reader.result });
            return;
          }
          const canvas = document.createElement("canvas");
          canvas.width = Math.round(img.width * scale); canvas.height = Math.round(img.height * scale);
          canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
          const url = canvas.toDataURL("image/jpeg", 0.85);
          resolve({ b64: url.split(",")[1], mime: "image/jpeg", url });
        };
        img.src = reader.result;
      };
      reader.readAsDataURL(file);
    });
  }

  // ---- API ----
  async function api(path, body) {
    const res = await fetch(path, { method: body ? "POST" : "GET", headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || t("error_generic"));
    return data;
  }
  function track(event, checkId) {
    api("/api/feedback", { event, check_id: checkId || null, client_id: clientId, variant }).catch(() => {});
  }

  function showError(msg) { const el = $("#formError"); el.textContent = msg; el.hidden = !msg; }

  function buildRequest() {
    if (tab === "call") {
      const answered = call.claimed || call.asked.length || call.threat || call.video_or_secret !== null || call.safe_account !== null || $("#details").value.trim();
      if (!answered) { showError(t("need_call")); return null; }
      return { kind: "call", call: { ...call, video_or_secret: !!call.video_or_secret, safe_account: !!call.safe_account, details: $("#details").value.trim() } };
    }
    if (image) return { kind: "image", image_b64: image.b64, image_mime: image.mime };
    const text = $("#msg").value.trim();
    if (!text) { showError(t("need_input")); return null; }
    return { kind: "text", text };
  }

  async function runCheck(req, relang) {
    showError("");
    $("#loading").hidden = false; $("#result").hidden = true; $("#checkBtn").disabled = true;
    try {
      const card = await api("/api/check", { ...req, lang, client_id: clientId, variant, ref, relang: !!relang });
      lastRequest = req; lastCard = card;
      renderCard(card);
      $("#formPanel").hidden = true;
    } catch (e) {
      showError(e.message || t("error_generic"));
    } finally {
      $("#loading").hidden = true; $("#checkBtn").disabled = false;
    }
  }

  // ---- the verdict card ----
  const ICONS = {
    scam: '<path fill="currentColor" d="M1 21h22L12 2 1 21Zm12-3h-2v-2h2v2Zm0-4h-2v-4h2v4Z"/>',
    unsure: '<path fill="currentColor" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm1 17h-2v-2h2v2Zm2.1-7.7-.9.9A3.4 3.4 0 0 0 13 15h-2v-.5c0-1.1.4-2.1 1.2-2.8l1.2-1.3A2 2 0 1 0 10 9H8a4 4 0 1 1 7.1 2.3Z"/>',
    no_signs: '<path fill="currentColor" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm1 15h-2v-6h2v6Zm0-8h-2V7h2v2Z"/>',
  };

  function li(text, quote) {
    const el = document.createElement("li");
    if (quote) { const q = document.createElement("q"); q.textContent = quote; el.appendChild(q); }
    el.appendChild(document.createTextNode(text));
    return el;
  }

  function renderCard(card) {
    const node = $("#cardTpl").content.firstElementChild.cloneNode(true);
    node.classList.add(card.verdict);
    if (variant === "explanation_first") node.classList.add("explanation-first");
    node.lang = card.lang;
    $(".verdict-icon", node).innerHTML = ICONS[card.verdict];
    $(".verdict-label", node).textContent = card.verdict_label;
    const typeEl = $(".verdict-type", node);
    if (card.scam_type_label) typeEl.textContent = T[card.lang].type_label + ": " + card.scam_type_label; else typeEl.remove();
    $(".summary", node).textContent = card.summary;

    const flags = card.red_flags || [];
    $(".flags-title", node).textContent = T[card.lang].red_flags_title;
    flags.forEach((f) => $(".flags", node).appendChild(li(f.why, f.quote)));
    if (!flags.length) $(".flags-block", node).remove();
    const gen = card.genuine_signs || [];
    $(".genuine-title", node).textContent = T[card.lang].genuine_title;
    gen.forEach((g) => $(".genuine", node).appendChild(li(g)));
    if (!gen.length) $(".genuine-block", node).remove();

    $(".steps-title", node).textContent = T[card.lang].steps_title;
    card.next_steps.forEach((s) => $(".steps", node).appendChild(li(s)));
    $(".verify-title", node).textContent = T[card.lang].verify_title;
    $(".verify", node).textContent = card.verify;
    $(".disclaimer", node).textContent = card.disclaimer;

    const share = $(".share", node);
    share.textContent = T[card.lang].share_btn;
    share.addEventListener("click", () => {
      const text = card.share_text + "\n" + T[card.lang].share_suffix + " " + location.origin + "/?ref=share";
      track("shared", card.check_id);
      window.open("https://wa.me/?text=" + encodeURIComponent(text), "_blank", "noopener");
    });
    $(".helpful-q", node).textContent = T[card.lang].helpful_q;
    $(".stopped-q", node).textContent = T[card.lang].stopped_q;
    const labels = { helpful: T[card.lang].yes, not_helpful: T[card.lang].no, stopped_me: T[card.lang].yes, wrong_verdict: T[card.lang].wrong_btn };
    $$(".fb", node).forEach((b) => {
      b.textContent = labels[b.dataset.event];
      b.addEventListener("click", () => {
        if (b.classList.contains("selected")) return;
        b.classList.add("selected");
        if (b.dataset.event === "helpful" || b.dataset.event === "not_helpful") $$('.fb[data-event="helpful"], .fb[data-event="not_helpful"]', node).forEach((x) => (x.disabled = true));
        track(b.dataset.event, card.check_id);
        const thanks = $(".thanks", node); thanks.textContent = T[card.lang].thanks; thanks.hidden = false;
      });
    });
    const again = $(".again", node);
    again.textContent = T[card.lang].check_another;
    again.addEventListener("click", resetForm);

    $("#result").innerHTML = "";
    $("#result").appendChild(node);
    $("#result").hidden = false;
    $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function resetForm() {
    $("#result").hidden = true; $("#formPanel").hidden = false;
    $("#msg").value = ""; $("#count").textContent = "0"; clearImage();
    Object.assign(call, { claimed: null, asked: [], threat: null, video_or_secret: null, safe_account: null });
    $("#details").value = ""; renderChips(); lastCard = null;
    $("#msg").focus();
  }
  function clearImage() { image = null; $("#file").value = ""; $("#preview").hidden = true; }

  // ---- wiring ----
  $$(".langs button").forEach((b) => b.addEventListener("click", () => {
    if (b.dataset.lang === lang) return;
    lang = b.dataset.lang; store("itas_lang", lang); applyLang();
    if (lastCard && lastRequest) runCheck(lastRequest, true);   // same message, new language
  }));
  $("#tabMsg").addEventListener("click", () => setTab("text"));
  $("#tabCall").addEventListener("click", () => setTab("call"));
  $("#msg").addEventListener("input", (e) => { $("#count").textContent = String(e.target.value.length); });
  $("#file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      image = await readImage(file);
      $("#previewImg").src = image.url; $("#previewImg").alt = file.name; $("#preview").hidden = false;
    } catch (err) { showError(t("error_generic")); clearImage(); }
  });
  $("#removeImg").addEventListener("click", clearImage);
  $("#checkBtn").addEventListener("click", () => { const req = buildRequest(); if (req) runCheck(req); });
  $("#urgentBtn").addEventListener("click", () => {
    $("#urgentPanel").hidden = false; $("#urgentPanel").scrollIntoView({ behavior: "smooth" }); track("already_paid_open");
  });
  $("#urgentClose").addEventListener("click", () => { $("#urgentPanel").hidden = true; });

  applyLang();
  api("/api/config").then((c) => { config = c; renderUrgent(); $("#noModel").hidden = c.model_available; }).catch(() => {});
  if (ref) track("share_open");
})();
