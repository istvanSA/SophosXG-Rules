const DOMAIN = "sophos_firewall_rules";
const TAG = "sophos-firewall-rule-card";
const POLICIES = ["application_policy", "web_policy", "traffic_shaping_policy"];
const ACTIONS = { accept: "Allow", drop: "Drop", reject: "Reject" };

class SophosFirewallRuleCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    // The markup is static. Names and values from Sophos are set through DOM properties.
    this.shadowRoot.innerHTML = `
      <style>
        .content { padding: 16px; display: grid; gap: 14px; }
        header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
        h2 { font-size: 1.25rem; line-height: 1.4; margin: 0; }
        p { margin: 0; }
        form { display: grid; gap: 14px; }
        label { display: grid; gap: 5px; font-weight: 500; }
        .check { display: flex; align-items: center; gap: 9px; }
        input, select, button { color: inherit; font: inherit; }
        select, input[type="search"] {
          width: 100%; box-sizing: border-box; min-height: 40px; padding: 6px 9px;
          background: var(--card-background-color);
          border: 1px solid var(--divider-color); border-radius: 6px;
        }
        select:disabled, button:disabled { opacity: .55; }
        button { padding: 7px 12px; border: 1px solid var(--divider-color);
          border-radius: 6px; background: var(--card-background-color); cursor: pointer; }
        button[type="submit"] { background: var(--primary-color); color: var(--text-primary-color); }
        .buttons { display: flex; justify-content: flex-end; gap: 10px; }
        .secondary { color: var(--secondary-text-color); font-size: .9rem; }
        .error { color: var(--error-color); }
        :focus-visible { outline: 2px solid var(--primary-color); outline-offset: 2px; }
        [hidden] { display: none !important; }
      </style>
      <ha-card>
        <div class="content">
          <header><h2></h2><button id="refresh" type="button">Refresh</button></header>
          <label id="search-row" hidden>Find a rule<input id="search" type="search"></label>
          <label id="picker" hidden>Firewall rule<select id="rule"></select></label>
          <form hidden>
            <p id="state" class="secondary"></p>
            <label class="check"><input type="checkbox" id="enabled"> Enabled</label>
            <label>Application filter<select id="application_policy"></select><small class="secondary" hidden></small></label>
            <label>Web filter<select id="web_policy"></select><small class="secondary" hidden></small></label>
            <label>Traffic shaping<select id="traffic_shaping_policy"></select><small class="secondary" hidden></small></label>
            <label class="check"><input type="checkbox" id="block_quic"> Block QUIC</label>
            <p id="policy-note" class="secondary" hidden></p>
            <p id="quic-note" class="secondary" hidden>Block QUIC requires a web filter or HTTP scanning.</p>
            <div class="buttons">
              <button id="cancel" type="button">Cancel</button>
              <button id="apply" type="submit">Apply</button>
            </div>
          </form>
          <p id="message" class="secondary" role="status"></p>
          <p id="error" class="error" role="alert"></p>
        </div>
      </ha-card>`;
    this._rules = [];
    this._busy = false;
    this._snapshot = null;
    this._draft = null;
    this._rulePicker = this._element("rule");
    this._search = this._element("search");
    this._form = this.shadowRoot.querySelector("form");
    this._element("refresh").addEventListener("click", () => this._loadRules());
    this._search.addEventListener("input", () => this._showRuleOptions());
    this._rulePicker.addEventListener("change", () => this._loadRule());
    this._form.addEventListener("submit", (event) => {
      event.preventDefault();
      this._apply();
    });
    this._element("cancel").addEventListener("click", () => {
      this._showSnapshot(this._snapshot);
      this._message("");
    });
    for (const field of ["enabled", "block_quic", ...POLICIES]) {
      const input = this._element(field);
      input.addEventListener("change", () => {
        this._draft[field] = input.type === "checkbox" ? input.checked : input.value || null;
        this._updateControls();
      });
    }
  }

  _element(id) {
    return this.shadowRoot.getElementById(id);
  }

  setConfig(config) {
    this.shadowRoot.querySelector("h2").textContent =
      config.title ?? "Sophos Firewall Rules";
  }

  static getStubConfig() {
    return {};
  }

  getCardSize() {
    return 7;
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._started) {
      this._started = true;
      this._loadRules();
    }
  }

  _ruleId(rule) {
    return JSON.stringify([rule.entry_id, rule.rule_key]);
  }

  _ruleLabel(rule) {
    return `${rule.name} · IPv${rule.family.slice(-1)} · ${rule.firewall}`;
  }

  _showRuleOptions() {
    const query = this._search.value.trim().toLocaleLowerCase();
    const matches = this._rules.filter((rule) =>
      this._ruleId(rule) === this._selection ||
      this._ruleLabel(rule).toLocaleLowerCase().includes(query)
    );
    const placeholder = matches.length ? "Choose a rule" : "No matching rules";
    this._rulePicker.replaceChildren(new Option(placeholder, ""));
    for (const rule of matches) {
      this._rulePicker.add(new Option(this._ruleLabel(rule), this._ruleId(rule)));
    }
    this._rulePicker.value = this._selection ?? "";
  }

  _message(message, error = "") {
    this._element("message").textContent = message;
    this._element("error").textContent = error;
  }

  async _run(task, loadingText) {
    if (this._busy) return;
    this._busy = true;
    this._message(loadingText);
    this._updateControls();
    try {
      this._message(await task());
    } catch (error) {
      this._message("", error?.message || "Could not communicate with Sophos Firewall.");
    } finally {
      this._busy = false;
      this._updateControls();
    }
  }

  _loadRules() {
    return this._run(async () => {
      this._rules = await this._hass.callWS({ type: `${DOMAIN}/rules` });
      this._rules.sort((left, right) => this._ruleLabel(left).localeCompare(this._ruleLabel(right)));
      if (!this._rules.some((rule) => this._ruleId(rule) === this._selection)) {
        this._selection = this._rules.length === 1 ? this._ruleId(this._rules[0]) : "";
      }
      this._search.value = "";
      this._element("search-row").hidden = this._rules.length < 2;
      this._element("picker").hidden = !this._rules.length;
      this._showRuleOptions();
      this._showSnapshot(null);
      await this._readSelection();
      return this._rules.length ? "" : "Select firewall rules in the integration settings first.";
    }, "Loading firewall rules…");
  }

  _loadRule() {
    return this._run(async () => {
      this._selection = this._rulePicker.value;
      this._showRuleOptions();
      this._showSnapshot(null);
      await this._readSelection();
      return "";
    }, "Reading firewall rule…");
  }

  _target() {
    const [entry_id, rule_key] = JSON.parse(this._selection);
    return { entry_id, rule_key };
  }

  async _readSelection() {
    if (this._selection) {
      this._showSnapshot(await this._hass.callWS({
        type: `${DOMAIN}/read_rule`,
        ...this._target(),
      }));
    }
  }

  _showSnapshot(snapshot) {
    this._snapshot = snapshot;
    this._draft = snapshot ? { ...snapshot.values } : null;
    this._form.hidden = !snapshot;
    if (snapshot) {
      const status = snapshot.values.enabled ? "Enabled" : "Disabled";
      const action = ACTIONS[snapshot.action] ?? snapshot.action;
      this._element("state").textContent =
        [status, action, `IPv${snapshot.family.slice(-1)}`].filter(Boolean).join(" · ");
      for (const field of ["enabled", "block_quic"]) {
        this._element(field).checked = snapshot.values[field];
      }
      for (const field of POLICIES) {
        const input = this._element(field);
        const current = snapshot.values[field];
        const options = snapshot.options[field];
        input.replaceChildren(new Option("None", ""));
        if (current && !options?.includes(current)) {
          input.add(new Option(current, current));
        }
        for (const option of options ?? []) input.add(new Option(option, option));
        input.value = current ?? "";
        const note = input.nextElementSibling;
        note.hidden = !snapshot.policy_editable || options !== null;
        note.textContent = note.hidden ? "" : "Policy list unavailable.";
      }
      const policyNote = this._element("policy-note");
      policyNote.hidden = snapshot.policy_editable;
      policyNote.textContent = policyNote.hidden ? "" : "Policy editing is available on standard allow rules.";
    }
    this._updateControls();
  }

  _changes() {
    return Object.fromEntries(
      Object.entries(this._draft ?? {}).filter(([field, value]) =>
        value !== this._snapshot.values[field]
      )
    );
  }

  _updateControls() {
    const dirty = Object.keys(this._changes()).length > 0;
    this._rulePicker.disabled = this._busy || dirty;
    this._search.disabled = this._busy || dirty;
    this._element("refresh").disabled = this._busy || dirty;
    this._element("enabled").disabled = this._busy;
    this._element("cancel").disabled = this._busy || !dirty;
    this._element("apply").disabled = this._busy || !dirty;
    if (this._snapshot) {
      const { policy_editable, scans_web, options } = this._snapshot;
      for (const field of POLICIES) {
        this._element(field).disabled = this._busy || !policy_editable || !options[field];
      }
      const canEnableQuic = scans_web || Boolean(this._draft.web_policy);
      this._element("block_quic").disabled =
        this._busy || !policy_editable || (!canEnableQuic && !this._draft.block_quic);
      this._element("quic-note").hidden = !policy_editable || canEnableQuic;
    }
  }

  _apply() {
    return this._run(async () => {
      const changes = this._changes();
      if (!Object.keys(changes).length) return "";
      const snapshot = await this._hass.callWS({
        type: `${DOMAIN}/edit_rule`,
        ...this._target(),
        revision: this._snapshot.revision,
        changes,
      });
      this._showSnapshot({ ...snapshot, options: this._snapshot.options });
      return "Changes confirmed by Sophos.";
    }, "Applying changes…");
  }
}

if (!customElements.get(TAG)) {
  customElements.define(TAG, SophosFirewallRuleCard);
  window.customCards = window.customCards ?? [];
  window.customCards.push({
    type: TAG,
    name: "Sophos Firewall Rule",
    description: "View and edit the settings of a selected firewall rule.",
    preview: false,
  });
}
