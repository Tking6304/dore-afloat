/* Runs the DORE server logic inside the browser for the standalone HTML file.
   It answers the same /api routes as server.py, so the screen code is unchanged.
   Keep it in step with server.py, reasoner.py and packet_pdf.py; check_parity.py compares them. */
(function () {
  const DATA = window.DORE_DATA;
  const LIB = DATA.library;
  const ROLES = {
    EOOW: { label: 'Engineering Officer of the Watch', confirm: true },
    DCA: { label: 'Damage Control Assistant', confirm: true },
    OOD: { label: 'Officer of the Deck', confirm: true },
    MESSENGER: { label: 'Messenger of the Watch', confirm: false },
  };
  const SENSOR_STALE_S = 60, DUE_BASE = 15, DUE_EACH = 15;
  const sessions = {};
  let incident = {};
  let counter = Math.floor(Date.now() / 1000);
  let auditRows = [];
  const clone = v => JSON.parse(JSON.stringify(v));
  const seconds = () => Date.now() / 1000;
  const empty = o => !o || !Object.keys(o).length;
  const iso = () => new Date().toISOString().slice(0, 19) + 'Z';
  const now = () => new Date().toISOString().slice(11, 19) + 'Z';
  const today = () => new Date().toISOString().slice(0, 10) + ' ';
  const norm = t => t.replace(/\s+/g, ' ').trim().toLowerCase();
  const reEsc = t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  /* SHA-256, so the audit chain needs no secure context */
  function sha256(text) {
    const bytes = new TextEncoder().encode(text);
    const K = [], H = [];
    let n = 0, c = 2;
    const frac = x => ((x - Math.floor(x)) * 4294967296) | 0;
    while (n < 64) {
      let prime = true;
      for (let i = 2; i * i <= c; i++) if (c % i === 0) { prime = false; break; }
      if (prime) { if (n < 8) H[n] = frac(Math.pow(c, 1 / 2)); K[n++] = frac(Math.pow(c, 1 / 3)); }
      c++;
    }
    const length = bytes.length, padded = new Uint8Array(((length + 9 + 63) >> 6) << 6);
    padded.set(bytes); padded[length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(length / 536870912));
    view.setUint32(padded.length - 4, (length << 3) >>> 0);
    const rotr = (x, r) => (x >>> r) | (x << (32 - r));
    const w = new Int32Array(64);
    for (let o = 0; o < padded.length; o += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getInt32(o + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], b = w[i - 2];
        w[i] = (w[i - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + w[i - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) | 0;
      }
      let [a, b, cc, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = cc; cc = b; b = a; a = (t1 + t2) | 0;
      }
      [a, b, cc, d, e, f, g, h].forEach((v, i) => { H[i] = (H[i] + v) | 0; });
    }
    return H.map(v => (v >>> 0).toString(16).padStart(8, '0')).join('');
  }

  /* Audit log */
  const entryHash = r => sha256([r.seq, r.ts, r.actor, r.role, r.event, r.detail, r.prev_hash].join('|'));
  function audit(actor, role, event, detail) {
    const last = auditRows[auditRows.length - 1];
    const keys = Object.keys(detail).sort(), sorted = {};
    keys.forEach(k => { sorted[k] = detail[k]; });
    const row = { seq: last ? last.seq + 1 : 1, ts: iso(), actor, role, event, detail: JSON.stringify(sorted), prev_hash: last ? last.hash : 'GENESIS' };
    row.hash = entryHash(row);
    auditRows.push(row);
  }
  function verifyAudit() {
    let prev = 'GENESIS';
    for (const r of auditRows) {
      if (r.prev_hash !== prev || r.hash !== entryHash({ ...r, prev_hash: prev })) return { ok: false, entries: auditRows.length, broken_at: r.seq };
      prev = r.hash;
    }
    return { ok: true, entries: auditRows.length, broken_at: null };
  }

  /* Reasoner */
  function ratio(a, b) {
    const matches = (s, t) => {
      let best = 0, si = 0, ti = 0;
      for (let i = 0; i < s.length; i++) for (let j = 0; j < t.length; j++) {
        let k = 0;
        while (i + k < s.length && j + k < t.length && s[i + k] === t[j + k]) k++;
        if (k > best) { best = k; si = i; ti = j; }
      }
      return best ? best + matches(s.slice(0, si), t.slice(0, ti)) + matches(s.slice(si + best), t.slice(ti + best)) : 0;
    };
    return (2 * matches(a, b)) / (a.length + b.length);
  }
  const SINGLE = [...new Set(LIB.hazards.flatMap(h => h.words).filter(w => !w.includes(' ') && w.length >= 5))].sort();
  function fixTypos(low) {
    return low.split(' ').map(word => {
      const bare = word.replace(/^[.,;:!?]+|[.,;:!?]+$/g, '');
      if (bare.length < 5 || SINGLE.includes(bare)) return word;
      let best = null, score = 0.84;
      SINGLE.forEach(w => { const r = ratio(bare, w); if (r >= score) { score = r; best = w; } });
      return best ? word.replace(bare, best) : word;
    }).join(' ');
  }
  function wordFound(word, low) {
    const m = new RegExp('\\b' + reEsc(word) + '\\b').exec(low);
    if (!m) return false;
    const before = low.slice(0, m.index);
    return !LIB.negations.some(n => before.endsWith(n));
  }
  const capitalize = t => t.charAt(0).toUpperCase() + t.slice(1).toLowerCase();
  function findLocation(pack, low) {
    const aliases = [];
    Object.entries(pack.spaces).forEach(([id, s]) => s.aliases.forEach(a => aliases.push([a, id])));
    aliases.sort((x, y) => y[0].length - x[0].length);
    for (const [alias, id] of aliases) if (new RegExp('\\b' + reEsc(alias) + '\\b').test(low)) return [id, pack.spaces[id].name];
    const nouns = LIB.location_words.join('|');
    const pattern = new RegExp('\\b(?:in|at|on|near|inside|from)\\s+(?:the\\s+|a\\s+|our\\s+)?((?:[a-z0-9]+\\s+){0,2}?(?:' + nouns + ')(?:\\s+[0-9]+)?)\\b', 'g');
    const found = [...low.matchAll(pattern)];
    return found.length ? [null, capitalize(found[found.length - 1][1].trim())] : [null, null];
  }
  function understand(pack, report) {
    const low = fixTypos(norm(report));
    const guard = LIB.not_a_casualty.find(g => (low + ' ').includes(g));
    const hazards = LIB.hazards.filter(h => h.words.some(w => wordFound(w, low)));
    const named = pack.casualties.filter(c => c.always && c.keywords.some(k => wordFound(k, low)));
    if (guard || (!hazards.length && !named.length)) return { casualty: false };
    let [spaceId, location] = findLocation(pack, low);
    const side = ['port', 'starboard'].find(s => wordFound(s, low)) || null;
    const magazine = LIB.magazine.words.some(w => wordFound(w, low));
    const ids = new Set(hazards.map(h => h.id));
    let exact = named[0] || null;
    if (!exact) {
      exact = pack.casualties.find(c => {
        const covers = new Set(c.hazards || []);
        return covers.size && [...ids].every(i => covers.has(i)) && (c.spaces || []).includes(spaceId) && !magazine;
      }) || null;
    }
    if (exact && !spaceId && !(side && exact.default_space == null)) {
      spaceId = exact.default_space || null;
      if (spaceId) location = pack.spaces[spaceId].name;
    }
    return { casualty: true, low, hazards, space_id: spaceId, location, side, magazine, exact };
  }
  const needsLocation = u => !u.hazards.length || !u.hazards.every(h => h.shipwide);
  function asks(u) {
    const q = [];
    if (needsLocation(u) && !u.location) q.push('Which compartment?');
    else if (needsLocation(u) && !u.space_id) q.push(`What is the compartment number for ${u.location}?`);
    u.hazards.forEach(h => { if (h.ask) q.push(h.ask); });
    if (!u.hazards.some(h => h.id === 'injury')) q.push('Is anyone injured or missing?');
    return q.slice(0, 4);
  }
  function explain(u, exact) {
    const names = u.hazards.map(h => h.label.toLowerCase()), ids = new Set(u.hazards.map(h => h.id)), lines = [];
    if (names.length) lines.push('Heard: ' + names.join(', ') + '.');
    if (!needsLocation(u)) lines.push('This affects the whole ship, so no compartment is needed.');
    else if (u.location && u.space_id) lines.push(`Location matched to the ship map: ${u.location}.`);
    else if (u.location) lines.push(`Location '${u.location}' isn't on the ship map, so confirm it.`);
    else lines.push('No location given, so confirming it comes first.');
    lines.push(exact ? `Exact procedure found: ${exact.name}.` : 'No exact procedure, so this plan is built from approved general actions.');
    if (ids.has('electrical') && (ids.has('fire') || ids.has('flooding'))) lines.push('Electrical hazard moved first: no water until the circuit is dead.');
    if (ids.has('smoke') && !ids.has('fire')) lines.push('Smoke is treated as a fire until the source is found.');
    if (ids.has('injury')) lines.push('Injury raises life safety ahead of fighting the casualty.');
    if (u.magazine) lines.push('Magazine or ammunition nearby, so that report moves up.');
    return lines;
  }
  function confidence(u, exact) {
    if (exact && (u.space_id || u.side || exact.always)) return 'HIGH';
    return u.location || !needsLocation(u) ? 'MEDIUM' : 'LOW';
  }
  const PRIORITY = ['fire', 'flooding', 'gas', 'steam', 'fuel', 'electrical', 'smoke', 'power', 'steering', 'injury'];
  const byPriority = list => list.slice().sort((a, b) => PRIORITY.indexOf(a.id) - PRIORITY.indexOf(b.id));
  function leadHazard(hazards) {
    const ids = new Set(hazards.map(h => h.id));
    if (ids.has('fire') && ids.has('electrical')) return 'Electrical Fire';
    return hazards.length ? byPriority(hazards)[0].label : 'Casualty';
  }
  function planName(hazards) {
    const lead = leadHazard(hazards);
    const covered = lead === 'Electrical Fire' ? ['fire', 'electrical', 'smoke'] : lead === 'Fire' ? ['fire', 'smoke'] : hazards.filter(h => h.label === lead).map(h => h.id);
    const others = byPriority(hazards).filter(h => !covered.includes(h.id)).map(h => h.label);
    return lead + (others.length ? ' with ' + others.join(' and ') : '');
  }
  function compose(pack, u) {
    const equipment = pack.general_equipment, station = pack.station_map || {};
    const names = Object.fromEntries(pack.equipment.map(e => [e.id, e.name]));
    let chosen = clone(LIB.common);
    if (!u.space_id && needsLocation(u)) chosen.push(clone(LIB.confirm_location));
    const ids = new Set(u.hazards.map(h => h.id));
    u.hazards.forEach(h => { chosen = chosen.concat(clone(h.steps)); });
    if (ids.has('smoke') && !ids.has('fire')) {
      const fire = LIB.hazards.find(h => h.id === 'fire');
      chosen = chosen.concat(clone(fire.steps.filter(s => ['F2', 'F3', 'F4', 'F5', 'F6'].includes(s.id))));
    }
    if (u.magazine) chosen.push(clone(LIB.magazine.step));
    const seen = new Set(), actions = [];
    chosen.map((s, i) => [s, i]).sort((a, b) => a[0].rank - b[0].rank || a[1] - b[1]).forEach(([step]) => {
      if (seen.has(step.quote)) return;
      seen.add(step.quote);
      step.doc = 'GEN';
      step.owner = station[step.owner] || step.owner;
      step.needs = (step.needs || []).map(n => equipment[n.slice(1)]);
      Object.entries(equipment).forEach(([key, value]) => { step.title = step.title.replace('{' + key + '}', names[value]); });
      actions.push(step);
    });
    const injects = [];
    u.hazards.forEach(h => {
      if (!h.inject) return;
      const equipmentId = equipment[h.inject.equipment.slice(1)];
      injects.push({ ...h.inject, equipment: equipmentId, label: `${names[equipmentId].toUpperCase()} FAILS` });
    });
    const top = leadHazard(u.hazards);
    const comms = LIB.comms.map(item => {
      let text = item.text.split('{hazard_list}').join(planName(u.hazards)).split('{hazard}').join(top);
      if (!needsLocation(u)) text = text.split(' reported in {location}.').join(' reported.').split(' All hands stand clear of {location}.').join(' All hands stand by.').split('Investigate {location}.').join('Stand by to assist.');
      return { ...item, speaker: station[item.speaker] || item.speaker, text };
    });
    const serious = u.hazards.some(h => h.serious) || u.magazine;
    return { id: 'built-' + [...ids].sort().join('-'), name: planName(u.hazards), severity: serious ? 'CRITICAL' : 'SERIOUS', actions, comms, injects, built: true };
  }
  function reason(pack, report) {
    const u = understand(pack, report);
    if (!u.casualty) return [null, u];
    if (!u.location && !needsLocation(u)) u.location = 'Ship-wide';
    const casualty = u.exact || compose(pack, u);
    u.reasoning = { built: !u.exact, confidence: confidence(u, u.exact), lines: explain(u, u.exact), ask: asks(u), hazards: u.hazards.map(h => h.label) };
    return [casualty, u];
  }

  /* Agents */
  const citation = (pack, doc, para, quote) => ({ doc, title: pack.documents[doc].title, rev: pack.documents[doc].rev, para, quote });
  function median(values) {
    const v = values.slice().sort((a, b) => a - b), m = Math.floor(v.length / 2);
    return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
  }
  function checkSensors(pack, spaceId) {
    const group = pack.sensors.filter(s => s.space === spaceId);
    const middle = group.length ? median(group.map(s => s.value)) : 0;
    return group.map(s => {
      const problems = [], off = Math.abs(s.value - middle), limit = pack.sensor_tolerance[s.unit];
      if (s.age_s > SENSOR_STALE_S) problems.push(`no update for ${s.age_s} s`);
      if (limit !== undefined && off > limit) problems.push(`off by ${off.toFixed(0)} ${s.unit} from nearby sensors`);
      return { ...s, trusted: !problems.length, problems };
    });
  }
  function unavailable(pack, failed) {
    const down = {};
    pack.tagouts.filter(t => t.status === 'Active').forEach(t => { down[t.equipment] = { ...t, kind: 'TAGGED OUT' }; });
    (failed || []).forEach(e => { down[e] = { id: 'FAILED', equipment: e, reason: 'Failed during the casualty', authorized_by: 'Reported by watch', kind: 'FAILED', rule: null }; });
    return down;
  }
  function agentTriage(pack, casualty, u, report, failed, reportedAt) {
    const needed = new Set(casualty.actions.flatMap(a => a.needs));
    const names = Object.fromEntries(pack.equipment.map(e => [e.id, e]));
    const down = unavailable(pack, failed);
    const location = u.side ? `${capitalize(u.side)} side` : u.location || 'Location unknown';
    const tagouts = [...needed].filter(e => down[e]).map(e => ({ id: down[e].id, equipment: names[e].name, reason: down[e].reason, authorized_by: down[e].authorized_by, kind: down[e].kind }));
    const equipment = pack.equipment.filter(e => e.space === u.space_id || needed.has(e.id)).map(e => ({ ...e, state: down[e.id] ? capitalize(down[e.id].kind) : e.state }));
    return { casualty: casualty.name, severity: casualty.severity, location, report, time: reportedAt || now(), equipment, tagouts, sensors: checkSensors(pack, u.space_id), reasoning: u.reasoning };
  }
  function agentActions(pack, casualty, side, failed) {
    const down = unavailable(pack, failed);
    const names = Object.fromEntries(pack.equipment.map(e => [e.id, e.name]));
    const verified = [], dropped = [];
    casualty.actions.forEach(card => {
      if (norm(pack.source_text[card.doc] || '').includes(norm(card.quote))) verified.push(card);
      else dropped.push({ id: card.id, title: card.title });
    });
    const blockedIds = new Set(verified.filter(c => c.needs.some(n => down[n])).map(c => c.id));
    const fallbackFor = {};
    verified.forEach(c => { if (c.only_if_blocked) fallbackFor[c.only_if_blocked] = c; });
    const replacement = id => {
      let option = fallbackFor[id];
      while (option && blockedIds.has(option.id)) option = fallbackFor[option.id];
      return option;
    };
    const steps = [], blocked = [];
    verified.slice().sort((a, b) => a.rank - b.rank).forEach(card => {
      const trigger = card.only_if_blocked;
      if (trigger && !blockedIds.has(trigger)) return;
      const title = card.title.split('{side}').join(side || 'reported side');
      const cite = citation(pack, card.doc, card.para, card.quote);
      if (blockedIds.has(card.id)) {
        const item = down[card.needs.find(n => down[n])], option = replacement(card.id), rule = item.rule;
        blocked.push({ id: card.id, title, equipment: names[item.equipment], kind: item.kind, tagout: item.id, reason: item.reason, use_instead: option ? option.title : null, citation: rule ? citation(pack, rule.doc, rule.para, rule.quote) : cite });
        return;
      }
      steps.push({ id: card.id, title, owner: card.owner, citation: cite, fallback: !!trigger, status: card.status || null, needs: card.needs });
    });
    steps.forEach((s, i) => { s.order = i + 1; s.due_s = DUE_BASE + DUE_EACH * (i + 1); });
    return { steps, blocked, dropped, verified: verified.length };
  }
  function agentTasking(actions) {
    const teams = new Map();
    actions.steps.forEach(s => {
      if (!teams.has(s.owner)) teams.set(s.owner, []);
      teams.get(s.owner).push({ title: s.title, ref: `${s.citation.doc} ${s.citation.para}` });
    });
    return { teams: [...teams].map(([station, tasks]) => ({ station, tasks })) };
  }
  function agentComms(casualty, triage, actions, side) {
    const lines = actions.blocked.map(b => `${b.equipment} ${b.kind.toLowerCase()}.`);
    const options = [...new Set(actions.blocked.map(b => b.use_instead).filter(Boolean))].map(o => `${o}.`);
    const status = lines.concat(options).join(' ');
    const messages = casualty.comms.map(item => {
      const text = item.text.split('{location}').join(triage.location).split('{side}').join(side || 'reported side').split('{status}').join(status);
      return { channel: item.channel, speaker: item.speaker, text: text.replace(/\s+/g, ' ').trim() };
    });
    return { messages };
  }
  function agentRecords() {
    if (empty(incident)) return null;
    const t = incident.triage, a = incident.actions, done = incident.done;
    const log = [`${t.time}  ${t.casualty} reported, ${t.location}.`];
    a.blocked.filter(b => b.kind !== 'FAILED').forEach(b => log.push(`${t.time}  DORE: ${b.equipment} tagged out (${b.tagout}).`));
    incident.changes.forEach(c => log.push(`${c.at}  PLAN CHANGE: ${c.note}`));
    done.forEach(d => log.push(`${d.at}  ${d.role} ${d.verb}: ${d.title}.`));
    if (incident.ended) log.push(`${incident.ended_at}  Casualty secured.`);
    const untrusted = t.sensors.filter(s => !s.trusted).map(s => s.name);
    return { watch_log: log, ics201: [
      ['Incident', `${incident.ship} ${t.casualty}`], ['Time', today() + t.time], ['Location', `${incident.ship}, ${t.location}`], ['Situation', t.report],
      ['Actions complete', done.map(d => d.title).join('; ') || 'None yet'],
      ['Out of service', t.tagouts.map(x => `${x.equipment} (${x.id})`).join('; ') || 'None'],
      ['Do not trust', untrusted.join('; ') || 'None'], ['Prepared by', `${incident.name}, ${incident.role}`],
    ] };
  }
  function agentDebrief() {
    if (empty(incident)) return null;
    const t = incident.triage, done = Object.fromEntries(incident.done.map(d => [d.id, d]));
    const length = incident.ended ? incident.ended_s : Math.round(seconds() - incident.started);
    const rows = incident.actions.steps.map(s => {
      const record = done[s.id];
      const result = record ? (record.elapsed_s > s.due_s ? 'Late' : 'On time') : length > s.due_s ? 'Overdue' : 'Open';
      return { id: s.id, order: s.order, title: s.title, owner: s.owner, due_s: s.due_s, done_s: record ? record.elapsed_s : null, result };
    });
    const count = r => rows.filter(x => x.result === r).length;
    const onTime = count('On time'), late = count('Late'), overdue = count('Overdue'), open = count('Open') + overdue;
    const judged = incident.ended ? rows.length : onTime + late + overdue;
    const missed = incident.ended ? ['Late', 'Overdue', 'Open'] : ['Late', 'Overdue'];
    const practice = rows.filter(r => missed.includes(r.result)).map(r => `${r.title} (${r.owner})`).slice(0, 3);
    const report = [
      ['Ship', incident.ship], ['Casualty', t.casualty], ['Location', t.location], ['Reported', t.time], ['Duration', `${length} seconds`], ['Cause', 'Under investigation'],
      ['Equipment affected', t.tagouts.map(x => `${x.equipment} (${x.kind.toLowerCase()})`).join('; ') || 'None'],
      ['Plan changes', incident.changes.map(c => c.note).join('; ') || 'None'],
      ['Actions complete', incident.done.map(d => d.title).join('; ') || 'None'],
      ['Actions open', rows.filter(r => r.result === 'Open').map(r => r.title).join('; ') || 'None'],
      ['Status', incident.ended ? 'Secured' : 'Open'],
    ];
    return { rows, on_time: onTime, late, overdue, open, total: rows.length, score: judged ? Math.round((100 * onTime) / judged) : 100, practice, length_s: length,
      drill: incident.drill, ended: incident.ended, report, changes: incident.changes.map(c => c.note), casualty: t.casualty, location: t.location };
  }
  function mapView(pack, spaceId, steps, down) {
    const plan = pack.map || { spaces: [], boundaries: {} };
    const boundaries = spaceId ? plan.boundaries[spaceId] || [] : [];
    const use = new Set(steps.filter(s => s.fallback).flatMap(s => s.needs));
    const marks = [];
    pack.equipment.forEach(e => {
      if (down[e.id]) marks.push({ space: e.space, name: e.name, state: 'down' });
      else if (use.has(e.id)) marks.push({ space: e.space, name: e.name, state: 'use' });
    });
    return { spaces: plan.spaces.map(s => ({ ...s, state: s.id === spaceId ? 'casualty' : boundaries.includes(s.id) ? 'boundary' : 'normal' })), marks };
  }
  function agentBrief(user) {
    const pack = DATA.packs[user.pack], stations = pack.role_stations[user.role];
    const plans = pack.casualties.map(c => {
      const actions = agentActions(pack, c, null);
      const mine = actions.steps.filter(s => !stations || stations.includes(s.owner));
      return { casualty: c.name, changes: actions.blocked.map(b => ({ equipment: b.equipment, tagout: b.tagout, use_instead: b.use_instead })), first: mine.length ? mine[0].title.split('reported side').join('the reported side') : null };
    });
    let distrust = [];
    [...new Set(pack.sensors.map(s => s.space))].forEach(id => { distrust = distrust.concat(checkSensors(pack, id).filter(s => !s.trusted).map(s => ({ name: s.name, problems: s.problems }))); });
    distrust.sort((a, b) => a.name.localeCompare(b.name));
    const parts = [`Watch brief for ${user.role} on ${pack.ship.name}.`];
    plans.forEach(p => {
      p.changes.forEach(c => parts.push(`${p.casualty}: ${c.equipment} is down. ${c.use_instead || 'No substitute'}.`));
      if (p.first) parts.push(`Your first step: ${p.first}.`);
    });
    distrust.forEach(s => parts.push(`Do not trust ${s.name}.`));
    return { ship: pack.ship.name, plans, distrust, speech: parts.join(' '), map: mapView(pack, null, [], unavailable(pack)) };
  }
  function payload() {
    if (empty(incident)) return { id: 0, ver: 0 };
    const out = {};
    ['id', 'ver', 'drill', 'triage', 'actions', 'tasking', 'comms', 'timings', 'total_ms', 'changes', 'map'].forEach(k => { out[k] = incident[k]; });
    const injects = (incident.casualty.injects || []).filter(i => !incident.failed.includes(i.equipment)).map(i => ({ id: i.id, label: i.label }));
    return { ...out, kind: 'answer', records: agentRecords(), done: incident.done.map(d => d.id), done_detail: incident.done, ended: incident.ended, injects, debrief: incident.ended ? agentDebrief() : null };
  }
  function overdueSteps() {
    if (empty(incident) || incident.ended) return [];
    const elapsed = seconds() - incident.started, done = new Set(incident.done.map(d => d.id)), late = [];
    incident.actions.steps.forEach(s => {
      if (done.has(s.id) || elapsed <= s.due_s) return;
      late.push({ id: s.id, title: s.title, owner: s.owner, late_s: Math.round(elapsed - s.due_s), script: `${s.owner}, report status: ${s.title}.` });
      if (!incident.overdue_logged.includes(s.id)) {
        incident.overdue_logged.push(s.id);
        audit('DORE', 'AGENT', 'OVERDUE', { step: s.id, owner: s.owner });
      }
    });
    return late;
  }
  function runAgents(user, report, drill) {
    const pack = DATA.packs[user.pack];
    const [casualty, u] = reason(pack, report);
    if (!casualty) {
      audit(user.name, user.role, 'REFUSED', { report });
      return { kind: 'refusal', message: 'No approved procedure found', hint: 'DORE answers only from approved documents. State the hazard you see and the space.' };
    }
    const timings = {};
    const timed = (key, fn) => {
      const start = performance.now(), result = fn();
      timings[key] = Math.round((performance.now() - start) * 100) / 100;
      audit('DORE', 'AGENT', key, { casualty: casualty.id });
      return result;
    };
    audit(user.name, user.role, drill ? 'DRILL_REPORT' : 'REPORT', { report });
    const triage = timed('A1_TRIAGE', () => agentTriage(pack, casualty, u, report));
    const actions = timed('A2_ACTIONS', () => agentActions(pack, casualty, u.side));
    const tasking = timed('A3_TASKING', () => agentTasking(actions));
    const comms = timed('A4_COMMS', () => agentComms(casualty, triage, actions, u.side));
    counter += 1;
    incident = { id: counter, ver: 1, drill: !!drill, started: seconds(), pack: user.pack, ship: pack.ship.name, casualty, understood: u, space_id: u.space_id, side: u.side, triage, actions, tasking, comms,
      name: user.name, role: user.role, done: [], failed: [], changes: [], overdue_logged: [], ended: false, ended_at: null, ended_s: 0, timings, total_ms: 0,
      map: mapView(pack, u.space_id, actions.steps, unavailable(pack)) };
    timed('A5_RECORDS', agentRecords);
    incident.total_ms = Math.round(Object.values(timings).reduce((x, y) => x + y, 0) * 10) / 10;
    return payload();
  }
  function replan(user, injectId) {
    if (empty(incident) || incident.ended) return [400, { error: 'No open casualty' }];
    const pack = DATA.packs[incident.pack], casualty = incident.casualty;
    const inject = (casualty.injects || []).find(i => i.id === injectId);
    if (!inject || incident.failed.includes(inject.equipment)) return [400, { error: 'Nothing to change' }];
    const start = performance.now();
    incident.failed.push(inject.equipment);
    const failed = incident.failed, side = incident.side;
    const triage = agentTriage(pack, casualty, incident.understood, incident.triage.report, failed, incident.triage.time);
    const actions = agentActions(pack, casualty, side, failed);
    Object.assign(incident, { triage, actions, tasking: agentTasking(actions), comms: agentComms(casualty, triage, actions, side), map: mapView(pack, incident.space_id, actions.steps, unavailable(pack, failed)) });
    const name = pack.equipment.find(e => e.id === inject.equipment).name;
    const hit = actions.blocked.find(b => b.equipment === name);
    const note = `${name} failed. ${(hit && hit.use_instead) || 'No approved substitute'}.`;
    const ms = Math.round((performance.now() - start) * 100) / 100;
    incident.changes.push({ at: now(), note, ms });
    incident.ver += 1;
    audit(user.name, user.role, 'PLAN_CHANGE', { failed: inject.equipment, note, ms });
    return [200, payload()];
  }
  function recordStep(user, step, verb) {
    incident.done.push({ id: step.id, title: step.title, role: user.role, at: now(), elapsed_s: Math.round(seconds() - incident.started), verb });
    incident.ver += 1;
    const c = step.citation;
    audit(user.name, user.role, verb === 'completed' ? 'STEP_DONE' : 'STATUS_LOGGED', { step: step.id, source: `${c.title} ${c.rev} para ${c.para}` });
  }
  function markDone(user, stepId) {
    if (incident.ended) return [409, { error: 'Casualty is secured' }];
    const step = ((incident.actions || {}).steps || []).find(s => s.id === stepId);
    if (!step) return [400, { error: 'Unknown step.' }];
    if (!ROLES[user.role].confirm) {
      audit(user.name, user.role, 'DENIED', { step: stepId, why: 'role cannot confirm' });
      return [403, { error: `${user.role} can view but cannot confirm steps` }];
    }
    if (incident.done.some(d => d.id === stepId)) return [409, { error: 'Step already complete' }];
    if (!(DATA.packs[user.pack].role_stations[user.role] || []).includes(step.owner)) {
      audit(user.name, user.role, 'DENIED', { step: stepId, why: 'other station' });
      return [403, { error: `This step belongs to ${step.owner}` }];
    }
    recordStep(user, step, 'completed');
    return [200, payload()];
  }
  function endCasualty(user) {
    if (empty(incident) || incident.ended) return [400, { error: 'No open casualty' }];
    if (!ROLES[user.role].confirm) return [403, { error: `${user.role} can view but cannot end the casualty` }];
    incident.ended = true; incident.ended_at = now(); incident.ended_s = Math.round(seconds() - incident.started); incident.ver += 1;
    audit('DORE', 'AGENT', 'A6_DEBRIEF', { score: agentDebrief().score });
    audit(user.name, user.role, 'CASUALTY_SECURED', { seconds: incident.ended_s });
    return [200, payload()];
  }

  /* PDF packet */
  const W = 612, HGT = 792, M = 48, BOTTOM = 56, WIDTH = W - 2 * M;
  const NAVY = [0.03, 0.10, 0.17], INK = [0.08, 0.10, 0.13], QUIET = [0.38, 0.43, 0.48], RULE = [0.80, 0.83, 0.86];
  const RED = [0.80, 0.10, 0.10], BLUE = [0.0, 0.42, 0.72], ORANGE = [0.85, 0.42, 0.0], GREEN = [0.0, 0.50, 0.32], VIOLET = [0.45, 0.20, 0.72], WHITE = [1, 1, 1];
  const FONTS = { body: 'F1', bold: 'F2', mono: 'F3' }, PER = { body: 0.5, bold: 0.55, mono: 0.6 };
  const pdfEsc = v => String(v).replace(/[^\x00-\xff]/g, '?').replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  function wrap(text, size, width, font) {
    const limit = Math.max(1, Math.floor(width / (PER[font || 'body'] * size)));
    const lines = []; let line = '';
    String(text).split(/\s+/).filter(Boolean).forEach(word => {
      if (line && line.length + 1 + word.length > limit) { lines.push(line); line = word; }
      else line = (line + ' ' + word).trim();
    });
    return line ? lines.concat(line) : lines.length ? lines : [''];
  }
  function buildPacket(inc, records, status, debrief) {
    const pages = [[]]; let y = HGT - 48;
    const draw = c => pages[pages.length - 1].push(c);
    const newPage = () => { pages.push([]); y = HGT - 48; };
    const need = h => { if (y - h < BOTTOM) newPage(); };
    const text = (x, yy, v, size = 10, font = 'body', c = INK) => draw(`${c[0]} ${c[1]} ${c[2]} rg BT /${FONTS[font]} ${size} Tf ${x} ${yy} Td (${pdfEsc(v)}) Tj ET`);
    const rect = (x, yy, w, h, c) => draw(`${c[0]} ${c[1]} ${c[2]} rg ${x} ${yy} ${w} ${h} re f`);
    const box = (x, yy, w, h, c) => draw(`${c[0]} ${c[1]} ${c[2]} RG 0.8 w ${x} ${yy} ${w} ${h} re S`);
    const rule = yy => draw(`${RULE[0]} ${RULE[1]} ${RULE[2]} RG 0.5 w ${M} ${yy} m ${W - M} ${yy} l S`);
    const paragraph = (v, o = {}) => {
      const { x = M, width = WIDTH, size = 10, font = 'body', color = INK } = o, leading = o.leading || size + 3.5;
      wrap(v, size, width, font).forEach(l => { need(leading); y -= leading; text(x, y, l, size, font, color); });
    };
    const heading = (title, c, tag) => {
      need(52); y -= 12; rect(M, y - 18, 4, 18, c); text(M + 12, y - 13, title.toUpperCase(), 11.5, 'bold', NAVY);
      if (tag) text(W - M - 46, y - 13, tag, 9, 'mono', c);
      y -= 23; rule(y); y -= 3;
    };
    const field = (label, value, c = INK) => {
      const lines = wrap(value, 10, WIDTH - 112);
      need(14 * lines.length + 2); y -= 14;
      text(M, y, label.toUpperCase(), 8, 'mono', QUIET); text(M + 112, y, lines[0], 10, 'body', c);
      lines.slice(1).forEach(l => { y -= 13; text(M + 112, y, l, 10, 'body', c); });
    };
    const t = inc.triage, a = inc.actions, done = Object.fromEntries(inc.done.map(d => [d.id, d]));
    rect(0, HGT - 92, W, 92, NAVY);
    text(M, HGT - 42, 'D.O.R.E. AFLOAT', 20, 'bold', WHITE);
    text(M, HGT - 60, 'CASUALTY RESPONSE PACKET', 10, 'mono', [0.55, 0.80, 1]);
    text(M, HGT - 78, `${inc.ship}  //  ${t.location}`, 10, 'body', WHITE);
    rect(W - M - 128, HGT - 50, 128, 22, RED);
    text(W - M - 118, HGT - 43, inc.drill ? 'DRILL' : `${t.severity} CASUALTY`, 9.5, 'bold', WHITE);
    text(W - M - 144, HGT - 78, `Generated ${new Date().toISOString().slice(0, 19).replace('T', ' ')}Z`, 8, 'mono', [0.75, 0.85, 0.95]);
    y = HGT - 100;
    heading('Casualty brief', BLUE, 'AGENT 1');
    field('Casualty', t.casualty, RED); field('Location', t.location); field('Reported', t.time); field('Report', t.report);
    field('Out of service', t.tagouts.map(x => `${x.equipment} (${x.id}, ${x.reason})`).join('; ') || 'None', t.tagouts.length ? RED : INK);
    const distrust = t.sensors.filter(s => !s.trusted).map(s => `${s.name}: ${s.value} ${s.unit} (${s.problems.join(', ')})`);
    field('Do not trust', distrust.join('; ') || 'None', distrust.length ? RED : INK);
    const why = t.reasoning;
    field('Confidence', why.confidence + (why.built ? ' (built from general procedures, confirm before acting)' : ''), why.built ? ORANGE : GREEN);
    field('Reasoning', why.lines.join(' '));
    if (why.ask.length) field('Ask next', why.ask.join(' '), ORANGE);
    heading('Immediate actions', RED, 'AGENT 2');
    a.steps.forEach(s => {
      const c = s.citation, finished = done[s.id];
      need(32); y -= 16; box(M, y - 2, 10, 10, QUIET);
      if (finished) rect(M + 2, y, 6, 6, GREEN);
      text(M + 18, y, `${s.order}. ${s.title}`, 11, 'bold');
      if (finished) text(W - M - 112, y, `Done ${finished.at} ${finished.role}`, 8, 'mono', GREEN);
      y -= 12; text(M + 18, y, `${s.owner}  //  ${c.title}, ${c.rev}, para ${c.para}`, 8, 'body', QUIET);
    });
    a.blocked.forEach(b => {
      const state = b.kind === 'FAILED' ? 'has failed' : `is tagged out under ${b.tagout}`;
      y -= 5; paragraph(`BLOCKED: ${b.title}. ${b.equipment} ${state}.${b.use_instead ? ` Use instead: ${b.use_instead}.` : ''}`, { size: 9.5, font: 'bold', color: RED });
    });
    a.dropped.forEach(d => { y -= 3; paragraph(`Draft removed: ${d.title}. Its quote is not in the source document.`, { size: 9, color: ORANGE }); });
    heading('Team assignments', ORANGE, 'AGENT 3');
    inc.tasking.teams.forEach(team => {
      need(30); y -= 7; paragraph(team.station.toUpperCase(), { size: 9, font: 'bold', color: ORANGE });
      team.tasks.forEach(task => paragraph(`${task.title}  (${task.ref})`, { x: M + 12, width: WIDTH - 12 }));
    });
    heading('Say this', GREEN, 'AGENT 4');
    inc.comms.messages.forEach(m => {
      need(44); y -= 7; paragraph(m.channel.toUpperCase(), { size: 8.5, font: 'bold', color: GREEN });
      paragraph(m.text, { x: M + 12, width: WIDTH - 12, size: 10.5 });
    });
    heading('Watch log', VIOLET, 'AGENT 5');
    records.watch_log.forEach(l => paragraph(l, { size: 8.5, font: 'mono', leading: 12 }));
    heading('ICS-201 draft', VIOLET, 'AGENT 5');
    records.ics201.forEach(([k, v]) => field(k, v));
    heading('Response summary', BLUE, 'AGENT 6');
    paragraph(`${debrief.on_time} on time, ${debrief.late} late, ${debrief.open} open (${debrief.overdue} overdue), out of ${debrief.total} steps.`, { font: 'bold' });
    debrief.rows.forEach(r => {
      const result = r.done_s === null ? r.result : `${r.result} at ${r.done_s} s`;
      need(15); y -= 14;
      text(M, y, `${r.order}. ${r.title}`, 9.5); text(M + 300, y, `due ${r.due_s} s`, 8, 'mono', QUIET);
      text(M + 370, y, result, 9, 'bold', r.result === 'On time' ? GREEN : RED);
    });
    if (debrief.practice.length) { y -= 6; paragraph('Practice next: ' + debrief.practice.join('; '), { size: 9.5, color: ORANGE }); }
    heading('Casualty report draft', BLUE, 'AGENT 6');
    debrief.report.forEach(([k, v]) => field(k, v));
    y -= 4; paragraph('Draft for review. Not a formal Navy report.', { size: 8.5, color: QUIET });
    heading('Audit status', QUIET);
    if (status.ok) paragraph(`Chain intact across ${status.entries} entries.`, { color: GREEN });
    else paragraph(`TAMPERING DETECTED at entry ${status.broken_at}.`, { font: 'bold', color: RED });
    const footer = 'CONCEPT DEMO. Fictional ship, notional procedures, synthetic data. Not for operational use.';
    pages.forEach((page, i) => {
      page.push(`${RULE[0]} ${RULE[1]} ${RULE[2]} RG 0.5 w ${M} 42 m ${W - M} 42 l S`);
      page.push(`${QUIET[0]} ${QUIET[1]} ${QUIET[2]} rg BT /F1 7.5 Tf ${M} 30 Td (${pdfEsc(footer)}) Tj ET`);
      page.push(`${QUIET[0]} ${QUIET[1]} ${QUIET[2]} rg BT /F1 7.5 Tf ${W - M - 44} 30 Td (Page ${i + 1} of ${pages.length}) Tj ET`);
    });
    const objects = { 1: '<< /Type /Catalog /Pages 2 0 R >>',
      3: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
      4: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
      5: '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>' };
    const kids = []; let next = 6;
    pages.forEach(page => {
      const stream = page.join('\n');
      kids.push(`${next} 0 R`);
      objects[next] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${HGT}] /Contents ${next + 1} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>`;
      objects[next + 1] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
      next += 2;
    });
    objects[2] = `<< /Type /Pages /Kids [${kids.join(' ')}] /Count ${kids.length} >>`;
    let out = '%PDF-1.4\n'; const offsets = {};
    Object.keys(objects).map(Number).sort((p, q) => p - q).forEach(n => { offsets[n] = out.length; out += `${n} 0 obj\n${objects[n]}\nendobj\n`; });
    const xref = out.length, size = next;
    out += `xref\n0 ${size}\n0000000000 65535 f \n`;
    for (let n = 1; n < size; n++) out += `${String(offsets[n]).padStart(10, '0')} 00000 n \n`;
    out += `trailer\n<< /Size ${size} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Uint8Array.from(out, c => c.charCodeAt(0));
  }

  /* The same routes as server.py */
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  function route(path, method, headers, body) {
    const url = new URL(path, 'http://dore.local'), p = url.pathname, user = sessions[headers['X-Session'] || ''];
    if (method === 'GET') {
      if (p === '/api/config') return json(200, { packs: Object.keys(DATA.packs).sort().map(id => {
        const k = DATA.packs[id];
        return { id, ...k.ship, buttons: k.casualties.map(c => ({ label: c.button, report: c.sample_report })), role_stations: k.role_stations };
      }), roles: ROLES });
      if (p === '/api/audit') return json(200, { rows: auditRows, verify: verifyAudit() });
      if (!user) return json(401, { error: 'Sign in first.' });
      if (p === '/api/state') {
        const have = [url.searchParams.get('id') || '0', url.searchParams.get('ver') || '0'], live = [String(incident.id || 0), String(incident.ver || 0)];
        return json(200, { id: incident.id || 0, ver: incident.ver || 0, overdue: overdueSteps(), elapsed: empty(incident) ? 0 : Math.round(seconds() - incident.started),
          full: have[0] !== live[0] || have[1] !== live[1] ? payload() : null });
      }
      if (p === '/api/brief') {
        if (url.searchParams.get('log') === '1') audit(user.name, user.role, 'WATCH_BRIEF', { pack: user.pack });
        return json(200, agentBrief(user));
      }
      if (p === '/api/summary') {
        if (empty(incident)) return json(400, { error: 'Run a casualty first' });
        audit(user.name, user.role, 'SUMMARY_VIEWED', { ended: incident.ended });
        return json(200, agentDebrief());
      }
      if (p === '/api/packet.pdf') {
        if (empty(incident)) return json(400, { error: 'Run a casualty first' });
        const data = buildPacket(incident, agentRecords(), verifyAudit(), agentDebrief());
        audit(user.name, user.role, 'PACKET_PDF', { bytes: data.length });
        return new Response(data, { status: 200, headers: { 'Content-Type': 'application/pdf' } });
      }
      if (p === '/api/source') {
        const text = DATA.packs[user.pack].source_text[url.searchParams.get('doc')];
        return text ? json(200, { text }) : json(404, { error: 'Unknown document.' });
      }
      return json(404, { error: 'Not found.' });
    }
    if (p === '/api/signin') {
      if (!ROLES[body.role] || !DATA.packs[body.pack]) return json(400, { error: 'Unknown role or ship pack.' });
      const name = String(body.name || 'Demo Watchstander').trim().slice(0, 40);
      const token = Math.random().toString(16).slice(2) + Date.now().toString(16);
      sessions[token] = { name, role: body.role, pack: body.pack };
      if (incident.pack !== body.pack) incident = {};
      audit(name, body.role, 'SIGN_IN', { pack: body.pack });
      return json(200, { token });
    }
    if (p === '/api/reset') {
      Object.keys(sessions).forEach(k => delete sessions[k]);
      incident = {}; auditRows = [];
      return json(200, { ok: true });
    }
    if (p === '/api/demo/tamper') {
      if (auditRows.length < 2) return json(400, { error: 'Not enough entries yet.' });
      auditRows[1].actor = 'Someone Else';
      return json(200, verifyAudit());
    }
    if (!user) return json(401, { error: 'Sign in first.' });
    if (p === '/api/report') return json(200, runAgents(user, String(body.text || '').slice(0, 500), body.drill));
    const send = ([status, result]) => json(status, result);
    if (p === '/api/done') return send(markDone(user, body.step));
    if (p === '/api/inject') return send(replan(user, body.inject));
    if (p === '/api/end') return send(endCasualty(user));
    return json(404, { error: 'Not found.' });
  }

  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = async (url, options = {}) => {
    const path = String(url);
    if (!path.startsWith('/api/')) return realFetch(url, options);
    return route(path, options.method || 'GET', options.headers || {}, options.body ? JSON.parse(options.body) : {});
  };
  window.DORE_STANDALONE = true;
  window.DORE_ENGINE = { reason, runAgents, replan, markDone, endCasualty, agentBrief, agentDebrief, buildPacket, agentRecords, verifyAudit, sha256, get incident() { return incident; } };
})();
