// @ts-check
// DSIP reference client — the screens. Everything normative (verification, the §12 engine, payload building,
// first-contact state, and the call glue: candidates, SDP, media gating, answering, the sealed-body fallback,
// recording consent) runs inside dsip_wasm; this file owns the views and the one current call, and is the host layer
// (relay socket, WebRTC, storage): it does the media work the call glue asks for. No signaling decision is made here:
// a screen changes only when the engine or the call glue emits.
//
// Spec: §12 (engine states shown as they are), §12.12 (ICE candidates in signed `info`, ACTIVE-only), §14.1 (no
// media before a signed answer), §14.4 (screening), §10.4 (sealed bodies; once in clear when refused), C§3–C§4 (the
// other side's recording declaration rendered; nothing answered or sent before acceptance), §8.4 (did:web documents
// fetched for signers not held), §18.1 (the verification basis, never a badge), §18.2 (display
// names are claims), §19.4 (first contact), B§ (SDP in `transports[].sdp`), G§5/G§7 (PSTN caller line, downgrade),
// N§4 (a caller's bound number, checked by `check_claim`), N§4.1 (`tel:` through a gateway as `destination`), N§5
// (a number that moved), N§6 (number lookup on the nodes in Settings), §8.1/§8.3 and DHT Hints Profile §10 (a
// signed reachability hint published on the nodes and looked up before a call: hint-sourced, never authoritative;
// a call to someone bound elsewhere goes through the relay their hint names), Messaging Profile M§4.2 (the mailbox a
// did:key identity names in its hint, and the peer's found the same way), M§4.3 (bound with a verified hello), M§7.2
// and M§8.1 (text in a direct conversation; every decision inside `Messenger`, spec-gap 44: its MLS and delivery state
// saved together after each step).

import init, { create_identity, revocation_frame, rehome, did_document, check_claim, identity_change, tn_select, hint_frame, hint_select, mailbox_select, voicemail_offer, redelegate, Endpoint, Messenger, verification_basis, tel_caller_line, downgrade_summary } from './pkg/dsip_wasm.js';
import { store } from './host/store.js';
import { Engine } from './host/engine.js';
import { Relay } from './host/relay.js';
import { Media } from './host/media.js';
import { exportIdentity, importIdentity } from './host/identity-file.js';

/** @typedef {import('./pkg/dsip_wasm.js').RelayHello} RelayHello */
/** @typedef {import('./pkg/dsip_wasm.js').LocalCommand} LocalCommand */

// What the Messenger keeps as it received or saved it crosses as `unknown` (dsip-rs B3b): the shapes below are what
// this page reads of it, declared here beside their readers.
/** A call record (C§9).
 *  @typedef {{ session: string, direction: string, peer: string, outcome: string, ended_by: string, reason?: string,
 *              invited_at: number, answered_at?: number, ended_at: number, evidence?: string[] }} CallRecord */
/** A call record a record-keeper received (C§9).
 *  @typedef {{ group: string, from: string, device: string, received_at: number, record: CallRecord }} HeldRecord */
/** An introduction not yet answered (M§14.1).
 *  @typedef {{ from: string, purpose?: string }} IntroductionRequest */
/** A thread message (M§8.5), or this identity's call event for the peer (M§13.3, `call`); `object` is the content
 *  object as it came off the wire.
 *  @typedef {{ key: string, group: string, sender: string, sender_device: string, object: any, seq: number | null,
 *              mine: boolean, delivered?: object, played?: object, from_archive?: boolean,
 *              call?: { outcome: string, at: number, session: string } }} TimelineEntry */
/** A roster change (M§7.3).
 *  @typedef {{ group: string, seq: number | null, epoch: number, by: string, added: string[], removed: string[],
 *              left: string[] }} RosterEntry */

/** An element of the page by id. `any`: the check is for the values crossing the wasm boundary, not the DOM's
 *  element kinds (dsip-rs B4).
 *  @param {string} id @returns {any} */
const $ = (id) => document.getElementById(id);
const now = () => Date.now() / 1000;
// `?as=` namespaces storage so two tabs on one origin can be two people (a convenience for trying it alone).
const slot = new URLSearchParams(location.search).get('as') || '';
const key = (k) => (slot ? `${slot}.${k}` : k);
const short = (d) => (d && d.length > 32 ? d.slice(0, 20) + '…' + d.slice(-8) : d || '');

let identity = null, settings = {}, contacts = [];
/** @type {Engine | null} */
let engine = null;
/** @type {Relay | null} */
let relay = null;
// {sid, role, peer, media, offer, pendingUpdate, screening, video, placing}: the call on screen. The call glue in the
// wasm decides; this keeps what the screens show and the media leg (`placing`: our invite waits on its SDP offer)
let call = null;
const invites = new Map();   // session → the verified invite (`received`), until the call glue rings it
/** @type {Extract<RelayHello, {ok: true}> | null} */
let relayInfo = null;
let purposes = {};    // introduction id → {purpose, basis}: what a request shows (the engine keeps only the ids)
let grantAudiences = {};   // grant id we issued → its presence audience (P§6): the engine keeps scope and valid_until only
let links = [];       // contact links issued here: {token, url, created}
let onBound = null;   // one action deferred until the relay is bound (a contact link opened before connecting)
let devices = [];     // {device, enrolled?}: this identity's devices as this browser knows them (no registry for did:key)
let revoked = [];     // {device, reason, at, frame}: revocations this identity issued here (§7.4)
let documents = {};   // did → DID document held here (§8.1; the CLI's --did-document): did:web signers verify against them
let served = {};      // the operator's defaults, `config.json` beside this page (spec-gap 114); a setting left empty takes them
const callRelays = new Map();   // session → a Relay opened to the peer's own relay for that call (their hint named it, §8.1)
let ice = null;       // {servers, until}: ICE servers in effect, from Settings, the operator, or the relay's /turn (short-lived)
let hintTimer = null; // re-signs the published reachability hint at ⅔ of its life
let hintBusy = false, hintAgain = false; // a publish is in flight; another was asked for meanwhile
let hintSeq = 0;      // the last `seq` this browser published (§8.3: newer wins; a re-sign within the same second must still be newer)
/** @type {Messenger | null} */
let messenger = null; // the wasm messaging device (stage 6), when a mailbox is configured
/** @type {Relay | null} */
let mailboxConn = null;                       // the Relay to this identity's mailbox
/** @type {Extract<RelayHello, {ok: true}> | null} */
let mailboxInfo = null;                       // its verified hello
let activeConv = null;                        // the group id open on the Messages screen
const waiters = [];                           // {pred, resolve}: one-shot waits for a Messenger emission on the mailbox connection
let messagingTick = null;                     // advances the receipts machines (M§10.3: a held read goes out when 5 s pass)
const lastRead = {};                          // group → the content id this screen last reported read (M§10.3)
let reconciling = null;                       // the device reconciliation in progress (M§12.3), one at a time
const media = {};                             // content id → {url, state: 'fetching'|'ready'|'failed', attempt, why}: blobs fetched and opened (M§8.4)
let recorder = null;                          // {rec, chunks, started, stream} while a voice message is being recorded
const VOICEMAIL_MAX_S = 180;                  // what this client's owner accepts as voicemail (M§4.2 `voicemail.max_duration_s`)
const EXTERNAL_JOIN_WAIT_S = 30;              // Impl: how long a device that knows of siblings waits to be added (M§12.3) before joining by external commit; M§6.8 leaves it to the device (v0.13, spec-gap 120)
let externalJoinTimer = null;
let pendingVoicemail = null;                  // {peer, session, max_s}: a voicemail offered after an unanswered call (M§13.2)
let lastVoice = null;                         // what the last recording became: {plain_size, sha256, size, content_type, duration_ms} (for tests)
const HINT_TTL_S = 3600;   // the profile's maximum (§12.9, spec-gap 96)
// A setting of null says "none", overriding the operator's default (typed as `none` in Settings).
const setting = (k) => (settings[k] === null ? undefined : settings[k] !== undefined && settings[k] !== '' && !(Array.isArray(settings[k]) && !settings[k].length) ? settings[k] : served[k]);
const noneable = (text, list) => (/^none$/i.test(text.trim()) ? null : list ? text.split(/[\s,]+/).filter(Boolean) : text.trim() || undefined);
const nodesInEffect = () => setting('nodes') || [];
const publishHint = () => (setting('publish_hint') ?? true) && nodesInEffect().length > 0;
const payloadOf = (frame) => { try { return JSON.parse(atob(JSON.parse(frame).payload.replace(/-/g, '+').replace(/_/g, '/'))); } catch { return {}; } };

// ---------------------------------------------------------------- log

function log(line, sec = '') {
  const el = $('log');
  el.textContent += `${new Date().toLocaleTimeString()}  ${line}${sec ? '   ' + sec : ''}\n`;
  el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------- views

function show(view) {
  for (const v of document.querySelectorAll('.view:not(.overlay)')) v.classList.toggle('hidden', v.id !== `view-${view}`);
}

function nameOf(did) { return contacts.find((c) => c.did === did)?.name || ''; }

function renderHeader() {
  $('me-name').textContent = identity.display_name || '(no name)';
  $('me-did').textContent = identity.identity;
}

// The lists are rebuilt only when what they show changed: they are asked to render on many events, and a button
// replaced under a click would swallow it.
let shownContacts = null, shownRequests = null;
function renderContacts() {
  const file = JSON.parse(engine.contactsFile());     // grants by id → {identity, scope, valid_until}
  const rows = contacts.map((c) => {
    const held = Object.values(file.grants_held || {}).some((g) => g.identity === c.did);
    const t = now();
    const mine = Object.entries(file.grants_issued || {}).filter(([, g]) => g.identity === c.did && g.valid_until > t);
    const issued = mine.length > 0;
    // P§6, P§7: what we share with them, and until when when it is a time-boxed share
    const shares = mine.map(([id, g]) => {
      // a grant re-issued on rotation (P§12.5) is known by its wire audience: the label is ours (P§12.1)
      const audience = grantAudiences[id] || (g.presence_audience ? engine.ep.presence_audience_label(g.presence_audience) : null);
      const until = g.valid_until - t < 31536000 - 86400   // a time-boxed share, not "until removed"
        ? new Date(g.valid_until * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : null;
      return audience || until ? `${audience || 'presence'}${until ? ` until ${until}` : ''}` : null;
    }).filter(Boolean);
    const pending = Object.values(file.pending_sent || {}).includes(c.did);
    const asked = Object.values(file.requests || {}).some(([who]) => who === c.did);
    const status = (held && issued ? 'mutual grant' : held ? 'they granted you' : issued ? 'you granted them'
      : asked ? 'wants to connect: see Requests' : pending ? 'introduction sent, waiting' : 'no grant')
      + (issued && shares.length ? ` (${shares.join('; ')})` : '');
    return { c, status, issued, presence: presenceShown.get(c.did) };
  });
  // presence is left out: a badge changes in place (presenceRefresh), so a notify never rebuilds the rows under a click
  const key = JSON.stringify(rows.map(({ c, status, issued }) => [c.name, c.did, c.numbers, status, issued]));
  if (key !== shownContacts) { shownContacts = key; renderContactRows(rows); }
  renderRequests();
}

function renderContactRows(rows) {
  const ul = $('contact-list');
  // an open grant editor survives a rebuild (another row's status changed, a share ended): the same box, its picks kept
  const editing = new Map([...ul.querySelectorAll('li[data-did] > .grant-edit')].map((box) => [box.parentElement.dataset.did, box]));
  ul.innerHTML = '';
  if (!rows.length) ul.innerHTML = '<li class="muted small">no contacts yet: paste a DID above</li>';
  for (const { c, status, issued, presence } of rows) {
    const li = document.createElement('li');
    li.dataset.did = c.did;
    // the badge sits under the name in a cell of fixed width: a presence change never moves the buttons under a click
    li.innerHTML = `<span class="who"><span class="name"></span><span class="presence"></span></span><code class="did"></code><span class="muted small num"></span><span class="status">${status}</span>`;
    li.querySelector('.name').textContent = c.name || '(unnamed)';
    renderPresence(li.querySelector('.presence'), presence);
    li.querySelector('.did').textContent = c.did;
    li.querySelector('.num').textContent = (c.numbers || []).join(' ');
    const b = (text, cls, fn) => { const x = document.createElement('button'); x.textContent = text; if (cls) x.className = cls; x.onclick = fn; return x; };
    li.append(b('Call', 'primary', () => placeCall(c.did, false)), b('Video', '', () => placeCall(c.did, true)),
      b('Message', '', () => messagePeer(c.did)), b('Introduce', '', () => introduce(c.did)));
    // §19.4 (spec-gap 150): a grant that follows ours changes it; P§7: revoking withdraws all of it, the contact stays
    if (issued) li.append(b('Change grant', 'ghost', () => editGrant(li, c.did)), b('Revoke grant', 'ghost', () => revokeGrants(c.did)));
    li.append(b('Remove', 'ghost', () => removeContact(c.did)));
    if (issued && editing.has(c.did)) li.append(editing.get(c.did));
    ul.append(li);
  }
}

/** The audience and length pickers of a grant (P§6, P§7). */
function grantPickers(audience = '') {
  const aud = document.createElement('select'); aud.className = 'grant-audience';
  aud.title = 'the presence they see: your main record, plus an audience\'s if you pick one (P§6)';
  aud.append(new Option('presence: everyone\'s', ''));
  for (const a of Object.keys(settings.presence_audiences || {})) aud.append(new Option(`presence: ${a}`, a));
  aud.value = audience;
  const len = document.createElement('select'); len.className = 'grant-length';
  len.title = 'a share ends at the grant\'s valid_until, calls and messages with it (P§7); Remove ends it sooner';
  for (const [label, secs] of SHARE_LENGTHS) len.append(new Option(label, String(secs)));
  return [aud, len];
}

/** The editor under a contact row for the grant we issued them: another audience or length, or calls without presence. */
function editGrant(li, did) {
  if (li.querySelector('.grant-edit')) return;
  const ours = liveGrantTo(did);
  const box = document.createElement('div'); box.className = 'grant-edit small';
  const [aud, len] = grantPickers(ours ? grantAudiences[ours] || '' : '');
  const share = document.createElement('label');
  share.innerHTML = '<input type="checkbox" class="grant-presence" checked> share presence';
  const apply = document.createElement('button'); apply.textContent = 'Apply'; apply.className = 'primary';
  apply.onclick = () => { box.remove(); changeGrant(did, { audience: aud.value, secs: Number(len.value), presence: share.querySelector('input').checked }); };
  box.append(aud, len, share, apply);
  li.append(box);
}

/** The live grant we issued `did` (the newest), if any. */
function liveGrantTo(did) {
  const t = now();
  return Object.entries(JSON.parse(engine.contactsFile()).grants_issued || {})
    .filter(([, g]) => g.identity === did && g.valid_until > t).map(([id]) => id).sort().pop() || null;
}

/** §19.4 (spec-gap 150): a grant that follows the one we issued `did`, so they need not introduce again. The engine
 *  revokes the old one at our relay first, with every grant of its rotation chain (P§7, P§12.5), which ends what they
 *  admitted there; they watch again presenting the new one. */
async function changeGrant(did, { audience, secs, presence }) {
  const old = liveGrantTo(did);
  if (!old) return notify('no live grant to change: they need to introduce themselves again');
  /** @type {LocalCommand} */
  const ev = { local: 'regrant', grant: old, id: engine.newId(), valid_until: Math.floor(now()) + secs,
               scope: ['dsip.invite', 'dsip.message', ...(presence ? ['dsip.subscribe'] : [])] };
  // P§12.1: a sealed audience goes on the wire as its tag
  if (presence && audience) { ev.presence_audience = engine.ep.presence_wire_audience(audience); noteGrantAudience(ev.id, audience); }
  log(`changing our grant to ${nameOf(did) || short(did)}: ${presence ? `presence${audience ? ` (${audience})` : ''}` : 'calls and messages only'}${secs < 31536000 ? `, ending in ${secs} s` : ''}`, '§19.4 · P§7');
  await engine.local(ev);
  persist(); renderContacts();
}

function noteGrantAudience(id, audience) { grantAudiences[id] = audience; store.set(key('grant-audiences'), grantAudiences); }

/** How long a grant lasts (P§7: a share ends at the grant's valid_until; calls and messages end with it). */
/** @type {[string, number][]} */
const SHARE_LENGTHS = [['until removed', 31536000], ['for 1 hour', 3600], ['for 1 day', 86400], ['for 1 week', 604800]];

function renderRequests() {
  const reqs = engine.requests();
  const audiences = Object.keys(settings.presence_audiences || {});
  const key = JSON.stringify([audiences, reqs.map(([id, who]) => [id, who, nameOf(who), purposes[id]?.purpose, purposes[id]?.basis])]);
  if (key === shownRequests) return;
  shownRequests = key;
  const rl = $('request-list');
  rl.innerHTML = reqs.length ? '' : '<li class="muted small">none</li>';
  for (const [id, who] of reqs) {
    const li = document.createElement('li');
    li.innerHTML = `<div class="request"><span class="name"></span> <code class="did"></code><div class="small purpose"></div><div class="small basis"></div></div>`;
    li.querySelector('.name').textContent = nameOf(who) || 'someone';
    li.querySelector('.did').textContent = who;
    li.querySelector('.purpose').textContent = purposes[id]?.purpose ? `“${purposes[id].purpose}”  (a claim, §18.2)` : '(no purpose given)';
    li.querySelector('.basis').textContent = purposes[id]?.basis || '';
    const [aud, len] = grantPickers();
    const g = document.createElement('button'); g.textContent = 'Grant'; g.className = 'primary';
    g.onclick = () => {
      /** @type {LocalCommand} */
      const ev = { local: 'grant', introduction: id, id: engine.newId(), scope: ['dsip.invite', 'dsip.message', 'dsip.subscribe'],
                   valid_until: Math.floor(now()) + Number(len.value) };   // §19.4; M§14.2: calls and messages; P§6: presence
      // P§6 (spec-gap 145); P§12.1: a sealed audience goes on the wire as its tag
      if (aud.value) { ev.presence_audience = engine.ep.presence_wire_audience(aud.value); noteGrantAudience(ev.id, aud.value); }
      const secs = Number(len.value);
      log(`granting ${nameOf(who) || short(who)}${aud.value ? ` the ${aud.value} audience` : ''}${secs < 31536000 ? `, a share ending in ${secs} s` : ''}`, 'P§6 · P§7');
      engine.local(ev);
    };
    const r = document.createElement('button'); r.textContent = 'Ignore';
    r.onclick = () => engine.local({ local: 'reject_introduction', introduction: id, reason: 'user.declined' });
    li.append(aud, len, g, r);
    rl.append(li);
  }
}

function renderCall() {
  if (!call) return;
  const st = engine.state(call.sid);
  $('call-state').textContent = st || '';
  $('call-title').textContent = { INVITING: 'Calling', PROCEEDING: 'Ringing', ACTIVE: 'In call', ENDED: 'Call ended' }[st] || (call.role === 'responder' ? 'Answering' : 'Calling');
  // §12.8: one outstanding update per session in either direction: while theirs waits, accepting it is the way to video
  $('btn-add-video').classList.toggle('hidden', !(st === 'ACTIVE' && !call.screening && !call.pendingUpdate && !call.media?.localStream?.getVideoTracks().length));
  $('btn-escalate').classList.toggle('hidden', !(st === 'ACTIVE' && call.screening));
  $('btn-answer-update').classList.toggle('hidden', !call.pendingUpdate);
  $('btn-reject-update').classList.toggle('hidden', !call.pendingUpdate);
  renderRecording();
}

/** C§3–C§4: the other side's recording declaration, as the call glue holds it: said on both call screens; while it
 *  waits on acceptance, accepting or declining it are the choices, and the call is not answered before it. */
function renderRecording() {
  const rec = call?.sid ? engine.recording(call.sid) : null;
  const d = /** @type {{ state?: string, recorder?: string, purpose?: string } | undefined} */ (rec?.disclosure);
  const on = d && d.state !== 'off';
  const text = on ? `⏺ RECORDED: the other side declares recording ${d.state} by ${nameOf(d.recorder) || short(d.recorder)}${d.purpose ? `, purpose ${d.purpose}` : ''}`
    + (rec.pending ? (call.role === 'responder' && !call.answered ? ': accept it to answer (C§4)' : ': nothing of yours is sent until you accept (C§4)') : ' (accepted)') : '';
  for (const id of ['in-recording', 'call-recording']) {
    $(id).classList.toggle('hidden', !on);
    $(`${id}-text`).textContent = text;
    $(`${id}-choices`).classList.toggle('hidden', !rec?.pending);
  }
  const blocked = !!rec?.pending;   // C§4: a callee never answers before accepting
  $('btn-accept').disabled = blocked; $('btn-screen').disabled = blocked;
}

/** P§12: whether this device seals, as the engine says (it cannot without the identity's key agreement secret). */
function renderSealing() {
  $('seal-presence-status').textContent = !settings.seal_presence || !sealing ? '' : sealing.sealed ? 'sealed: your relay carries presence it cannot read'
    : `not sealed: ${sealing.reason || 'reload to apply'}`;
}

function renderSettings() {
  $('set-name').value = identity.display_name || '';
  $('set-did').textContent = identity.identity;
  $('set-device').textContent = identity.device;
  $('set-first-contact').checked = !!settings.first_contact_required;
  $('set-seal').checked = !!settings.seal;
  $('set-seal-presence').checked = !!settings.seal_presence;
  renderSealing();
  $('set-recording-accept').value = settings.recording_accept || 'ask';
  $('presence-select').value = settings.presence || '';
  renderAudiences();
  $('set-read-disclosed').checked = !!settings.read_disclosed;
  $('set-record-keeper').value = settings.record_keeper || '';
  $('record-keeper-status').textContent = settings.record_keeper ? `records go to ${nameOf(settings.record_keeper) || short(settings.record_keeper)}${messenger?.held_records() ? `; ${messenger.held_records()} held until it opens the conversation` : ''}` : 'none: no call records are sent';
  $('btn-become-keeper').disabled = !identity.controller_seed_hex || !!messenger?.is_recorder();
  $('set-relay').value = settings.relay || '';
  $('set-relay').placeholder = served.relay || `wss://${location.host}/dsip`;
  $('set-ice').value = settings.ice ? JSON.stringify(settings.ice) : '';
  if (served.ice) $('set-ice').placeholder = JSON.stringify(served.ice);
  $('set-nodes').value = settings.nodes === null ? 'none' : (settings.nodes || []).join(', ');
  $('set-nodes').placeholder = (served.nodes || []).join(', ') || 'https://node.example:8090, …';
  $('set-publish-hint').checked = publishHint();
  $('set-mailbox').value = settings.mailbox === null ? 'none' : settings.mailbox?.uri || '';
  $('set-mailbox-did').value = settings.mailbox?.did || '';
  if (served.mailbox) { $('set-mailbox').placeholder = served.mailbox.uri || ''; $('set-mailbox-did').placeholder = served.mailbox.did || ''; }
  renderNetwork();
  const web = identity.identity.startsWith('did:web:');
  $('set-did-web').value = web ? identity.identity : '';
  $('did-web-host').classList.toggle('hidden', !web);
  if (web) $('did-web-url').textContent = didWebUrl(identity.identity);
  $('set-binding').value = settings.binding || '';
  $('binding-status').textContent = bindingStatus();
  $('set-gateway').value = settings.gateway === null ? 'none' : settings.gateway || '';
  if (served.gateway) $('set-gateway').placeholder = `${served.gateway} (operator default; type none to override)`;
  $('set-tn-policy').value = settings.tn_policy ? JSON.stringify(settings.tn_policy) : '';
  renderDevices();
  renderDocuments();
}

/** What the network settings resolve to, with where each came from. */
function renderNetwork() {
  const src = (k) => (settings[k] === null ? 'yours: none' : settings[k] !== undefined && settings[k] !== '' && !(Array.isArray(settings[k]) && !settings[k].length) ? 'yours' : served[k] !== undefined ? 'operator default' : 'built-in default');
  const iceLine = settings.ice ? `${JSON.stringify(settings.ice)} (yours)` : served.ice ? `${JSON.stringify(served.ice)} (operator default)`
    : ice?.servers?.length ? `${ice.servers.map((s) => [].concat(s.urls).join(' ')).join('; ')} (short-lived credentials from the relay's /turn, until ${new Date(ice.until * 1000).toLocaleTimeString()})` : 'none: host candidates only (the relay mints no TURN credentials)';
  $('network-effective').textContent = [
    `relay: ${relayUrl()} (${src('relay')})`,
    `ICE: ${iceLine}`,
    `nodes: ${nodesInEffect().join(', ') || 'none'} (${src('nodes')})`,
    `reachability hint: ${publishHint() ? `published on the nodes, ${HINT_TTL_S} s, re-signed at ⅔` : 'not published'}`,
    `gateway: ${setting('gateway') || 'none'} (${src('gateway')})`,
    `mailbox: ${mailboxOf() ? `${mailboxOf().uri} ${mailboxOf().did}` : 'none (messaging off)'} (${src('mailbox')})`,
  ].join('\n');
}

/** The mailbox this identity uses (M§4.2): Settings, else the operator's; `{uri, did}` or null. */
function mailboxOf() {
  const m = setting('mailbox');
  return m && m.uri && m.did ? m : null;
}

/** Where a did:web document is served (§8.4): `https://<host>/.well-known/did.json`, or `/<path>/did.json`. */
function didWebUrl(did) {
  const [host, ...path] = did.slice('did:web:'.length).split(':');
  return path.length ? `https://${host.replace('%3A', ':')}/${path.join('/')}/did.json` : `https://${host.replace('%3A', ':')}/.well-known/did.json`;
}

function bindingPayload(jws) { try { return JSON.parse(atob(jws.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch { return {}; } }
function bindingNumber() { return bindingPayload(settings.binding || '').tn || ''; }

/** Our own did:web document (§7.2): the identity key, and `tel:` for the bound number (N§3.3). `null` for did:key. */
function ownDocument() {
  if (!identity.identity.startsWith('did:web:')) return null;
  return JSON.parse(did_document(JSON.stringify(identity), bindingNumber() ? [`tel:${bindingNumber()}`] : []));
}

/** What a callee holding our document and this policy would make of our binding (N§3.4), said before any call. */
function bindingStatus() {
  if (!settings.binding) return 'no binding: your calls present no number';
  const claim = { type: 'tel', number: bindingNumber(), binding: settings.binding };
  const out = check_claim(claim, identity.identity, ownDocument(), now(), settings.tn_policy || {});
  if (out.outcome === 'attested') return `${out.line} — verifies, as a callee holding your document and this policy sees it (N§3.4)`;
  if (out.outcome === 'ignored') return 'the binding — would be refused: it is not a claim the check reads';
  const hint = out.reason === 'not-claimed-by-did'
    ? (identity.identity.startsWith('did:web:') ? ' (your document must list the number: host the one above)' : ' (a bound number needs a did:web identity whose document lists it, N§3.3)')
    : out.reason === 'untrusted-certificate' ? ' (no anchor in the number policy covers the issuer)' : '';
  return `${out.line || 'the binding'} — would be refused: ${out.reason}${hint}`;
}

function renderDocuments() {
  const ul = $('document-list');
  const ids = Object.keys(documents);
  ul.innerHTML = ids.length ? '' : '<li class="muted small">none</li>';
  for (const id of ids) { const li = document.createElement('li'); li.innerHTML = '<code class="did"></code>'; li.querySelector('.did').textContent = id; ul.append(li); }
}

/** Hold a did:web document (§8.1): it is the authority for its DID; this browser does not fetch, the person pastes. */
async function addDocument(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { return notify('a DID document is JSON'); }
  if (!doc || typeof doc.id !== 'string' || !doc.id.startsWith('did:web:')) return notify('a DID document names its did:web id');
  if (!engine.ep.add_document(doc)) return notify('that document could not be read');
  documents[doc.id] = doc;
  await store.set(key('documents'), documents);
  renderDocuments();
  log(`holding the DID document of ${doc.id}`, '§8.1');
}

/** Rehome to did:web (§7.2): the same keys under a hosted name; the delegation is re-signed under `<did>#key-1`. */
async function useDidWeb(did) {
  did = did.trim();
  if (!/^did:web:[a-z0-9.%:-]+$/i.test(did)) return alert('a did:web DID looks like did:web:alice.example (or did:web:host:path)');
  identity = JSON.parse(rehome(JSON.stringify(identity), did, now()));
  await store.set(key('identity'), identity);
  location.reload();
}

function downloadDidDocument() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(ownDocument(), null, 2)], { type: 'application/json' }));
  a.download = 'did.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function saveNumbers() {
  settings.gateway = noneable($('set-gateway').value);
  try { settings.tn_policy = $('set-tn-policy').value.trim() ? JSON.parse($('set-tn-policy').value) : undefined; } catch { return alert('the number policy must be JSON'); }
  await saveSettings();
  renderSettings();
}

async function saveBinding(jws) {
  jws = jws.trim();
  if (jws && !bindingPayload(jws).tn) return alert('that is not a binding (a compact JWS whose payload names tn)');
  settings.binding = jws || undefined;
  await saveSettings();
  renderSettings();
}

function renderDevices() {
  const ul = $('device-list');
  ul.innerHTML = '';
  for (const d of devices) {
    const li = document.createElement('li');
    const mine = d.device === identity.device;
    li.innerHTML = '<code class="did"></code><span class="status"></span>';
    li.querySelector('.did').textContent = d.device;
    li.querySelector('.status').textContent = mine ? 'this browser' : d.enrolled ? `enrolled ${new Date(d.enrolled * 1000).toLocaleString()}` : 'added by DID';
    if (!mine) { const b = document.createElement('button'); b.textContent = 'Revoke'; b.className = 'ghost'; b.onclick = () => revoke(d.device); li.append(b); }
    ul.append(li);
  }
  const rl = $('revoked-list');
  rl.innerHTML = '';
  for (const r of revoked) {
    const li = document.createElement('li');
    li.innerHTML = '<code class="did"></code><span class="status"></span>';
    li.querySelector('.did').textContent = r.device;
    li.querySelector('.status').textContent = `revoked (${r.reason}) ${new Date(r.at * 1000).toLocaleString()}`;
    rl.append(li);
  }
}

function renderRelay(text, state) {
  $('relay-status').textContent = text;
  $('relay-dot').className = `dot ${state}`;
}

// ---------------------------------------------------------------- persistence

let lastPersist = Promise.resolve();
/** The engine's contact file to storage; the write in flight is kept so a caller can wait for it. */
function persist() {
  lastPersist = store.set(key('engine.contacts'), engine.contactsFile());
  return lastPersist;
}

function renderLinks() {
  const ul = $('contact-links');
  ul.innerHTML = links.length ? '' : '<li class="muted small">none yet</li>';
  const file = JSON.parse(engine.contactsFile());
  for (const l of links) {
    const li = document.createElement('li');
    li.innerHTML = '<code class="did link"></code><span class="status"></span>';
    li.querySelector('.link').textContent = l.url;
    li.querySelector('.status').textContent = Object.prototype.hasOwnProperty.call(file.tokens || {}, l.token) ? 'unused' : 'used';
    ul.append(li);
  }
}

async function newContactLink() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const token = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await engine.local({ local: 'issue_token', token, grant_id: engine.newId() });   // §19.4: single-use, auto-granted
  const url = `${location.origin}${location.pathname}?contact=${encodeURIComponent(identity.identity)}&token=${token}&name=${encodeURIComponent(identity.display_name || '')}`;
  links.push({ token, url, created: Math.floor(now()) });
  await store.set(key('links'), links);
  renderLinks();
  navigator.clipboard?.writeText(url).catch(() => {});
  notify('contact link made (and copied): hand it to one person');
}

async function saveContacts() { await store.set(key('contacts'), contacts); renderContacts(); }

// ---------------------------------------------------------------- engine events

async function onReceived(r) {
  const m = r.message, p = r.payload;
  log(`← ${m.type.padEnd(12)} from ${short(r.identity)}${r.display_name ? ` "${r.display_name}"` : ''}  ✓ signature · delegation · replay · schema`, '§10.2');
  if (m.type === 'introduction') {
    // what the request will show: the stated purpose (a claim) and the introducer's §18.1 basis
    purposes[m.id] = { purpose: p.purpose || '', basis: verification_basis(r.identity, (p.identity && p.identity.claims) || []) };
    await store.set(key('purposes'), purposes);
    renderContacts();   // the request is listed now, with its purpose and basis
    return;
  }
  if (m.type === 'notify' && p.body?.event === 'presence') { presenceNotified(p); return; }
  if (m.type === 'error' && m.reason === 'transport.replaced') { relayReplaced(r.identity); return; }
  if (m.type === 'error') log(`   error ${m.reason || ''}${p.detail ? ': ' + (typeof p.detail === 'string' ? p.detail : JSON.stringify(p.detail)) : ''}`, '§15');
  if (m.type === 'error' && presenceSent.has(m.in_reply_to)) { presenceRefused(m.reason, p.retry_after, presenceSent.get(m.in_reply_to)); return; }
  if (m.type === 'reject' && (presenceSubFor(m.session) || m.session === ownWatch?.sub)) { presenceBlocked(m.session); return; }
  if (m.type === 'error' && m.reason === 'policy.rate-limited') {
    notify(`the relay limits introductions (§19.4): try again in ${p.retry_after ?? '?'} s`);
    return;
  }
  if (m.type === 'invite') {
    invites.set(m.id, r);   // the call glue rings it, declines it busy, or policy refused it
    if (invites.size > 16) invites.delete(invites.keys().next().value);   // the ones never rung
    return;
  }
  if (!call || ![m.id, m.session, m.in_reply_to].includes(call.sid)) return;   // not this call: the engine has already acted
  if (m.type === 'error' && m.reason === 'gateway.downgraded') {
    const text = '⚠ ' + downgrade_summary((p.detail && p.detail.losses) || []);
    for (const id of ['call-downgrade', 'in-downgrade']) { $(id).textContent = text; $(id).classList.remove('hidden'); }
    log(text, 'G§7');
  }
  if (m.type === 'update') { call.offer = p; if (p.answered_by === 'user') $('call-mode').textContent = ''; }   // §14.4 step 3: the screener answered for real
}

/** The incoming screen for a call the call glue rings (§12.4 OFFERED → ALERTING: policy admitted it, progress
 *  ringing went out; the person decides). */
function ringing(sid) {
  const r = invites.get(sid);
  invites.delete(sid);
  if (!r) return;
  const p = r.payload;
  call = { sid, role: 'responder', peer: r.identity, offer: p, media: null, pendingUpdate: null, screening: false, alerted: true };   // M§13.3: an alerted leg not answered here is a call event
  const claims = (p.identity && p.identity.claims) || [];
  const tel = claims.find((c) => c.type === 'tel');
  $('in-name').textContent = nameOf(r.identity) || r.display_name || '(no name)';
  $('in-did').textContent = r.identity;
  $('in-caller').textContent = tel ? '☎ ' + tel_caller_line(tel) + ' (via gateway)' : '';
  $('in-caller').classList.toggle('hidden', !tel);
  $('in-basis').textContent = verification_basis(r.identity, claims);
  // N§4: the caller's own bound numbers, verified against the identity that signed this invite and its document;
  // N§5: a number that a stored contact lists but that now belongs to another identity is said out loud
  const numberLines = [], warnings = [];
  for (const c of claims) {
    const out = check_claim(c, r.identity, documents[r.identity] ?? null, now(), setting('tn_policy') || {});
    if (out.outcome === 'attested') {
      numberLines.push(`☎ ${out.line} (N§4)`);
      const w = identity_change(contacts, c.number, r.identity, out.attested_by ?? undefined, out.issued);
      if (w) warnings.push(`⚠ ${w} (N§5)`);
    } else if (out.outcome === 'dropped') numberLines.push(`☎ ${out.line || 'a number'} — number binding refused: ${out.reason} (N§4, §18.2)`);
  }
  $('in-numbers').textContent = numberLines.join('\n');
  $('in-tn-warning').textContent = warnings.join('\n');
  $('in-tn-warning').classList.toggle('hidden', !warnings.length);
  for (const l of [...numberLines, ...warnings]) log(l, 'N§4');
  const file = JSON.parse(engine.contactsFile());
  const granted = Object.values(file.grants_issued || {}).some((g) => g.identity === r.identity) || (file.allow || []).includes(r.identity);
  const known = contacts.some((c) => c.did === r.identity);
  $('in-contact').textContent = granted ? 'you granted this identity contact (§19.4)' : known ? 'in your contacts, no grant' : '⚠ unknown identity: not in your contacts, no grant';
  $('in-contact').className = granted || known ? 'small' : 'small warn';
  $('in-policy').textContent = p.policy ? 'their policy: ' + Object.entries(p.policy).map(([k, v]) => `${k}=${v}`).join(', ') : '';
  $('in-downgrade').classList.add('hidden');
  $('view-incoming').classList.remove('hidden');
  renderRecording();
}

/** What the call glue says about a call (README of `dsip_endpoint::calls`: ringing, update offered, recording, the
 *  clear resend of a refused sealed call, …). */
async function onCall(e) {
  if (e.event === 'ringing') {
    if (call && call.sid !== e.session && engine.state(call.sid) !== 'ENDED') return;   // one call at a time: the glue declines the rest (user.busy)
    ringing(e.session);
    log(`☎ ringing: ${short(call?.peer)} is calling`, '§12.4');
    return;
  }
  if (!call || ![e.session, e.old].includes(call.sid)) return;
  if (e.event === 'update_offered') { call.pendingUpdate = e.id; renderCall(); }
  // §12.8 rule 7: not answered by its expires_at, their update can no longer be
  if (e.event === 'update_lapsed' && call.pendingUpdate === e.id) { call.pendingUpdate = null; renderCall(); }
  if (e.event === 'no_offer') log('the caller offered no SDP: answered without media', '§16.3');
  if (e.event === 'recording') {
    const x = e.emission, r = x.render;
    if (r) log(r.state === 'off' ? `⏺ recording ended (recorder ${short(r.recorder)})` : `⏺ RECORDED: the other side declares recording ${r.state} by ${short(r.recorder)}${r.purpose ? `  purpose ${r.purpose}` : ''}`, 'C§3');
    else if (x.accepted) log(`⏺ recording by ${short(x.accepted.recorder)} accepted (${x.accepted.by})`, 'C§4');
    else if (x.send) log(`⏺ declining to be recorded → ${x.send.type} policy.recording-declined`, 'C§4');
    else if (x.blocked) log('⏺ not answering before the recording is accepted', 'C§4');
    renderRecording();
  }
  if (e.event === 'recording_held') { log('⏺ holding our media until you accept the recording', 'C§4'); renderRecording(); }
  if (e.event === 'sending_resumed') { log('media: sending resumed', 'C§4'); renderRecording(); }
  if (e.event === 'resent_in_clear') {
    // §10.4, §11.3: the sealed invite was refused as an unknown critical extension; the call goes again in clear, once,
    // as a new session (its route and its record follow it)
    log(`seal: sealed body refused by ${short(e.by)} — placing the call again in clear`, '§10.4 · §11.3');
    const cr = callRelays.get(e.old);
    if (cr) { callRelays.delete(e.old); callRelays.set(e.new, cr); }
    call.sid = e.new; call.placing = true;
    $('call-note').textContent = 'their side cannot open sealed bodies: calling again in clear (§10.4)';
  }
}

/** Media work the call glue asks for (B§2–B§6, §12.12, §14.1, §14.4, C§4): SDP for offers and answers is handed
 *  back to it; local candidates go to it as they are gathered, and it sends them once the call is ACTIVE. */
async function onMediaRequest(m) {
  if (!call || call.sid !== m.session) return;
  try {
    switch (m.kind) {
      case 'offer': {
        if (!call.media) {
          call.media = await newMedia(m.session);
          await call.media.capture(!!call.video);
        } else if (m.add_source) {
          // §14.4 step 3: the screening leg was receive-only; our source joins and the re-offer says answered_by user
          await call.media.unscreen(!!call.offer?.media?.some((x) => x.type === 'video'));
          call.screening = false; $('call-mode').textContent = '';
        }
        $('local').srcObject = call.media.localStream;
        const sdp = await call.media.offer();
        const video = !!call.media.localStream?.getVideoTracks().length;
        engine.setVideo(video);                 // the offer's descriptors match the SDP that rides with it (B§2.1)
        if (video) engine.setVideoCodecsFromSdp(sdp);
        await engine.media({ kind: 'offer', session: m.session, sdp });
        if (call?.sid === m.session) call.placing = false;
        break;
      }
      case 'answer': {
        const wantVideo = /(^|\n)m=video /.test(m.offer);
        if (!call.media) {
          call.media = await newMedia(m.session);
          call.screening = m.screening;
          if (!m.screening) { await call.media.capture(wantVideo); $('local').srcObject = call.media.localStream; }
        } else if (wantVideo && !call.screening) { await call.media.addVideo(); $('local').srcObject = call.media.localStream; }
        const sdp = await call.media.answer(m.offer, m.screening || call.screening);
        await engine.media({ kind: 'answer', session: m.session, sdp });
        break;
      }
      case 'apply_answer': await call.media?.acceptAnswer(m.sdp); break;
      case 'remote_candidates': for (const c of m.candidates) await call.media?.addRemoteCandidate(c); break;
      case 'start_sending': await call.media?.resume(); break;   // §14.1: once the signed answer made the call active
      case 'hold_sending': await call.media?.hold(); break;      // C§4: a recording waits on acceptance
      case 'rollback': await call.media?.rollback(); break;   // B§5.2: our update was refused; the media is as it was
      case 'close': call.media?.close(); call.media = null; break;
      default: log(`media request ${m.kind}: not handled here`);
    }
  } catch (err) {
    notify(`${call?.role === 'responder' ? 'cannot answer' : 'cannot call'}: ${err.message || err}`);
    const sid = m.session, st = engine.state(sid);
    if (st === 'ALERTING' || st === 'OFFERED') await engine.call('decline', sid);
    else if (st === 'ACTIVE') await engine.call('hangup', sid);
    else await engine.call('cancel', sid);
    endCall();
  }
  renderCall();
}

/** §8.4: a did:web signer whose document is not held: fetched from where the DID says it is served, and held from
 *  then on (§8.1: the document is the authority for its DID). The frame that needed it waits meanwhile. */
async function resolveDid(did) {
  let text = '', err = '';
  const url = didWebUrl(did);
  try {
    const r = await fetch(url);
    if (r.ok) text = await r.text(); else err = `HTTP ${r.status}`;
  } catch (e) { err = e.message || String(e); }
  log(text ? `resolved ${did} from ${url}` : `could not resolve ${did} from ${url}: ${err}`, '§8.4');
  await engine.resolved(did, text, err);
}

async function onEmission(e) {
  if (e.timer) { log(`⏱ ${e.name} ${e.timer}${e.seconds ? ` (${e.seconds} s)` : ''}`, '§12.9'); if (e.timer === 'expired') $('call-note').textContent = `${e.name} expired`; return; }
  if (e.media) {
    log(`♫ media ${e.media}`, '§14.1');
    if (e.media === 'stop' && call && !call.placing && !live(call.sid)) endCall();
    return;
  }
  if (e.ui) {
    const fields = Object.entries(e).filter(([k]) => k !== 'ui').map(([k, v]) => `${k}=${v}`).join(' ');
    const sec = { progress: '§12.10', answered: '§14.3', offered: '§12.4', missed_call: '§12.11', ended: '§12.4', glare_retry: '§12.6', update_offered: '§12.8',
      update_rejected: '§12.8', update_lapsed: '§12.8', introduction_received: '§19.4', granted: '§19.4', introduction_rejected: '§19.4' }[e.ui] || '§12';
    log(`◆ ${e.ui} ${fields}`, sec);
    if (e.ui === 'progress') $('call-note').textContent = e.status === 'ringing' ? 'ringing at the other end' : e.status || '';
    if (e.ui === 'answered') $('call-mode').textContent = e.answered_by === 'screening' ? 'answered in screening mode: they hear you, you do not hear them (§14.4)' : '';
    if (e.ui === 'missed_call') notify(`Missed call from ${nameOf(call?.peer) || short(call?.peer)}`);
    if (e.ui === 'ended') {
      // a `ui ended` names no session: one for another session (a refused sealed invite placed again, a call declined
      // busy) leaves the call on screen alone
      if (call && (call.placing || live(call.sid))) return;
      const peer = call?.peer;
      if (call && legs.has(call.sid)) legs.get(call.sid).uiReason = e.reason;   // C§9: a leg that ended without a frame
      const refused = e.reason === 'policy.first-contact-required' && peer;
      // §12.7: a forked invite answered on another device ends this leg; §12.11: never a missed call
      const elsewhere = e.reason === 'session.answered-elsewhere';
      const noRoute = e.reason === 'identity.unknown' && call?.destination;
      $('call-note').textContent = refused ? 'They require an introduction before calls (§19.4). Introduce yourself; once they grant you, call again.'
        : elsewhere ? 'answered on another of your devices (§12.7); not a missed call'
        : noRoute ? `${call.destination}: the gateway found no identity for that number and no route (identity.unknown, N§6.1)`
        : e.reason ? `ended: ${e.reason}` : 'ended';
      const leg = endCall(refused);
      if (leg?.role === 'responder') callEnded(leg, e.reason === 'user.no-answer' ? 'local' : 'remote', e.reason);
      if (leg?.role === 'initiator' && !refused) offerVoicemail(leg, e.reason);
      if (refused) { $('btn-introduce-after').classList.remove('hidden'); $('btn-introduce-after').onclick = () => introduce(peer); }
    }
    if (e.ui === 'introduction_received' && e.token) { notify(`${short(e.from)} used your contact link: granted`); if (!contacts.some((c) => c.did === e.from)) await addContact('', e.from); }
    else if (e.ui === 'introduction_received') notify(`Introduction from ${nameOf(e.from) || short(e.from)}: see Requests`);
    if (e.ui === 'introduction_rejected') notify(`an introduction of yours was declined${e.reason ? ` (${e.reason})` : ''}`);
    if (e.ui === 'granted') {
      notify(`${nameOf(e.by) || short(e.by)} granted you contact`); closePeerRelay(e.by);
      // a grant that follows another (spec-gap 150) may change what we may watch: ask again at once with what we hold
      const s = presenceSubs.get(e.by);
      if (s) Object.assign(s, { renewAt: now(), retryAt: 0 });
    }
    return;
  }
  if (e.info) { log(`ℹ info for ${e.info.about}`, '§12.12'); return; }
  if (e.keys) {
    // P§12.5: a scope's epoch rose, by our rotation or a sibling's record; the grants carrying it follow with the new key
    const scope = e.scope === 'main' ? 'main' : engine.ep.presence_audience_label(e.scope);
    log(`· presence key ${scope} ${e.keys} to epoch ${e.epoch}`, 'P§12.5');
    presenceSend(engine.ep.presence_rekeyed(e.scope, now()));
    return;
  }
  if (e.drop) { log(`· dropped: ${e.drop}`); return; }
  if (e.refused) { log(`✗ refused: ${e.refused}`); notify(`Refused: ${e.refused}`); return; }
  if (e.queue) log(`queued ${e.queue.type} for ${short(e.queue.to)}`);
}

function notify(text) { $('call-note').textContent = text; log(text); }

/** Whether the engine holds `sid` as a session not yet ended. */
function live(sid) { const st = engine.state(sid); return !!st && st !== 'ENDED'; }

// ---------------------------------------------------------------- calls

/** The ICE servers for a call: Settings, else the operator's, else short-lived TURN credentials minted by the relay's
 *  origin (`/turn`, spec-gap 114), fetched again once half their life is gone; else none (host candidates only). */
async function iceServers() {
  if (settings.ice) return settings.ice;
  if (served.ice) return served.ice;
  if (ice && now() < ice.until - ice.ttl / 2) return ice.servers;
  try {
    const r = await fetch(`${httpOrigin(relayUrl())}/turn`);
    if (!r.ok) { ice = { servers: [], until: now() + 300, ttl: 600 }; log(`no TURN credentials at the relay's origin (${r.status}): host candidates only`, 'B§'); return []; }
    const t = await r.json();
    ice = { servers: t.iceServers || [], until: now() + (t.ttl || 600), ttl: t.ttl || 600 };
    log(`TURN credentials from the relay's origin: ${ice.servers.map((s) => [].concat(s.urls).join(' ')).join('; ')}, valid ${ice.ttl} s`, 'B§');
  } catch (e) { ice = { servers: [], until: now() + 60, ttl: 120 }; log(`the relay's origin did not answer /turn: ${e.message}`, 'B§'); }
  renderNetwork();
  return ice.servers;
}

/** `https://host:port` of a `wss://host:port/dsip` relay URL. */
function httpOrigin(wss) { return wss.replace(/^wss:/, 'https:').replace(/\/dsip\/?$/, ''); }

/** A media leg for `sid`: its local candidates go to the call glue, which sends them in signed info once the call is
 *  ACTIVE (§12.12). */
async function newMedia(sid) {
  return new Media(await iceServers(), {
    candidate: (entry) => { engine.media({ kind: 'candidate', session: sid, candidate: entry }); },
    track: (stream) => { if ($('remote').srcObject !== stream) $('remote').srcObject = stream; },
    state: async (s) => {
      log(`webrtc: ${s}`, 'B§');
      if (!call) return;
      if (s === 'connected') {
        const path = await call.media?.path();
        const via = path ? ` · path ${path.local}↔${path.remote}${path.relayed ? ' (through TURN)' : ' (direct)'}` : '';
        $('call-note').textContent = `media connected (DTLS-SRTP)${via}`;
        if (path) log(`media path ${path.local}↔${path.remote} ${path.protocol}${path.relayed ? ' relayed through TURN' : ' direct'}${path.rtt_ms != null ? `, rtt ${path.rtt_ms} ms` : ''}`, 'B§');
      } else if (s === 'failed') $('call-note').textContent = 'media failed: check ICE servers in Settings';
    },
  });
}

/** Place a call to a DID; with `destination` (`tel:+…`), `to` is a gateway and the number rides as the invite's
 *  destination (N§4.1). A saved binding is presented on every call as a `tel` claim (N§4). */
async function placeCall(to, video, destination) {
  if (call && engine.state(call.sid) !== 'ENDED') return notify('already in a call');
  pendingVoicemail = null; $('btn-voicemail').classList.add('hidden');
  log(`placing a ${video ? 'video ' : ''}call to ${nameOf(to) || short(to)}${destination ? ` (${destination})` : ''}`, '§12.4');
  call = { sid: null, role: 'initiator', peer: to, destination, video, media: null, pendingUpdate: null, screening: false, placing: true };
  const me = call;
  $('call-peer-name').textContent = nameOf(to) || '';
  $('call-peer-did').textContent = to;
  $('call-basis').textContent = verification_basis(to, []);
  const lines = [];
  if (destination) lines.push(`to ${destination} through the gateway ${short(to)}: the number is the invite's destination (N§4.1)`);
  if (settings.binding) lines.push(`presenting ${bindingNumber()} with its binding (N§4)`);
  $('call-number-line').textContent = lines.join(' · ');
  $('call-number-line').classList.toggle('hidden', !lines.length);
  $('call-route').classList.add('hidden');
  $('call-note').textContent = ''; $('call-mode').textContent = '';
  $('call-downgrade').classList.add('hidden');
  $('btn-introduce-after').classList.add('hidden');
  show('call');
  try {
    // §8.1: discovery before the invite. A did:key has no document; the hints tier may name the peer's relay, and a
    // call to someone bound elsewhere goes through that relay on a connection of its own (the hint is not authority:
    // it only says where to try).
    // The route is chosen before the session exists (keyed by `route` until the call glue names the session).
    const route = `route:${engine.newId()}`;
    const hint = await discover(to);
    if (call !== me) return;
    let r = null;
    if (hint && hint.uri && hint.uri !== relayUrl()) {
      $('call-route').textContent = `via their relay ${hint.uri} (a hint from the nodes, signed by ${short(hint.signer)}, expires in ${Math.max(0, Math.round(hint.expires_at - now()))} s; hint-sourced, not authoritative, §8.1)`;
      $('call-route').classList.remove('hidden');
      r = await openCallRelay(hint.uri, route);
      if (call !== me) { callRelays.delete(route); releasePeerRelay(r); return; }
      if (!r) { log(`their relay ${hint.uri} did not bind us; trying our own relay instead`, '§8.1'); $('call-route').textContent += ' — unreachable; through our own relay'; }
    } else if (hint) { $('call-route').textContent = `their hint names our relay (${hint.uri})`; $('call-route').classList.remove('hidden'); }
    // the call glue asks for the SDP offer (onMediaRequest); the invite carries it (B§: the transport binding object)
    const placed = engine.place(to, {
      claims: settings.binding ? [{ type: 'tel', number: bindingNumber(), binding: settings.binding }] : [],   // N§4
      ...(destination ? { patch: { destination } } : {}) });   // N§4.1
    call.sid = placed.session;
    if (r) { callRelays.delete(route); callRelays.set(placed.session, r); }
    await placed.go();
  } catch (err) { notify(`cannot call: ${err.message || err}`); endCall(); }
  renderCall();
}

/** Call a phone number: looked up on the number nodes (N§6 route 1, each binding verified against its own DID's
 *  document held here, the newest winning, N§7); a number nothing resolves is a PSTN number, dialled through the
 *  gateway in Settings as the invite's destination (N§4.1). */
async function callNumber(input) {
  const tn = input.trim().replace(/^tel:/, '').replace(/[\s().-]/g, '');
  if (!/^\+[1-9][0-9]{1,14}$/.test(tn)) return notify('a number is tel:+ and 2 to 15 digits (E.164)');
  const nodes = nodesInEffect();
  if (nodes.length) {
    const bindings = [];
    for (const n of nodes) {
      try {
        const r = await fetch(`${n.replace(/\/$/, '')}/dsip/v1/tn/${encodeURIComponent(tn)}`);
        if (r.ok) for (const b of (await r.json()).bindings || []) if (!bindings.includes(b)) bindings.push(b);
        log(`number ${tn}: ${r.ok ? `${bindings.length} binding(s)` : `${r.status}`} from ${n} (hints tier)`, 'N§6');
      } catch (e) { log(`number ${tn}: ${n} did not answer (${e.message})`, 'N§6'); }
    }
    const sel = tn_select(tn, bindings, documents, now(), setting('tn_policy') || {});
    if (sel) {
      log(`number ${tn} → ${sel.did}${sel.attested_by ? ` (attested by ${sel.attested_by})` : ''}${sel.others.length ? `; also claimed by ${sel.others.join(', ')}` : ''}`, 'N§6 · N§7');
      return placeCall(sel.did, false);
    }
    log(`number ${tn}: no binding verifies`, 'N§6');
  }
  const gateway = setting('gateway');
  if (!gateway) return notify(nodes.length ? `${tn} resolves to no identity, and no gateway is set in Settings` : 'calling a number needs nodes or a gateway in Settings');
  log(`number ${tn} → PSTN through gateway ${short(gateway)}, as the invite's destination`, 'N§4.1');
  return placeCall(gateway, false, `tel:${tn}`);
}

/** Look `did` up on the nodes (DHT Hints Profile §10): every frame they return goes through the same §8.3 selection
 *  a node applies (`hint_select`: verified against the subject or its delegation, unexpired, highest `seq`). What
 *  comes back is a hint. */
async function discover(did) {
  const nodes = nodesInEffect();
  if (!nodes.length) return null;
  const frames = [];
  const t0 = performance.now();
  for (const n of nodes) {
    try {
      const r = await fetch(`${n.replace(/\/$/, '')}/dsip/v1/hints/${encodeURIComponent(did)}`);
      const got = r.ok ? (await r.json()).hints || [] : [];
      for (const f of got) if (!frames.includes(f)) frames.push(f);
      log(`hints for ${short(did)}: ${r.ok ? `${got.length} record(s)` : r.status === 404 ? 'none (no overlay at that node)' : r.status} from ${n} in ${Math.round(performance.now() - t0)} ms (hints tier)`, '§8.5 · profile §10');
    } catch (e) { log(`hints for ${short(did)}: ${n} did not answer (${e.message})`, '§8.5'); }
  }
  const out = hint_select(did, frames, documents, now());
  for (const v of out.report) if (v.verdict !== 'accept') log(`   a hint record was refused: ${v.code}${v.reason ? ' ' + v.reason : ''}`, '§8.3');
  if (out.hint) log(`hint for ${short(did)}: ${out.hint.uri} seq ${out.hint.seq}, signed by ${out.hint.signer === did ? 'the subject' : 'delegated device ' + short(out.hint.signer)} — HINT-SOURCED, NOT AUTHORITATIVE (§8.1 rule 6)`, '§8.3');
  else if (frames.length) log(`hint for ${short(did)}: none of ${frames.length} verified`, '§8.3');
  return out.hint;
}

/** Route a call (or an introduction, keyed by the peer's DID) through another relay: the shared connection there
 *  (peerRelay), recorded against `sid` until the call ends. Resolves to null if it refuses or does not bind in 8 s. */
async function openCallRelay(uri, sid) {
  const shared = peerRelays.get(uri)?.bound;
  const r = await peerRelay(uri, 'this call');
  if (r) {
    callRelays.set(sid, r);
    if (shared) log(`their relay ${uri}: using the connection already open there`, '§13.2');
  }
  return r;
}

/** Our one connection to another relay, shared by the calls and introductions routed through it and by the presence
 *  watches of contacts bound there: a second binding of this device there would replace the first, which then stops
 *  (§13.2: the relay says `transport.replaced`, spec-gap 158). Our hello binds this device there; frames go through it, routed
 *  by `to` on that relay. Resolves to null if it refuses or does not bind within 8 s; releasePeerRelay closes it
 *  once nothing uses it. */
const peerRelays = new Map();   // relay URI → the connection
function peerRelay(uri, why) {
  let r = peerRelays.get(uri);
  if (r?.bound) return Promise.resolve(r);
  if (!r) {
    const conn = new Relay(uri, engine.ep, {
      bound: (info) => {
        conn.did = info.did;
        log(`← hello        their relay ${short(info.did)} bound us for ${why} (in_reply_to matched)`, '§13.2 · §20.5');
        for (const s of presenceSubs.values()) if (s.relay === conn) s.renewAt = now();   // reconnected: watch again
        conn.waiting.splice(0).forEach((w) => w(conn));
      },
      refused: (x) => { log(`✗ their relay's hello rejected: ${x.code}`, '§20.5'); dropPeerRelay(conn); },
      rejected: (code) => { log(`✗ their relay refused our hello: ${code}`, '§13.2'); dropPeerRelay(conn); },
      frame: (text) => engine.inbound(text),
      closed: (was) => { if (was && !conn.closedByUs) log(`their relay ${uri} dropped the connection; reconnecting`, '§13.2'); },
      dropped: (f) => log(`✗ their relay not connected: a ${JSON.parse(f).type || 'frame'} was not sent`),
    }, now);
    conn.waiting = [];
    peerRelays.set(uri, conn);
    conn.connect();
    r = conn;
  }
  return new Promise((resolve) => {
    const w = (x) => { clearTimeout(t); resolve(x); };
    const t = setTimeout(() => {
      r.waiting = r.waiting.filter((x) => x !== w);
      resolve(null);
      if (!r.bound) releasePeerRelay(r);
    }, 8000);
    r.waiting.push(w);
  });
}

/** §13.2 (spec-gap 158): a relay we are bound at said this device bound there again on another connection (another tab
 *  or window of this browser, most often), and is closing ours. We do not reconnect, or each would replace the other. */
function relayReplaced(relayDid) {
  if (relay && relayInfo?.did === relayDid) {
    relay.replaced();
    renderRelay('this device is connected to the relay elsewhere (another tab or window): reload to use it here', 'bad');
    log(`✗ relay ${short(relayDid)} replaced this connection: this device bound there on another one; not reconnecting`, '§13.2');
    notify('This device connected to your relay from another tab or window, which now has it. Reload this one to take it back.');
    return;
  }
  const peer = [...peerRelays.values()].find((c) => c.did === relayDid);
  if (peer) {
    log(`✗ their relay ${short(relayDid)} replaced our connection: this device bound there on another one; not reconnecting`, '§13.2');
    peer.replaced(); dropPeerRelay(peer);
  }
}

function dropPeerRelay(r) {
  r.close();
  if (peerRelays.get(r.url) === r) peerRelays.delete(r.url);
  r.waiting.splice(0).forEach((w) => w(null));
}

/** Publish our reachability hint on the nodes (DHT Hints Profile §10 `POST /dsip/v1/hints`): signed by this
 *  device under its delegation, naming our relay, `seq` = now, ttl the profile's maximum; re-signed at ⅔ of it.
 *  Impl: one publish at a time. The relay and the mailbox bind together, and two overlapping publishes each armed a
 *  re-sign timer, one of which nothing cleared; every later overlap leaked another, until a tab left open flooded the
 *  nodes. A request during a publish runs once more after it, so the last hint names the latest relay and mailbox. */
async function publishReachability() {
  if (hintBusy) { hintAgain = true; return; }
  hintBusy = true;
  try {
    do { hintAgain = false; await publishReachabilityOnce(); } while (hintAgain);
  } finally { hintBusy = false; }
}

async function publishReachabilityOnce() {
  clearTimeout(hintTimer); hintTimer = null;
  if (!publishHint() || !relay?.bound) return;
  // Impl: `seq` is the issue time, as the CLI's, but never at or below the last one this browser published: a relay
  // changed within the same second would otherwise tie with the held record and lose to it (§8.3, same seq, live).
  // The last seq is kept in storage, so a reload stays newer too. Two devices of one identity on different relays
  // are not reconciled here (each publishes its own, and the newest wins at a node).
  const seq = Math.max(Math.floor(now()), hintSeq + 1);
  hintSeq = seq; store.set(key('hint_seq'), seq);
  const uri = relayUrl();
  // M§4.2: a did:key identity advertises its mailbox in the hint, as a DSIPMailbox endpoint carrying the service
  // entry's fields; only once the mailbox has bound this device (it serves this identity, spec-gap 115)
  const endpoints = [{ uri }];
  const mb = mailboxOf();
  if (mb && mailboxInfo && mailboxInfo.did === mb.did) endpoints.push({ uri: mb.uri, service: 'DSIPMailbox', mailbox: mb.did, priority: 0, profiles: ['messaging/1.0'], accepts: ['text', 'audio'], voicemail: { max_duration_s: VOICEMAIL_MAX_S } });
  const frame = hint_frame(JSON.stringify(identity), engine.newId(), endpoints, HINT_TTL_S, seq, now());
  for (const n of nodesInEffect()) {
    try {
      const r = await fetch(`${n.replace(/\/$/, '')}/dsip/v1/hints`, { method: 'POST', body: frame, headers: { 'content-type': 'text/plain' } });
      const text = r.status === 202 ? `accepted (${(await r.json()).acknowledged ?? '?'} peer(s) acknowledged)` : r.status === 409 ? 'a held record wins (§8.3)' : `${r.status} ${(await r.text()).slice(0, 80)}`;
      log(`hint published → ${n}: ${uri}${endpoints.length > 1 ? ' + mailbox' : ''} seq ${seq} for ${HINT_TTL_S} s: ${text}`, '§8.3 · profile §10');
    } catch (e) { log(`hint not published: ${n} did not answer (${e.message})`, '§8.5'); }
  }
  clearTimeout(hintTimer); hintTimer = setTimeout(publishReachability, (HINT_TTL_S * 2 / 3) * 1000);
}

async function accept(screening) {
  if (!call || call.role !== 'responder') return;
  if (engine.recording(call.sid)?.pending) return notify('accept or decline being recorded first (C§4)');
  call.answered = true;
  $('view-incoming').classList.add('hidden');
  $('call-peer-name').textContent = nameOf(call.peer) || '';
  $('call-peer-did').textContent = call.peer;
  $('call-basis').textContent = $('in-basis').textContent;
  $('call-note').textContent = '';
  $('call-mode').textContent = screening ? 'screening: nothing of yours is sent (§14.4)' : '';
  $('btn-introduce-after').classList.add('hidden');
  show('call');
  // the call glue asks for the SDP answer to their offer (onMediaRequest), then answers
  await engine.call(screening ? 'screen' : 'accept', call.sid);
  renderCall();
}

async function decline() {
  if (!call) return;
  $('view-incoming').classList.add('hidden');
  const leg = call;
  await engine.call('decline', call.sid);
  endCall();
  callEnded(leg, 'local', 'user.declined');
}

async function hangup() {
  if (!call) return;
  const st = engine.state(call.sid);
  if (st === 'ACTIVE') await engine.call('hangup', call.sid);
  else if (call.placing) { if (call.sid) await engine.call('cancel', call.sid); endCall(); }   // no session yet: the glue drops it
  else if (st === 'ENDED' || !st) endCall();
  else if (call.role === 'responder') await engine.call('decline', call.sid);
  else {
    // §12.5: our cancel ends the session for us at once; a late answer that crosses it is answered by the engine
    // with a bye on its own, and neither is a `ui ended` (the person ended it), so the screen is cleared here.
    await engine.call('cancel', call.sid);
    endCall();
  }
}

/** Add video (a re-offer with the camera, §12.8), or answer for real from screening (§14.4 step 3: the glue asks
 *  for an offer with our source added, and the update says answered_by user). */
async function sendUpdate(escalate) {
  if (!call?.media) return;
  if (!escalate) { await call.media.addVideo(); $('local').srcObject = call.media.localStream; }
  await engine.call(escalate ? 'escalate' : 'update', call.sid);
  renderCall();
}

async function answerUpdate() {
  if (!call?.pendingUpdate || !call.media) return;
  call.pendingUpdate = null;
  await engine.call('answer_update', call.sid);
  renderCall();
}

async function rejectUpdate() {
  if (!call?.pendingUpdate) return;
  call.pendingUpdate = null;
  await engine.call('reject_update', call.sid);
  renderCall();
}

/** C§4: accept or decline the other side's recording. Accepting answers a call held for it, or sends our media
 *  again; declining rejects a ringing call or ends an answered one (policy.recording-declined). */
async function callRecording(accept) {
  if (!call?.sid) return;
  await engine.call(accept ? 'accept_recording' : 'decline_recording', call.sid);
  if (!accept && call && !live(call.sid)) { const leg = endCall(); if (leg?.role === 'responder') callEnded(leg, 'local', 'policy.recording-declined'); }
  renderCall();
}

/** M§6.8: no sibling added this device, so it joins by external commit every group its mailbox holds a GroupInfo for,
 *  the personal group first; each member (and the hub) checks the joiner's identity already had a leaf there. No
 *  archive key comes with it: history waits for a sibling to re-send one (M§12.3). */
async function joinAvailable() {
  if (!messenger || !mailboxInfo) return [];
  const groups = messenger.available();
  if (!groups.length) { log('external join: the mailbox holds no GroupInfo for a group this device is not in', 'M§6.8'); return []; }
  const joined = [];
  for (const g of groups) {
    try {
      const p = awaitEmission((e) => (e.ui === 'joined' && e.group === g.group) || (e.refused && e.refused.includes(g.group)), 30000);
      await driveMailbox(messenger.external_join(g.group, now()).map((f) => ({ send: f })));
      log(`external commit for the ${g.kind} group ${short(g.group)} sent to its hub ${short(g.hub?.did)}`, 'M§6.8');
      const r = await p;
      if (r.ui === 'joined') joined.push(g.group);
      else log(`external join of ${short(g.group)} refused: ${r.refused}`, 'M§6.8');
    } catch (e) { log(`external join of ${short(g.group)}: ${e.message || e}`, 'M§6.8'); }
  }
  renderMessages();
  return joined;
}

// ---------------------------------------------------------------- call records (Recording Profile C§9)

/** What this device saw of each session leg, by session id: every frame of the session sent or accepted, exactly as
 *  it went (for `evidence`), the invite's and the applied answer's `issued_at`, the answer's media and the relay. */
const legs = new Map();
const TERMINAL = ['bye', 'cancel', 'reject'];

function legFrame(text, dir) {
  const p = payloadOf(text);
  const sid = p.type === 'invite' ? p.id : p.session;
  if (!sid) return;
  let leg = legs.get(sid);
  if (!leg) {
    if (p.type !== 'invite') return;
    const via = callRelays.get(sid)?.did;
    leg = { session: sid, direction: dir === 'out' ? 'outbound' : 'inbound', peer: dir === 'out' ? p.to : p.from, invited_at: p.issued_at,
      relay: via || relayInfo?.did || null, frames: [], answered: false };
    legs.set(sid, leg);
  }
  leg.frames.push({ text, dir, type: p.type, reason: p.reason });
  if (p.type === 'answer' && leg.answered_at == null) {
    leg.answered_at = p.issued_at;
    leg.media = (p.media || []).map((m) => m.type).filter(Boolean);
  }
}

/** After each engine step: a leg whose session became active was answered here; one that ended is recorded. */
function legsChanged() {
  for (const leg of [...legs.values()]) {
    const st = engine.state(leg.session);
    if (st === 'ACTIVE') leg.answered = true;
    if (st === 'ENDED' || st === null) { legs.delete(leg.session); recordLeg(leg); }
  }
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

/** C§9: one `call-record` per leg to the record-keeper named in Settings. `ended_by` and `reason` come from the frame
 *  that ended the leg (the last bye, cancel or reject, else the last error), sent (`local`) or received (`remote`);
 *  a leg that ended without one ended here (a timer, glare). `evidence` is the SHA-256 of each frame's text. The
 *  Messenger derives the outcome and holds the record until the record-keeper's conversation exists. */
async function recordLeg(leg) {
  const keeper = settings.record_keeper;
  if (!keeper) return;
  if (!messenger) { log(`no call record for ${short(leg.session)}: messaging is not running (C§9)`, 'C§9'); return; }
  const end = [...leg.frames].reverse().find((f) => TERMINAL.includes(f.type)) || [...leg.frames].reverse().find((f) => f.type === 'error');
  const evidence = [];
  for (const f of leg.frames) evidence.push(hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(f.text))));
  const input = { session: leg.session, direction: leg.direction, peer: leg.peer, relay: leg.relay || undefined, invited_at: leg.invited_at,
    answered: leg.answered, answered_at: leg.answered_at, ended_by: end ? (end.dir === 'out' ? 'local' : 'remote') : 'local',
    reason: end ? end.reason : leg.uiReason, media: leg.answered ? leg.media : undefined, evidence };
  try {
    const out = messenger.call_record(keeper, input, now());
    if (out.frames.length) await driveMailbox(out.frames.map((f) => ({ send: f })));
    else await store.set(key('messenger'), JSON.parse(messenger.save()));
    const record = /** @type {CallRecord} */ (out.record);
    log(`call record for ${short(leg.session)}: ${record.outcome}, ended ${record.ended_by}${record.reason ? ` (${record.reason})` : ''}, ${evidence.length} frame hashes; ${out.frames.length ? 'sent to the record-keeper' : `held (${messenger.held_records()}): no conversation with the record-keeper yet`}`, 'C§9');
  } catch (e) { log(`✗ call record for ${short(leg.session)}: ${e.message || e}`, 'C§9'); }
}

/** Records held while no conversation with the record-keeper existed go out once it does (C§9, spec-gap 123). */
async function flushRecords() {
  if (!messenger || !settings.record_keeper || !messenger.held_records()) return;
  try {
    const frames = messenger.flush_records(settings.record_keeper, now());
    if (frames.length) { await driveMailbox(frames.map((f) => ({ send: f }))); log(`${frames.length} held call record${frames.length === 1 ? '' : 's'} sent to the record-keeper`, 'C§9'); }
  } catch (e) { log(`✗ held call records: ${e.message || e}`, 'C§9'); }
}

/** M§7.3 "Leaving": propose the removal of this identity's leaves; another member commits it. The conversation is
 *  no longer listed, and nothing more is sent there. */
async function leaveConversation(gid) {
  if (!messenger) return;
  try {
    const out = messenger.leave(gid, now());
    await driveMailbox(out);
    if (activeConv === gid) activeConv = null;
    log(`left ${short(gid)}: the removal of this identity's ${out.filter((e) => 'send' in e && e.send).length} leaf(s) proposed; another member commits it`, 'M§7.3');
    notify('You left the conversation');
  } catch (e) { notify(`cannot leave: ${e.message || e}`); }
  renderMessages();
}

/** C§5: the user accepts every recorder now in the conversation; the acceptance goes to the personal group so this
 *  identity's other devices accept them too. */
async function acceptRecording(gid) {
  if (!messenger) return;
  try {
    const out = messenger.accept_recording(gid, now());
    await driveMailbox(out.frames.map((f) => ({ send: f })));
    log(`recording accepted: ${out.accepted.map(short).join(', ')}${out.frames.length ? '; your other devices are told through the personal group' : ''}`, 'C§5');
  } catch (e) { notify(`${e.message || e}`); }
  renderMessages();
}

/** Make this identity a record-keeper: its device re-delegated with `dsip.record` (C§5, C§9). */
async function becomeRecordKeeper() {
  if (!identity.controller_seed_hex) return notify('only a device holding the identity key can re-delegate itself (§7.4)');
  identity = JSON.parse(redelegate(JSON.stringify(identity), now(), 'dsip.record'));
  await store.set(key('identity'), identity);
  // C§5: a recorder is never in its identity's personal group, so its messaging starts afresh: no group made before
  // it was a recorder (its personal group included) is carried over. Messaging stops first, so a mailbox answer still
  // being handled (the personal group's, on a first bind) cannot save the old state back before the reload
  clearTimeout(messagingStart); messagingStart = null;
  mailboxConn?.close(); mailboxConn = null; mailboxInfo = null; messenger = null;
  await store.del(key('messenger'));
  log('delegation re-issued with dsip.record: this device is a recorder and keeps call records (C§5, C§9); its messaging starts afresh; reloading', 'C§9');
  location.reload();
}

function renderRecords() {
  const keeper = !!messenger?.is_recorder();
  $('records-pane').classList.toggle('hidden', !keeper);
  if (!keeper) return;
  const recs = /** @type {HeldRecord[]} */ (messenger.records());
  const key = JSON.stringify(recs.map((r) => [r.device, r.record.session]));
  if ($('record-list').dataset.shown === key) return;
  $('record-list').dataset.shown = key;
  $('record-list').innerHTML = recs.length ? '' : '<li class="muted small">none yet</li>';
  for (const r of recs) {
    const c = r.record, li = document.createElement('li');
    li.className = 'record'; li.dataset.session = c.session; li.dataset.outcome = c.outcome;
    const secs = c.answered_at ? ` · ${c.ended_at - c.answered_at} s` : '';
    li.textContent = `${nameOf(r.from) || short(r.from)} ${c.direction === 'outbound' ? '→' : '←'} ${nameOf(c.peer) || short(c.peer)} · ${c.outcome}${secs} · ended ${c.ended_by}${c.reason ? ` (${c.reason})` : ''} · ${new Date(c.invited_at * 1000).toLocaleTimeString()} · ${(c.evidence || []).length} hashes · device ${short(r.device)}`;
    $('record-list').append(li);
  }
}

/** M§13.3: a callee leg ended; the pinned decision says whether this device records a call event in the personal
 *  group (alerted here, not answered here, never answered elsewhere). */
async function callEnded(leg, endedBy, reason) {
  if (!messenger || !leg) return;
  try {
    const frames = messenger.call_ended({ session: leg.sid, peer: leg.peer, alerted: !!leg.alerted, answered_here: !!leg.answered, ended_by: endedBy, reason: reason || '' }, now());
    if (frames.length) { await driveMailbox(frames.map((f) => ({ send: f }))); log(`call event for ${short(leg.sid)} to the personal group: ${reason === 'user.declined' && endedBy === 'local' ? 'declined' : 'missed'}`, 'M§13.3'); }
    else log(`no call event for ${short(leg.sid)} (${reason || 'ended'})`, 'M§13.3');
  } catch (e) { log(`call event not sent: ${e.message || e}`, 'M§13.3'); }
  renderMessages();
}

/** M§13.2: after an attempt of ours ended unanswered, offer to record a voicemail when the callee's mailbox entry
 *  carries `voicemail`, we can send to them, and the outcome is one the pinned rule lists. */
async function offerVoicemail(leg, reason) {
  $('btn-voicemail').classList.add('hidden');
  if (!messenger || !reason) return;
  const type = reason === 'session.timeout' ? 'cancel' : 'reject';   // §12.9: our own cancel on T-Establish/T-Ring expiry
  let mb = null;
  try { mb = await peerMailboxEntry(leg.peer); } catch { /* no entry: no offer */ }
  const d = voicemail_offer(mb?.entry ?? null, messenger.can_send(leg.peer), type, reason);
  log(`voicemail ${d.offer ? `offered (up to ${d.max_duration_s ?? '?'} s)` : 'not offered'}: ${type} ${reason}${mb?.entry?.voicemail ? '' : ', the callee advertises no voicemail'}`, 'M§13.2');
  if (!d.offer) return;
  pendingVoicemail = { peer: leg.peer, session: leg.sid, max_s: d.max_duration_s || VOICEMAIL_MAX_S };
  $('btn-voicemail').textContent = 'Leave a voicemail';
  $('btn-voicemail').classList.remove('hidden');
  if (!call) show('call');
}

/** Record the offered voicemail (M§13.1): caller-recorded audio with `purpose: voicemail` and the invite's `session`,
 *  sent end to end in the direct conversation — created first when only a grant is held (M§14.2). */
async function leaveVoicemail() {
  const vm = pendingVoicemail;
  if (!vm) return;
  if (recorder) { await toggleVoice(); return; }
  let conv = messenger.conversations(now()).find((c) => c.kind === 'direct' && c.peer === vm.peer);
  if (!conv) {
    await messagePeer(vm.peer);
    try { await until(() => messenger.conversations(now()).find((c) => c.kind === 'direct' && c.peer === vm.peer && c.members.length === 2), 30000); }
    catch { return notify('voicemail: no conversation with them could be opened'); }
    conv = messenger.conversations(now()).find((c) => c.kind === 'direct' && c.peer === vm.peer);
    show('call');
  }
  await toggleVoice({ gid: conv.group, purpose: 'voicemail', session: vm.session, max_s: vm.max_s });
  $('btn-voicemail').textContent = 'Stop and send voicemail';
  const done = setInterval(() => { if (!recorder) { clearInterval(done); pendingVoicemail = null; $('btn-voicemail').classList.add('hidden'); } }, 200);
}

/** Poll until `fn` returns something truthy. */
function until(fn, ms) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const t = setInterval(() => { const v = fn(); if (v) { clearInterval(t); resolve(v); } else if (Date.now() - t0 > ms) { clearInterval(t); reject(new Error('timeout')); } }, 200);
  });
}

function endCall(stay = false) {
  if (!call) return;
  call.media?.close();
  const cr = callRelays.get(call.sid);
  if (cr) { const sid = call.sid; setTimeout(() => { callRelays.delete(sid); log(releasePeerRelay(cr) ? `their relay ${cr.url}: connection for the call closed` : `their relay ${cr.url}: the call is done with the connection; kept, still in use`, '§13.2'); }, 1000); }
  $('local').srcObject = null; $('remote').srcObject = null;
  $('view-incoming').classList.add('hidden');
  const ended = call; call = null;
  renderContacts();
  if (!$('view-call').classList.contains('hidden')) {
    $('call-state').textContent = 'ENDED';
    $('call-title').textContent = 'Call ended';
    if (!stay) setTimeout(() => { if (!call && !pendingVoicemail && !$('view-call').classList.contains('hidden')) show('contacts'); }, 1500);
  }
  return ended;
}

function introduce(to) {
  show('contacts');
  $('introduce-name').textContent = nameOf(to) || '';
  $('introduce-did').textContent = to;
  $('introduce-form').dataset.to = to;
  $('introduce-purpose').value = '';
  $('introduce-form').classList.remove('hidden');
  $('introduce-purpose').focus();
}

async function sendIntroduction(to, purpose, token) {
  /** @type {LocalCommand} */
  const ev = { local: 'introduce', id: engine.newId(), to, purpose };
  if (token) ev.contact_token = token;
  // §8.1: as before a call, the hints tier may say they are bound to another relay; the introduction goes through
  // it on a connection kept open for the answer (their grant comes back on their relay, where we are now bound)
  if (!callRelays.has(to)) {
    const hint = await discover(to).catch(() => null);
    if (hint?.uri && hint.uri !== relayUrl()) {
      const r = await openCallRelay(hint.uri, to);
      if (r) { log(`introduction to ${short(to)} goes through their relay ${hint.uri} (hint-sourced, §8.1); kept open for their answer`, '§19.4'); setTimeout(() => closePeerRelay(to), 600000); }
      else log(`their relay ${hint.uri} did not bind us; introducing through our own relay`, '§8.1');
    }
  }
  await engine.local(ev);
  $('introduce-form').classList.add('hidden');
  notify('introduction sent; it never rings, and silence is a valid answer');
}

/** Close the connection kept to a peer's relay for an introduction, once answered or given up. */
function closePeerRelay(did) {
  const r = callRelays.get(did);
  if (!r) return;
  callRelays.delete(did);
  log(releasePeerRelay(r) ? `their relay ${r.url}: connection for the introduction closed` : `their relay ${r.url}: the introduction is done with the connection; kept, still in use`, '§13.2');
}

/** Close a connection to a peer's relay that a call or an introduction no longer needs, unless presence notifies
 *  still come over it (or another call uses it). Returns whether it was closed. */
function releasePeerRelay(r) {
  if (!r || r.waiting?.length || [...presenceSubs.values()].some((s) => s.relay === r) || [...callRelays.values()].includes(r)) return false;
  r.close();
  if (peerRelays.get(r.url) === r) peerRelays.delete(r.url);
  return true;
}

// ---------------------------------------------------------------- contacts

async function addContact(name, did, number = '') {
  did = did.trim();
  if (!/^did:(key|web):/.test(did)) return notify('a DID starts with did:key: or did:web:');
  if (did === identity.identity) return notify('that is you');
  number = number.trim();
  if (number && !/^\+[1-9][0-9]{1,14}$/.test(number)) return notify('a number is E.164: +15551234567');
  const existing = contacts.find((c) => c.did === did);
  if (existing) { existing.name = name || existing.name; if (number && !(existing.numbers || []).includes(number)) existing.numbers = [...(existing.numbers || []), number]; }
  else contacts.push({ name: name.trim(), did, numbers: number ? [number] : [] });
  await saveContacts();
}

/** Withdraws the grants we issued `did` (§19.4); the engine revokes each at our relay too, with its rotation chain, so
 *  it stops showing them our presence at once (P§7, P§12.5). A grant is withdrawn whole: their calls need a new
 *  introduction too. */
async function revokeGrants(did) {
  if (!relay?.bound) log(`our relay is not bound: the grants to ${short(did)} are withdrawn here only`, '§19.4');
  // §19.4: the granting endpoint stops honouring the grant whether or not a revocation was sent
  const issued = Object.entries(JSON.parse(engine.contactsFile()).grants_issued || {}).filter(([, g]) => g.identity === did);
  for (const [grant] of issued) await engine.local({ local: 'revoke', grant });
  persist(); renderContacts();
}

/** Removing a contact withdraws the grants we issued them first. */
async function removeContact(did) {
  await revokeGrants(did);
  contacts = contacts.filter((c) => c.did !== did);
  await saveContacts();
}

// ---------------------------------------------------------------- identity and settings

async function exportToFile() {
  const pass = prompt('Choose a passphrase for the identity file (at least 8 characters). Without it the file is useless; without the file the identity is unrecoverable.');
  if (pass === null) return;
  try {
    const text = await exportIdentity({ ...identity, devices, revoked }, pass);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    a.download = `${(identity.display_name || 'dsip').replace(/[^\w.-]+/g, '_')}.dsip-identity`;
    a.click();
    URL.revokeObjectURL(a.href);
    log('identity exported', '§7.3');
  } catch (err) { alert(err.message); }
}

async function importFromText(text) {
  const pass = prompt('Passphrase of the identity file:');
  if (pass === null) return;
  try {
    await enrol(await importIdentity(text, pass));
    location.reload();
  } catch (err) { alert(err.message); }
}

/** Enrol this browser as a device of the identity in a file: a fresh device key, its delegation signed by the
 *  identity key (§7.4), all locally. The file's own device key stays with the device that exported it; the file's
 *  device list and revocations come along. Impl: every import makes a new device (a restore too): a key that was in
 *  a file is not known to be only here. */
async function enrol(file) {
  let fresh = JSON.parse(create_identity(file.controller_seed_hex, null, file.display_name || '', now()));
  if (/^did:web:/.test(file.identity || '')) fresh = JSON.parse(rehome(JSON.stringify(fresh), file.identity, now()));   // §7.2: the file's did:web name, the same key
  const known = (file.devices || []).filter((d) => d.device !== fresh.device);
  if (file.device && !known.some((d) => d.device === file.device)) known.push({ device: file.device });
  known.push({ device: fresh.device, enrolled: Math.floor(now()) });
  await store.set(key('identity'), fresh);
  await store.set(key('devices'), known);
  await store.set(key('revoked'), file.revoked || []);
  await store.del(key('engine.contacts'));
  return fresh;
}

/** Revoke another device of this identity (§7.4, v0.8): the record is signed by the identity key, not this device's,
 *  and covers delegations issued at or before now, so the device can be enrolled again later with a fresh delegation.
 *  It goes to the relay (the only distribution a did:key identity has here) and is held by this engine. */
async function revoke(device) {
  const reason = (prompt('Why? lost, compromised, retired or policy (the §7.4 registry)', 'lost') || '').trim();
  if (!reason) return;
  if (!['lost', 'compromised', 'retired', 'policy'].includes(reason)) return alert('the reason must be lost, compromised, retired or policy');
  const at = Math.floor(now());
  const frame = revocation_frame(JSON.stringify(identity), engine.newId(), device, reason, now());
  engine.ep.hold_revocation(frame);
  relay.send(frame);
  log(`→ delegation-revocation of ${short(device)} (${reason}) to the relay; held here`, '§7.4');
  notify(`device ${short(device)} revoked: the relay ends its binding and refuses its next hello`);
  revoked.push({ device, reason, at, frame });
  devices = devices.filter((d) => d.device !== device);
  await store.set(key('devices'), devices);
  await store.set(key('revoked'), revoked);
  renderDevices();
}

async function setRecordKeeper(did) {
  settings.record_keeper = did || undefined;
  await saveSettings(); renderSettings();
  log(did ? `record-keeper: ${did}; a call record goes to it after every call (C§9)` : 'no record-keeper: no call records are sent', 'C§9');
  flushRecords();
}

async function saveSettings() { await store.set(key('settings'), settings); }

// ---------------------------------------------------------------- relay

function relayUrl() { return settings.relay || served.relay || `wss://${location.host}/dsip`; }

function connect() {
  relay?.close();
  renderRelay(`connecting to ${relayUrl()}…`, '');
  relay = new Relay(relayUrl(), engine.ep, {
    bound: (r) => {
      relayInfo = r;
      if (onBound) { const f = onBound; onBound = null; f(); }
      renderRelay(`relay ${short(r.did)}`, 'ok');
      $('relay-caps').textContent = `relay ${r.did}: ${JSON.stringify(r.capabilities)}`;
      log(`← hello        relay ${short(r.did)} bound (in_reply_to matched)`, '§13.2 · §20.5');
      ice = null; iceServers().catch(() => {});   // credentials are the relay's origin's: fetch them on each bind
      publishReachability();
      presenceBound(r.did);
    },
    refused: (r) => { renderRelay(`relay hello refused: ${r.code}`, 'bad'); log(`✗ relay hello rejected: ${r.code} (anti-splicing)`, '§20.5'); },
    rejected: (code) => {
      const revokedHere = code === 'delegation-revoked';
      renderRelay(revokedHere ? 'this device was revoked: its delegation no longer verifies (§7.4)' : `relay refused our hello: ${code}`, 'bad');
      log(`✗ relay refused our hello: ${code}${revokedHere ? '; this device is revoked, not reconnecting' : ''}`, '§13.2 · §7.4');
      if (revokedHere) notify('This device was revoked by your identity. If that was a mistake, enrol it again from the identity file (a new delegation).');
    },
    frame: (text) => engine.inbound(text),
    closed: () => {
      // P§7: a share ended while we are not bound is ended here only (§19.4); a replaced connection's close, coming
      // after the new one bound, leaves the authority the new one set
      if (!relay?.bound) engine.ep.presence_unbound();
      if (!relay.closedByUs && !relay.rejected) renderRelay('disconnected, reconnecting…', 'bad');
    },
    dropped: (f) => log(`✗ not connected: a ${JSON.parse(f).type || 'frame'} was not sent`),
  }, now);
  relay.connect();
}

// ---------------------------------------------------------------- presence (Presence Profile draft, P§3–P§5)

const presenceShown = new Map();   // contact DID → {state, token, source} (P§4), as the contact list shows it
const presenceSent = new Map();    // ids of our records → their audience (or null), to route the authority's refusal (P§3)
const presenceSubs = new Map();    // contact DID → {sub, relay, renewAt, retryAt}: our watch on it (§9.3)
const PRESENCE_SUB_S = 3600;       // §9.3: the presence event class's cap; renewed before it lapses
let presenceTimer = null;
let sealing = null;                // P§12: {sealed, audiences: {label: tag}, reason?} for this engine
let ownWatch = null;               // P§12.5: {sub, renewAt}: our watch on our own identity, when sealing

/** Send our signed presence record (or nothing) to our relay, the authority (P§3). */
function presenceSend(frame) {
  if (!frame || !relay?.bound) return;
  const p = payloadOf(frame);
  presenceSent.set(p.id, p.audience ?? null);
  if (presenceSent.size > 32) presenceSent.delete(presenceSent.keys().next().value);
  relay.send(frame);
  const audience = p.audience ? engine.ep.presence_audience_label(p.audience) : null;
  const what = p.kid ? `sealed under ${p.kid}` : p.state;   // P§12.2: the relay cannot read a sealed one
  log(`→ presence     ${what}${audience ? ` for audience ${audience}` : ''} seq ${p.seq} for ${p.expires_at - p.issued_at} s to our relay`, p.kid ? 'P§3 · P§12.2' : p.audience ? 'P§3 · P§6' : 'P§3');
}

/** Every record due now: one per audience at most (P§6, P§8). */
function presenceDrain() {
  for (let i = 0, f; i < 16 && (f = engine.ep.presence_tick(now())); i++) presenceSend(f);
}

/** Bound to our relay: our record goes to it, and every contact is watched (again). */
function presenceBound(authority) {
  presenceSend(engine.ep.presence_bound(authority, now()));
  for (const s of presenceSubs.values()) if (s.relay === relay) s.renewAt = 0;
  ownWatch = null;   // P§12.5: our own watch, at our relay, opened again
  clearInterval(presenceTimer);
  presenceTimer = setInterval(presenceTick, 1000);
  presenceTick();
}

/** The user picked a state (`null`: automatic, no record; the last one lapses at its expires_at). */
function presenceSet(state) {
  presenceSend(engine.ep.presence_set(state, now()));
  if (!state) log('presence automatic: no record sent; your relay says available while you are bound', '§9.3');
}

function presenceRefused(reason, retryAfter, audience) {
  log(`✗ our presence record${audience ? ` for audience ${audience}` : ''} was refused: ${reason}${retryAfter ? `, retry after ${retryAfter} s` : ''}`, 'P§9');
  engine.ep.presence_refused(reason, retryAfter ?? undefined, now(), audience ?? undefined);
}

/** The user set an audience's state (`null` removes the audience: its record lapses at its expires_at). P§6. */
async function audienceSet(name, state) {
  const all = { ...(settings.presence_audiences || {}) };
  if (state) all[name] = state; else delete all[name];
  settings.presence_audiences = all;
  await saveSettings();
  // P§12.6: sealing holds the audiences named when the engine started; a new one starts it again, sealed too
  if (state && sealing?.sealed && !(name in (sealing.audiences || {}))) { location.reload(); return; }
  presenceSend(engine.ep.presence_set_for(name, state || null, now()));
  if (!state) log(`presence audience ${name} removed: no more records for it; the last lapses at its expires_at`, 'P§6');
  renderAudiences();
  shownRequests = null; renderRequests();   // the Grant choices list the audiences
}

const PRESENCE_LABELS = { available: 'available', busy: 'busy', away: 'away', dnd: 'do not disturb', offline: 'invisible' };

function renderAudiences() {
  const ul = $('audience-list');
  const all = Object.entries(settings.presence_audiences || {});
  ul.innerHTML = all.length ? '' : '<li class="muted small">none: everyone you grant presence sees the same record</li>';
  for (const [name, state] of all) {
    const li = document.createElement('li');
    li.dataset.audience = name;
    li.innerHTML = '<span class="name"></span> <select></select> <button>Remove</button>';
    li.querySelector('.name').textContent = name;
    const sel = li.querySelector('select');
    for (const [v, label] of Object.entries(PRESENCE_LABELS)) sel.append(new Option(label, v, false, v === state));
    sel.onchange = () => audienceSet(name, sel.value);
    li.querySelector('button').onclick = () => audienceSet(name, null);
    ul.append(li);
  }
}

/** Once a second: our record's refresh, watches to open or renew, and records that expired since (P§4). */
function presenceTick() {
  presenceDrain();
  const t = now();
  if (sealing?.sealed && relay?.bound && relayInfo?.did && (!ownWatch || t >= ownWatch.renewAt)) presenceWatchOwn();
  for (const c of contacts) {
    const s = presenceSubs.get(c.did);
    // a contact's relay that dropped us forgot the subscription: watched again once it binds us again
    if (s?.relay && s.relay !== relay) { if (!s.relay.bound) s.down = true; else if (s.down) { s.down = false; s.renewAt = t; } }
    if (!s || (s.renewAt && t >= s.renewAt) || (s.retryAt && t >= s.retryAt)) presenceWatch(c.did);
  }
  for (const did of presenceSubs.keys()) if (!contacts.some((c) => c.did === did)) presenceSubs.delete(did);
  presenceRefresh(engine.ep.presence_all(now()));
}

/** Watch a contact's presence: subscribe at the relay that answers for it, ours or, when its hint names another,
 *  that one over the connection we keep there (§8.1: hint-sourced, not authoritative).
 *  Spec: §9.3 (spec-gap 143): we bind at their relay to subscribe there, and that binding makes this device
 *  reachable there too. Their records are verified here whatever relay carries them (§9.4, P§3). */
async function presenceWatch(did) {
  const pending = { renewAt: 0, retryAt: now() + 60 };   // until it is answered, not asked again for a minute
  presenceSubs.set(did, pending);
  let r = relay;
  const hint = await discover(did).catch(() => null);
  if (hint?.uri && hint.uri !== relayUrl()) r = (await peerRelay(hint.uri, 'presence')) || relay;
  if (!r?.bound) return;
  const authority = r === relay ? relayInfo?.did : r.did;
  if (!authority) return;
  const out = engine.ep.presence_subscribe(did, authority, PRESENCE_SUB_S, now());
  Object.assign(pending, { sub: out.subscription, relay: r, renewAt: now() + PRESENCE_SUB_S - 300, retryAt: 0 });
  r.send(out.frame);
  log(`→ subscribe    presence of ${short(did)} at ${r === relay ? 'our relay' : r.url} for ${PRESENCE_SUB_S} s${out.grants ? `, presenting ${out.grants} grant(s) of theirs` : ', no grant of theirs to present'}`, '§9.3 · P§6');
}

/** P§12.5: a sealing device watches its own identity at our relay (P§6 rule 1 admits it) to learn its siblings' epochs. */
function presenceWatchOwn() {
  const out = engine.ep.presence_subscribe(identity.identity, relayInfo.did, PRESENCE_SUB_S, now());
  ownWatch = { sub: out.subscription, renewAt: now() + PRESENCE_SUB_S - 300 };
  relay.send(out.frame);
  log(`→ subscribe    our own identity at our relay, sealed records too: a sibling's epoch is ours`, '§9.3 · P§12.5');
}

function presenceSubFor(sub) { return [...presenceSubs.entries()].find(([, s]) => s.sub === sub)?.[0]; }

/** The authority answered `reject policy.blocked`: uniform for a target it does not know or will not show (§9.3);
 *  tried again in a minute (the contact may bind there by then). */
function presenceBlocked(sub) {
  engine.ep.presence_rejected(sub);
  if (sub === ownWatch?.sub) { ownWatch.renewAt = now() + 60; log('our own presence watch was refused; trying again later', 'P§6 · P§12.5'); return; }
  const did = presenceSubFor(sub);
  const s = presenceSubs.get(did);
  if (s) Object.assign(s, { renewAt: 0, retryAt: now() + 60 });
  presenceForget(did);
  log(`presence of ${short(did)}: not available from that relay (§9.3: unknown and not allowed look the same; P§6: private unless they granted us); trying again later`, '§9.3 · P§6');
}

/** Nothing shown for a contact we may no longer watch (refused, or a share ended, P§7). */
function presenceForget(did) {
  if (!presenceShown.delete(did)) return;
  const li = [...$('contact-list').children].find((x) => x.dataset.did === did);
  if (li) renderPresence(li.querySelector('.presence'), null);
}

/** A presence notify: the wasm verifies each record and combines them (P§3, P§4). */
async function presenceNotified(p) {
  let out;
  try { out = engine.ep.presence_notify(p, now()); } catch (e) { return log(`✗ presence notify: ${e.message || e}`, 'P§12'); }
  if (!out) return;
  const v = out;
  if ('own' in v) {
    // P§12.5: our own watch; a sibling's higher epoch becomes ours, and the grants carrying it follow
    if (v.terminated) ownWatch = null;
    await engine.drive(v.events);
    return;
  }
  const unread = v.unreadable?.length ? `; ${v.unreadable.length} sealed record(s) not readable: no key for them (P§12.4)` : '';
  log(`◇ presence     ${short(v.target)}: ${v.state}${v.token !== v.state ? ` (${v.token})` : ''}, ${v.source === 'record' ? `from ${v.records - (v.unreadable?.length || 0)} signed record(s)` : v.source === 'assertion' ? "the relay's claim" : 'nothing bound'}${unread}`, v.unreadable?.length ? 'P§4 · P§12.4' : 'P§4');
  if (v.terminated) {
    const s = presenceSubs.get(v.target);
    if (s) Object.assign(s, { renewAt: now() });
    // P§7: the grant that admitted us ended or was revoked; nothing more is shown unless a renewal is admitted
    if (p.reason === 'policy.terminated') { log(`presence of ${short(v.target)}: they stopped sharing it with us`, 'P§7'); presenceForget(v.target); return; }
  }
  presenceRefresh([v]);
}

function presenceRefresh(list) {
  for (const v of list) {
    if (!v?.target) continue;
    const shown = { state: v.state, token: v.token, source: v.source, unreadable: v.unreadable?.length || 0 };
    if (JSON.stringify(presenceShown.get(v.target)) === JSON.stringify(shown)) continue;
    presenceShown.set(v.target, shown);
    const li = [...$('contact-list').children].find((x) => x.dataset.did === v.target);
    if (li) renderPresence(li.querySelector('.presence'), shown);
  }
}

/** P§4: the combined state; an unknown token is shown raw beside its fallback (P§5); the relay's own assertion is
 *  rendered as its claim (§9.3). */
function renderPresence(el, v) {
  if (!v) { el.textContent = ''; return; }
  const label = { available: 'available', busy: 'busy', away: 'away', dnd: 'do not disturb', offline: 'offline' }[v.state] || v.state;
  const text = v.source === 'assertion' ? `${label} (relay says)` : v.token !== v.state ? `${label} (${v.token})` : label;
  // P§12.4: a sealed record we hold no key for is neither shown nor guessed; we say that we hold one
  el.textContent = v.unreadable && v.source !== 'record' ? `${v.source === 'none' ? '' : `${text} · `}presence not readable` : text;
  el.className = `presence ${v.state}${v.source === 'assertion' ? ' claim' : ''}${v.unreadable ? ' unreadable' : ''}`;
  el.title = (v.source === 'record' ? 'from a record their device signed (P§4)' : v.source === 'assertion' ? 'their relay says they are bound; no device of theirs has said more (§9.3)' : 'no record and nothing bound')
    + (v.unreadable ? `; ${v.unreadable} sealed record(s) we hold no key for: a grant of theirs carrying keys opens them (P§12.3, P§12.4)` : '');
}

// ---------------------------------------------------------------- boot

async function startEngine() {
  // Impl: one call at a time in this client; a second invite is declined user.busy (§15) by the call glue
  // P§12: sealing presence is fixed for the engine's life: `main` and every audience named now (one added reloads)
  engine = new Engine(Endpoint, identity, { first_contact_required: !!settings.first_contact_required, one_call: true,
    seal: !!settings.seal, recording: settings.recording_accept || 'ask',
    seal_presence: !!settings.seal_presence, presence_audiences: Object.keys(settings.presence_audiences || {}) }, now);
  sealing = engine.ep.presence_sealing();
  renderSealing();
  engine.loadContactsFile(await store.get(key('engine.contacts')));
  engine.ep.presence_set(settings.presence || null, now());   // P§3: sent once our relay binds us
  for (const [a, st] of Object.entries(settings.presence_audiences || {})) engine.ep.presence_set_for(a, st, now());   // P§6
  for (const r of revoked) engine.ep.hold_revocation(r.frame);   // §7.4: revocations this identity issued apply here too
  for (const d of Object.values(documents)) engine.ep.add_document(d);   // §8.1: documents held
  engine.on = {
    send: (frame, meta) => {
      // a session placed through the peer's own relay stays there, an introduction through the relay their hint
      // named (keyed by their DID); everything else goes through ours
      const via = callRelays.get(meta.session) || callRelays.get(meta.to);
      (via || relay).send(frame);
      const p = payloadOf(frame);
      // P§7, P§12.5: the engine revokes a share's grants at our relay, the authority, before what changes it
      if (meta.type === 'grant-revocation') log(`→ grant-revocation of our grant …${p.grant.slice(-8)} to ${short(p.grantee)} to our relay`, 'P§7 · §19.4');
      else log(`→ ${meta.type.padEnd(12)} to ${short(meta.to)}${via ? ` via ${via.url}` : ''}${p.sealed ? ' · sealed (§10.4)' : ''}${p.presence_keys ? ' · with presence keys (P§12.3)' : ''}`, '§12.4');
      if (meta.type === 'reject' && payloadOf(frame).reason === 'policy.first-contact-required') log(`refused a call from ${short(meta.to)} without ringing: first contact required`, '§19.4');
    },
    frame: legFrame,
    received: onReceived,
    emission: onEmission,
    call: onCall,
    mediaRequest: onMediaRequest,
    resolve: (did) => { resolveDid(did); },   // not awaited: the held frame waits, nothing else does
    rejected: (code, detail) => log(`✗ inbound rejected: ${code} ${detail || ''}`, '§10.2'),
    changed: () => { persist(); renderContacts(); renderCall(); renderLinks(); messenger?.set_grants(heldGrantFrames()); legsChanged(); },
  };
  engine.startTimers();
  connect();
  startMessaging();
}

// ---------------------------------------------------------------- messaging (stage 6)

/** Grants held from others as `{identity: compact}` (§19.4: the grantee holds the signed grant; presented at M§14.2). */
function heldGrantFrames() {
  const file = JSON.parse(engine.contactsFile());
  /** @type {Record<string, string>} */
  const out = {};
  for (const [id, g] of Object.entries(file.grants_held || {})) if (file.grant_frames?.[id]) out[g.identity] = file.grant_frames[id];
  return out;
}

/** Start (or restart) the messaging device: a `Messenger` on this identity's mailbox (M§4.2), bound with our hello
 *  (M§4.3); its state is restored from storage and saved after every step (spec-gap 44). */
let messagingStart = null;   // a restart asked for twice in quick succession (relay and mailbox settings) starts once
function startMessaging() {
  clearTimeout(messagingStart);
  messagingStart = setTimeout(() => { messagingStart = null; startMessagingNow().catch((e) => log(`messaging: ${e.message || e}`, 'M§4')); }, 50);
}

async function startMessagingNow() {
  mailboxConn?.close(); mailboxConn = null; mailboxInfo = null; messenger = null;
  const mb = mailboxOf();
  renderMessages();
  if (!mb) return;
  // M§4.3: the delegation must carry dsip.messaging; an identity made before stage 6 is re-delegated here when its
  // identity key is on this device
  const saved = await store.get(key('messenger'));
  try {
    let m = new Messenger(JSON.stringify(identity), mb.did, mb.uri, saved ? JSON.stringify(saved) : undefined, now());
    if (!m.delegation_ok()) {
      if (!identity.controller_seed_hex) { log('messaging needs a delegation with dsip.messaging (M§4.3): enrol this device again from the identity file', 'M§4.3'); renderMessages(); return; }
      identity = JSON.parse(redelegate(JSON.stringify(identity), now()));
      await store.set(key('identity'), identity);
      log('delegation re-issued with dsip.messaging (M§4.3, §7.4): reloading', 'M§4.3');
      location.reload();
      return;
    }
    m.set_read_disclosed(!!settings.read_disclosed, now());
    if (settings.hub_timeout_s) m.set_hub_timeout(settings.hub_timeout_s);   // M§9.4: the device's own threshold
    if (settings.gap_timeout_s) m.set_gap_timeout(settings.gap_timeout_s);   // M§6.5: RECOMMENDED 300 s
    messenger = m;
  } catch (e) { log(`messaging not started: ${e.message || e}`, 'M§4'); renderMessages(); return; }
  messenger.set_grants(heldGrantFrames());
  clearInterval(messagingTick);
  messagingTick = setInterval(() => { if (messenger === m && mailboxInfo) driveMailbox(m.tick(now())).catch(() => {}); }, 5000);
  for (const d of Object.values(documents)) messenger.add_document(d);
  // Every callback belongs to this connection: a restart replaces `mailboxConn`, and the old socket's late close or
  // frame must not touch the state of the new one.
  const m = messenger;
  let conn = null;
  const mine = () => mailboxConn === conn && messenger === m;
  conn = new Relay(mb.uri, m, {
    bound: async (r) => {
      if (!mine()) return;
      if (r.did !== mb.did) {   // M§4.2: the mailbox's hello must be signed under the DID the entry names
        log(`✗ mailbox at ${mb.uri} is ${short(r.did)}, not ${short(mb.did)}: not used`, 'M§4.2');
        conn.close(); renderMessages(); return;
      }
      mailboxInfo = r;
      const caps = /** @type {{ mailbox?: { hub?: boolean, modes?: string[] } } | undefined} */ (r.capabilities);
      log(`← hello        mailbox ${short(r.did)} bound us (in_reply_to matched); ${caps?.mailbox?.hub ? 'a hub' : 'no hub'}, modes ${(caps?.mailbox?.modes || []).join('/')}`, 'M§4.3 · §20.5');
      await driveMailbox(messenger.on_bound(now()));                      // pending items again, then sync live (M§9.3, M§5.4)
      await driveMailbox([messenger.key_packages_frame(2, now())]);        // M§5.5: fresh KeyPackages on every bind
      if (messenger.is_recorder()) log('this device is a recorder: it never joins its identity\'s personal group (C§5)', 'C§5');
      else if (!messenger.personal()) {
        // M§7.1: the identity's first messaging device creates the personal group; a device that knows of siblings
        // (the identity file it was enrolled from listed them) waits to be added by one of them (M§12.3)
        const siblings = devices.filter((d) => d.device !== identity.device);
        if (!siblings.length) { try { await driveMailbox(messenger.create_personal(now())); log('creating the personal group at the mailbox', 'M§7.1'); } catch (e) { log(`personal group: ${e.message || e}`, 'M§7.1'); } }
        else {
          log(`waiting for another device of this identity (${siblings.map((d) => short(d.device)).join(', ')}) to add this one to the personal group (M§12.3); joining by external commit in ${EXTERNAL_JOIN_WAIT_S} s if none does (M§6.8)`, 'M§12.3');
          clearTimeout(externalJoinTimer);
          externalJoinTimer = setTimeout(() => { if (mine() && !messenger.personal()) joinAvailable(); }, EXTERNAL_JOIN_WAIT_S * 1000);
        }
      }
      publishReachability();                                               // the hint now names the mailbox too (M§4.2)
      flushRecords();                                                      // C§9: records held while the conversation did not exist
      renderMessages();
      reconcileDevices();                                                  // M§12.3: siblings this browser knows of join the groups
    },
    refused: (x) => { if (mine()) log(`✗ mailbox hello rejected: ${x.code}`, '§20.5'); },
    rejected: (code) => { if (mine()) { log(`✗ mailbox refused our hello: ${code}`, 'M§4.3'); renderMessages(); } },
    frame: async (text) => { if (mine()) await driveMailbox(m.inbound(text, now())); },
    closed: (was) => { if (was && mine()) { mailboxInfo = null; log(`mailbox ${mb.uri} dropped the connection; reconnecting`, '§13.2'); renderMessages(); } },
    dropped: (f) => { if (mine()) log(`✗ mailbox not connected: a ${payloadOf(f).type || 'frame'} was not sent`); },
  }, now);
  mailboxConn = conn;
  conn.connect();
  log(`messaging: mailbox ${mb.uri} (${short(mb.did)})`, 'M§4.2');
}

/** Act on what the Messenger returned (its emissions, or frames): send frames to the mailbox, log and render
 *  events, then save its state (MLS and delivery state together, spec-gap 44). */
async function driveMailbox(list) {
  const m = messenger;
  for (const e of list) {
    if (typeof e === 'string') { mailboxConn.send(e); log(`→ ${payloadOf(e).type?.padEnd(12)} to mailbox${payloadOf(e).class ? ` (${payloadOf(e).class})` : ''}`, 'M§5'); continue; }
    if (e.send === '') continue;   // M§9.4: queued behind an unreachable hub, or kept for a successor
    if (e.send) { mailboxConn.send(e.send); const p = payloadOf(e.send); log(`→ ${(p.type || '').padEnd(12)} to ${p.to === mailboxOf()?.did ? 'mailbox' : 'hub ' + short(p.to)}${p.class ? ` (${p.class})` : ''}`, 'M§5'); }
    else if (e.sync) { const f = messenger.sync_frame(false, now()); mailboxConn.send(f); log('→ sync         after a refused deposit (M§6.5 spec-gap 58; M§7.4 a group that moved)', 'M§6.5'); }
    else if (e.ui) onMessagingUi(e);
    else if (e.refused) { log(`✗ refused: ${e.refused}`, 'M§16'); notify(`Messaging: ${e.refused}`); }
    else if (e.error?.startsWith('mailbox.not-served')) {
      // M§4.1 (spec-gap 130): the mailbox enrols no more identities; nothing here will be kept until one has room
      log(`✗ the mailbox does not serve this identity: it has no room for another one (mailbox.not-served)`, 'M§4.1');
      notify('Messaging: this mailbox has no room for your identity. Choose another mailbox in Settings.');
    } else if (e.error) log(`✗ messaging error: ${e.error}`, 'M§5');
    else if (e.rejected) log(`✗ mailbox frame rejected: ${e.rejected.code}${e.rejected.reason ? ' ' + e.rejected.reason : ''}`, '§10.2');
    else if (e.drop) log(`· mailbox: ${e.drop}`);
    else if (e.successor_due) successorDue(e.successor_due);
    for (let i = waiters.length - 1; i >= 0; i--) if (waiters[i].pred(e)) waiters.splice(i, 1)[0].resolve(e);
  }
  // a messenger stopped meanwhile (messaging restarted, or the device became a recorder) is not saved over its successor
  if (m && m === messenger) await store.set(key('messenger'), JSON.parse(m.save()));
  renderMessages();
}

function onMessagingUi(e) {
  const sec = { joined: 'M§6.6', committed: 'M§6.5', personal: 'M§7.1', message: 'M§8.1', sent: 'M§9.2', receipt: 'M§10.2', receipt_sent: 'M§10.2', epoch: 'M§7.3', removed: 'M§7.3',
    key_packages_uploaded: 'M§5.5', archive_key: 'M§12.1', archive_key_created: 'M§12.1', granted: 'M§14.1', request: 'M§14.1', duplicate: 'M§8.5', self: 'spec-gap 47', hold: 'M§6.5', released: 'M§6.5', conflict: 'M§6.5',
    archive: 'M§12.2', archived: 'M§12.2', archive_held: 'M§12.3', history: 'M§12.3', history_receipt: 'M§12.2', history_applied: 'M§12.2', read_private_kept: 'M§10.5',
    call_record: 'C§9', recording: 'C§5', recorder_content: 'C§5', repropose: 'M§6.5', recording_accepted: 'C§5', receipt_withheld: 'C§5', left: 'M§7.3', leave_proposed: 'M§7.3', leave_committing: 'M§7.3', leave_proposals: 'M§7.3', leave_proposal_refused: 'M§7.3', hub_down: 'M§9.4', hub_retry: 'M§9.4', hub_back: 'M§9.4', handed_over: 'M§9.4', successor: 'M§7.5', successor_declined: 'M§7.5', successor_left: 'M§7.5', hub_moved: 'M§7.4', moved_check: 'M§7.4', hub_arriving: 'M§7.4', hub_arrival_expired: 'M§7.4',
    gap_timeout: 'M§6.5', unprocessable: 'spec-gap 138' }[e.ui] || 'M§';
  const fields = Object.entries(e).filter(([k]) => k !== 'ui' && k !== 'text' && k !== 'object').map(([k, v]) => `${k}=${typeof v === 'string' ? short(v) : JSON.stringify(v)}`).join(' ');
  log(`◇ ${e.ui} ${fields}`, sec);
  if (e.ui === 'message') { if (!activeConv) activeConv = e.group; notify(`Message from ${nameOf(e.from) || short(e.from)}`); }
  if (e.ui === 'joined' && e.kind === 'direct' && e.members.includes(settings.record_keeper)) setTimeout(flushRecords, 0);
  if (e.ui === 'leave_committing') notify(`${nameOf(e.identity) || short(e.identity)} left a conversation; this device commits their removal`);
  if (e.ui === 'left') notify('another of your devices left a conversation');
  if (e.ui === 'call_record') notify(`call record from ${nameOf(e.from) || short(e.from)}: ${e.outcome}`);
  if (e.ui === 'joined' && e.kind === 'direct') { activeConv = activeConv || e.group; notify(`${nameOf(e.members.find((m) => m !== identity.identity)) || 'someone'} opened a conversation with you`); }
  if (e.ui === 'committed' && e.device) notify(`device ${short(e.device)} added to ${e.personal ? 'the personal group' : 'a conversation'} (epoch ${e.epoch})`);
  else if (e.ui === 'committed' && e.added) notify(`conversation with ${nameOf(e.added) || short(e.added)} is up (epoch ${e.epoch})`);
  if (e.ui === 'epoch' && e.added?.length) notify(`${e.added.map((a) => { const [who, dev] = a.split('#'); return `${who === identity.identity ? 'your' : `${nameOf(who) || short(who)}'s`} device ${short(dev)}`; }).join(', ')} joined (epoch ${e.epoch})`);
  if (e.ui === 'roster' || e.ui === 'hub_moved') notify(rosterLine(e));
  if (e.ui === 'joined' && e.kind === 'group') { activeConv = activeConv || e.group; notify(`you were added to a group with ${e.members.filter((m) => m !== identity.identity).map((m) => nameOf(m) || short(m)).join(', ')}`); }
  if (e.ui === 'removed' && !e.left) notify(`${e.by ? nameOf(e.by) || short(e.by) : 'a member'} removed you from a conversation`);
  if (e.ui === 'hub_down') notify(`the hub of a conversation is unreachable: messages wait (M§9.4)`);
  if (e.ui === 'hub_back') notify('the hub answers again: pending messages sent');
  if (e.ui === 'successor') { if (activeConv === e.of) activeConv = e.group; notify(`the conversation continues in a successor group (its old hub is gone, M§7.5)`); }
  if (e.ui === 'history') notify(`history: ${e.from === identity.identity ? 'you' : nameOf(e.from) || short(e.from)} #${e.seq}`);
  if (e.ui === 'request') notify(`Message request from ${short(e.from)}: see Messages`);
  if (e.ui === 'granted') notify(`${nameOf(e.by) || short(e.by)} granted you dsip.message`);
}

/** Wait for one Messenger emission on the mailbox connection. */
function awaitEmission(pred, ms = 15000) {
  return new Promise((resolve, reject) => {
    const w = { pred, resolve };
    waiters.push(w);
    setTimeout(() => { const i = waiters.indexOf(w); if (i >= 0) { waiters.splice(i, 1); reject(new Error('no answer from the mailbox')); } }, ms);
  });
}

/** The peer's mailbox (M§4.2, §8.1): its DID document's entry when held here, else the DSIPMailbox endpoint of its
 *  reachability hint on the nodes (a hint: never authority). `{did, uri, source}` or null. */
async function peerMailbox(did) {
  const hint = did.startsWith('did:web:') && documents[did] ? null : await discover(did);
  const sel = mailbox_select(documents[did] ?? null, hint?.endpoints || []);
  if (!sel.selected) return null;
  log(`mailbox of ${short(did)}: ${sel.uri} ${short(sel.selected)} (${sel.source === 'hint' ? 'HINT-SOURCED, NOT AUTHORITATIVE, §8.1 rule 6' : 'from their DID document, §8.1'})`, 'M§4.2');
  return { did: sel.selected, uri: sel.uri, source: sel.source, entry: sel.entry };
}
const peerMailboxEntry = peerMailbox;

/** A short-lived connection to another mailbox for one `key-package-fetch` (M§5.5): bound with our hello, the
 *  answer returned, closed. */
function fetchFromMailbox(mb, target, successorOf) {
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (fn) => { if (!done) { done = true; r.close(); fn(); } };
    const r = new Relay(mb.uri, messenger, {
      bound: (info) => {
        if (info.did !== mb.did) return finish(() => reject(new Error(`their mailbox is ${short(info.did)}, not ${short(mb.did)}`)));
        log(`← hello        their mailbox ${short(info.did)} bound us (in_reply_to matched)`, 'M§4.3 · §20.5');
        r.send(messenger.fetch_frame(mb.did, target, now(), successorOf));
        log(`→ key-package-fetch for ${short(target)} to their mailbox${heldGrantFrames()[target] ? ', presenting their grant' : ', no grant held'}`, 'M§5.5 · M§14.2');
      },
      refused: (x) => finish(() => reject(new Error(`their mailbox's hello rejected: ${x.code}`))),
      rejected: (code) => finish(() => reject(new Error(`their mailbox refused our hello: ${code}`))),
      frame: (text) => {
        for (const e of messenger.inbound(text, now())) {
          if ('key_packages' in e) return finish(() => resolve(e.key_packages));
          if ('error' in e) return finish(() => reject(new Error(e.error)));
          if ('rejected' in e) return finish(() => reject(new Error(`frame rejected: ${e.rejected.code}`)));
        }
      },
      closed: () => { if (!done) finish(() => reject(new Error('their mailbox closed the connection'))); },
      dropped: () => {},
    }, now);
    r.connect();
    setTimeout(() => finish(() => reject(new Error('their mailbox did not answer in 15 s'))), 15000);
  });
}

/** Open (or create, M§7.2) the direct conversation with `did`: the peer's mailbox found, its KeyPackages fetched with
 *  the grant we hold, our own other devices' too, the group created at our mailbox and the add committed. */
async function messagePeer(did) {
  if (!messenger) return notify('messaging needs a mailbox in Settings → Network');
  show('messages');
  messenger.set_grants(heldGrantFrames());   // grants held since the messenger started (§19.4)
  const existing = messenger.conversations(now()).find((c) => c.kind === 'direct' && c.peer === did);
  if (existing) { activeConv = existing.group; renderMessages(); return; }
  if (!mailboxInfo) return notify('the mailbox is not bound yet');
  $('thread-title').textContent = `opening a conversation with ${nameOf(did) || short(did)}…`;
  try {
    const mb = await peerMailbox(did);
    if (!mb) throw new Error('no mailbox found for them: no document held, and no DSIPMailbox hint on the nodes');
    const theirs = await fetchFromMailbox(mb, did);
    log(`key packages of ${short(did)}: ${(theirs.key_packages || []).length} one-time${theirs.last_resort ? ' + last resort' : ''}`, 'M§5.5');
    // M§7.2: our own other devices join in the same commit; our mailbox is asked over the bound connection
    let own = null;
    try {
      const p = awaitEmission((e) => (e.key_packages && e.key_packages.subject === identity.identity) || e.error, 8000);
      mailboxConn.send(messenger.fetch_frame(mailboxOf().did, identity.identity, now()));
      const got = await p;
      if (got.error) throw new Error(got.error);
      own = got.key_packages;
    } catch (e) { log(`own devices: none added (${e.message})`, 'M§7.2'); }
    const frames = messenger.create_direct(did, theirs, own || undefined, now());
    await driveMailbox(frames);
    log(`conversation with ${short(did)} created at our mailbox (hub); the add goes out once the hub holds the group`, 'M§7.2 · M§6.5');
    activeConv = messenger.conversations(now()).find((c) => c.kind === 'direct' && c.peer === did)?.group || activeConv;
  } catch (e) { notify(`cannot message ${nameOf(did) || short(did)}: ${e.message || e}`); log(`✗ ${e.message || e}`, 'M§7.2'); }
  renderMessages();
}

/** Our own other devices' KeyPackages for a new group (M§7.2, M§7.3: they join in the same commit), or null. */
async function ownForNewGroup() {
  try { return await fetchOwnKeyPackages(); } catch (e) { log(`own devices: none added (${e.message})`, 'M§7.2'); return null; }
}

/** Create a group conversation (M§7.3) with `dids`: each one's mailbox found and its KeyPackages fetched with the grant
 *  we hold (M§14.2), our own other devices' too, the group created at our mailbox and every add in one commit. */
async function createGroup(dids) {
  if (!messenger || !mailboxInfo) return notify('messaging is not connected');
  messenger.set_grants(heldGrantFrames());
  try {
    /** @type {Record<string, any>} */
    const targets = {};
    for (const did of dids) {
      const mb = await peerMailbox(did);
      if (!mb) throw new Error(`no mailbox found for ${nameOf(did) || short(did)}`);
      targets[did] = await fetchFromMailbox(mb, did);
      log(`key packages of ${short(did)}: ${(targets[did].key_packages || []).length} one-time${targets[did].last_resort ? ' + last resort' : ''}`, 'M§5.5');
    }
    const own = await ownForNewGroup();
    const before = new Set(messenger.conversations(now()).map((c) => c.group));
    await driveMailbox(messenger.create_group(targets, own || undefined, now()));
    activeConv = messenger.conversations(now()).find((c) => !before.has(c.group))?.group || activeConv;
    log(`group with ${dids.map((d) => nameOf(d) || short(d)).join(', ')} created at our mailbox (hub); the adds go out once the hub holds it`, 'M§7.3 · M§6.5');
  } catch (e) { notify(`cannot create the group: ${e.message || e}`); log(`✗ ${e.message || e}`, 'M§7.3'); }
  show('messages');
  renderMessages();
}

/** Add the identity `did` to the group conversation `gid` (M§7.3): its KeyPackages fetched with our grant, one commit. */
async function addMember(gid, did) {
  if (!messenger || !mailboxInfo) return;
  messenger.set_grants(heldGrantFrames());
  try {
    const mb = await peerMailbox(did);
    if (!mb) throw new Error(`no mailbox found for ${nameOf(did) || short(did)}`);
    const kps = await fetchFromMailbox(mb, did);
    await driveMailbox([{ send: messenger.add_member(gid, did, kps, now()) }]);
    log(`adding ${short(did)} to ${short(gid)}`, 'M§7.3');
  } catch (e) { notify(`cannot add ${nameOf(did) || short(did)}: ${e.message || e}`); }
  renderMessages();
}

/** Remove the member identity `did` from `gid`, every device of it (M§7.3; members check the commit, spec-gap 126). */
async function removeMember(gid, did) {
  if (!messenger) return;
  try {
    await driveMailbox([{ send: messenger.remove_member(gid, did, now()) }]);
    log(`removing ${short(did)} from ${short(gid)}: every device of it`, 'M§7.3');
  } catch (e) { notify(`cannot remove ${nameOf(did) || short(did)}: ${e.message || e}`); }
  renderMessages();
}

/** Move the conversation `gid` to our own mailbox as its hub (M§7.4); on `accepted` our mailbox follows and the new
 *  hub is bootstrapped with the GroupInfo and `handover_seq`. */
async function moveHub(gid) {
  if (!messenger) return;
  try {
    await driveMailbox([{ send: messenger.move_hub(gid, now()) }]);
    log(`moving ${short(gid)} to our mailbox as its hub`, 'M§7.4');
  } catch (e) { notify(`cannot move the conversation: ${e.message || e}`); }
  renderMessages();
}

/** Refresh our own key material in the conversation `gid` (post-compromise security): an Update commit (M§6.5). */
async function rekey(gid) {
  if (!messenger) return;
  try {
    await driveMailbox([{ send: messenger.rekey(gid, now()) }]);
    log(`refreshing our keys in ${short(gid)}`, 'M§6.5');
  } catch (e) { notify(`cannot refresh the keys: ${e.message || e}`); }
}

/** One roster change as members see it (M§7.3: attributed to the committing identity), or a hub move (M§7.4). */
function rosterLine(r) {
  const who = (d) => (d === identity.identity ? 'you' : nameOf(d) || short(d));
  const by = r.by ? who(r.by) : 'a device that no longer authenticates';
  if (r.hub) return `${by} moved the conversation's hub to ${r.hub === mailboxOf()?.did ? 'your mailbox' : `mailbox ${short(r.hub)}`}`;
  const parts = [];
  if (r.added.length) parts.push(`${by} added ${r.added.map(who).join(', ')}`);
  if (r.removed.length) parts.push(`${by} removed ${r.removed.map(who).join(', ')}`);
  for (const l of r.left) parts.push(`${who(l)} left${r.by && r.by !== l ? ` (removal committed by ${by})` : ''}`);
  return parts.join('; ');
}

/** M§9.4 → M§7.5: a group's hub has been unreachable past the threshold. Fetch the KeyPackages of the other
 *  identities of its last roster from their mailboxes, `successor_of` naming the dead group (served without a grant
 *  when the group is registered for them, spec-gap 61), and create the successor at our own mailbox; the pending items
 *  follow once it holds its members. A failure is retried with the §13.2 backoff (spec-gap 72). */
const successorBusy = new Set();
async function successorDue(d) {
  if (successorBusy.has(d.group)) return;
  successorBusy.add(d.group);
  try {
    log(`hub of ${short(d.group)} unreachable past the threshold: creating its successor${d.peers.length ? ` with ${d.peers.map((p) => nameOf(p) || short(p)).join(', ')}` : ''}`, 'M§9.4 · M§7.5');
    /** @type {Record<string, any>} */
    const kps = {};
    for (const peer of d.peers) {
      const mb = await peerMailbox(peer);
      if (!mb) throw new Error(`no mailbox found for ${short(peer)}`);
      kps[peer] = await fetchFromMailbox(mb, peer, d.group);
      log(`key packages of ${short(peer)} for the successor: ${(kps[peer].key_packages || []).length} one-time${kps[peer].last_resort ? ' + last resort' : ''}`, 'M§7.5');
    }
    const frames = messenger.create_successor(d.group, kps, now());
    await driveMailbox(frames.map((f) => ({ send: f })));
    log(`successor of ${short(d.group)} created at our mailbox; the members are added once the hub holds it`, 'M§7.5');
    if (activeConv === d.group) activeConv = messenger.conversations(now()).find((c) => c.predecessors.includes(d.group))?.group || activeConv;
  } catch (e) {
    messenger.successor_failed(d.group);
    log(`successor of ${short(d.group)} not created: ${e.message || e}; retried`, 'M§9.4');
  } finally { successorBusy.delete(d.group); }
}

/** Our own identity's KeyPackage directory answer (M§5.5), asked of our mailbox on the bound connection. */
async function fetchOwnKeyPackages() {
  const p = awaitEmission((e) => (e.key_packages && e.key_packages.subject === identity.identity) || e.error, 10000);
  mailboxConn.send(messenger.fetch_frame(mailboxOf().did, identity.identity, now()));
  const got = await p;
  if (got.error) throw new Error(got.error);
  return got.key_packages;
}

/** M§12.3, M§6.7: every device this browser knows of (the Devices list) that is not yet in the personal group and
 *  every conversation is added there by this device, personal group first; after that add every live archive key
 *  is re-sent so the new device reads the history. One reconciliation at a time; nothing when there is nothing to do. */
async function reconcileDevices() {
  if (!messenger || !mailboxInfo || !messenger.personal()) return;
  if (reconciling) return reconciling;
  reconciling = (async () => {
    for (const d of devices.map((d) => d.device).filter((d) => d !== identity.device)) {
      const groups = messenger.groups_for_new_device(d, now());
      for (const gid of groups) {
        if (!messenger || !mailboxInfo) return;
        try {
          const kps = await fetchOwnKeyPackages();
          if (!(kps.key_packages || []).length && !kps.last_resort) { log(`device ${short(d)}: no KeyPackage at the mailbox yet (it uploads on its first bind, M§5.5)`, 'M§12.3'); return; }
          const done = awaitEmission((e) => (e.ui === 'committed' && e.device === d && e.group === gid) || (e.refused && /commit|add/.test(e.refused)), 30000);
          await driveMailbox([{ send: messenger.add_device(gid, d, kps, now()) }]);
          log(`adding device ${short(d)} to ${gid === messenger.personal() ? 'the personal group' : 'a conversation'}`, 'M§12.3 · M§6.7');
          const r = await done;
          if (r.refused) { log(`device ${short(d)}: ${r.refused}`, 'M§12.3'); return; }
          if (r.personal) { await driveMailbox(messenger.resend_archive_keys(now())); log(`re-sent ${messenger.archive_keys().length} archive key(s) to the personal group for ${short(d)}`, 'M§12.3'); }
        } catch (e) {
          log(`device ${short(d)}: ${e.message || e}`, 'M§12.3');
          if (/is a recorder device/.test(e.message || e)) continue;   // C§5: it still joins the conversations
          return;
        }
      }
    }
  })().finally(() => { reconciling = null; renderMessages(); });
  return reconciling;
}

// ---------------------------------------------------------------- voice messages and blobs (M§8.4, M§5.6)

const b64u = {
  encode: (bytes) => { let s = ''; const u = new Uint8Array(bytes); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  decode: (text) => { const bin = atob(text.replace(/-/g, '+').replace(/_/g, '/')); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; },
};

/** The mailbox's blob endpoint, from its hello capabilities (M§4.3). */
function blobEndpoint() {
  const caps = /** @type {{ mailbox?: { blob_endpoint?: string } } | undefined} */ (mailboxInfo?.capabilities);
  return caps?.mailbox?.blob_endpoint || null;
}

/** Start or stop recording a voice message for the open conversation; on stop it is sealed, uploaded and sent. */
async function toggleVoice(opts = {}) {
  if (!messenger || !(opts.gid || activeConv)) return;
  if (recorder) { recorder.rec.stop(); return; }
  if (!blobEndpoint()) return notify('the mailbox advertises no blob endpoint (M§4.3)');
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mime = ['audio/ogg;codecs=opus', 'audio/webm;codecs=opus', 'audio/ogg', 'audio/webm'].find((m) => window.MediaRecorder?.isTypeSupported?.(m)) || '';
    const rec = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
    recorder = { rec, chunks: [], started: Date.now(), stream, gid: opts.gid || activeConv, purpose: opts.purpose || 'voice-message', session: opts.session };
    // M§13.2: a voicemail recording stops at the callee's max_duration_s
    if (opts.max_s) { const r = recorder; setTimeout(() => { if (recorder === r) { log(`voicemail: stopped at the callee's limit of ${opts.max_s} s`, 'M§13.2'); rec.stop(); } }, opts.max_s * 1000); }
    rec.ondataavailable = (ev) => { if (ev.data.size) recorder.chunks.push(ev.data); };
    rec.onstop = async () => {
      const r = recorder; recorder = null;
      r.stream.getTracks().forEach((t) => t.stop());
      $('compose-voice').textContent = 'Record voice'; $('compose-voice-state').textContent = 'sealing and uploading…';
      try { await sendVoice(r.gid, new Blob(r.chunks, { type: rec.mimeType || mime || 'audio/webm' }), Math.min(Date.now() - r.started, (opts.max_s || 1e9) * 1000), r.purpose, r.session); }
      catch (e) { notify(`voice message not sent: ${e.message || e}`); log(`✗ voice message: ${e.message || e}`, 'M§8.4'); }
      $('compose-voice-state').textContent = '';
    };
    rec.start(250);
    $('compose-voice').textContent = 'Stop and send'; $('compose-voice-state').textContent = 'recording…';
  } catch (e) { notify(`cannot record: ${e.message || e}`); }
}

/** M§8.4 rules 1–4 and M§5.6: seal under a fresh key, PUT the ciphertext to our mailbox with a signed blob-put, then
 *  send the audio content carrying the key; the deposit's manifest carries the blob without it. */
async function sendVoice(gid, blob, durationMs, purpose = 'voice-message', session = undefined) {
  const plain = await blob.arrayBuffer();
  const sealed = messenger.seal_blob(b64u.encode(plain));
  const uri = `${blobEndpoint().replace(/\/$/, '')}/${sealed.sha256}`;
  const auth = messenger.blob_put(sealed.sha256, sealed.size, now());
  const r = await fetch(uri, { method: 'PUT', headers: { Authorization: `DSIP ${auth}`, 'Content-Type': 'application/octet-stream' }, body: b64u.decode(sealed.sealed) });
  const answer = payloadOf(await r.text());
  if (!(r.status === 200 || r.status === 201) || answer.type !== 'accepted') throw new Error(`blob upload refused: ${r.status} ${answer.reason || ''}`);
  log(`blob ${sealed.sha256.slice(0, 12)}… (${sealed.size} B, ciphertext) uploaded to ${uri}: ${r.status}${answer.duplicate ? ' (already held)' : ''}`, 'M§5.6');
  const content_type = blob.type || 'audio/webm';
  lastVoice = { plain_size: plain.byteLength, sha256: sealed.sha256, size: sealed.size, content_type, duration_ms: durationMs };
  const frame = messenger.send_audio(gid, { uri, sha256: sealed.sha256, size: sealed.size, key: sealed.key, content_type }, durationMs, purpose, session, now());
  await driveMailbox([{ send: frame }]);
  log(`${purpose === 'voicemail' ? `voicemail for call ${short(session)}` : 'voice message'} sent: ${Math.round(durationMs / 1000)} s, ${content_type}, the key in the content and never on the mailbox`, 'M§8.2 · M§8.4');
}

/** Fetch and open a content's blob (M§8.4 rules 6–7): the sources the pinned rule orders (our mailbox's copy first),
 *  each verified by size and SHA-256 before it is decrypted; a source with nothing to serve is tried again as the pinned
 *  decision says (spec-gap 106). */
async function fetchBlob(gid, m, attempt = 1) {
  const id = m.object.id;
  if (media[id] && media[id].state !== 'retry') return;
  media[id] = { state: 'fetching', attempt };
  const sources = messenger.blob_sources(m.object, m.blobs || null);
  const tried = [];
  for (const uri of sources) {
    try {
      const r = await fetch(uri);
      if (!r.ok) { tried.push(messenger.blob_tried(uri, r.status, '')); log(`blob source ${uri}: ${r.status}`, 'M§8.4'); continue; }
      const stored = await r.arrayBuffer();
      try {
        const plain = messenger.open_blob(m.object, b64u.encode(stored));
        const url = URL.createObjectURL(new Blob([b64u.decode(plain)], { type: m.object.blob?.content_type || 'audio/webm' }));
        media[id] = { state: 'ready', url, from: uri, size: stored.byteLength };
        log(`blob for ${short(id)} fetched from ${uri}: size and SHA-256 verified, decrypted under the content's key`, 'M§8.4 rule 7');
        renderMessages();
        return;
      } catch (why) { tried.push(messenger.blob_tried(uri, 200, b64u.encode(stored))); log(`blob source ${uri}: ${why}`, 'M§8.4 rule 7'); }
    } catch (e) { tried.push(messenger.blob_tried(uri, 0, '')); log(`blob source ${uri}: ${e.message}`, 'M§8.4'); }
  }
  const d = messenger.blob_fetch_decision(m.object, tried, attempt);
  if (d.action === 'retry') {
    const delay = messenger.blob_retry_delay_s(attempt) * 1000;
    media[id] = { state: 'retry', attempt: attempt + 1 };
    log(`blob for ${short(id)}: nothing served yet, trying again in ${delay / 1000} s (attempt ${attempt})`, 'spec-gap 106');
    setTimeout(() => fetchBlob(gid, m, attempt + 1), delay);
  } else { const why = 'reason' in d ? d.reason : d.action; media[id] = { state: 'failed', why }; log(`blob for ${short(id)} given up: ${why}`, 'M§8.4'); renderMessages(); }
}

async function sendText(text) {
  if (!messenger || !activeConv || !text.trim()) return;
  try { await driveMailbox([{ send: messenger.send_text(activeConv, text.trim(), now()) }]); } catch (e) { notify(`not sent: ${e.message || e}`); }
}

/** A group conversation's name: its other members (M§7.3). */
function groupName(c) {
  const others = c.members.filter((m) => m !== identity.identity);
  return others.length ? `group: ${others.map((m) => nameOf(m) || short(m)).join(', ')}` : 'group (only you)';
}

/** Rebuild `el` with `build` only when `key`, a digest of what it shows, has changed. A render that changes nothing
 *  must leave the controls in place: a button replaced between a press and its release gets no click (the browser fires
 *  none), and a select rebuilt between a choice and its button loses the choice. */
function rebuildIf(el, key, build) {
  if (el.dataset.shown === key) return;
  el.dataset.shown = key; el.innerHTML = ''; build();
}

function renderMessages() {
  const mb = mailboxOf();
  const status = !mb ? 'no mailbox: set one under Settings → Network (the operator may serve a default)'
    : !messenger ? `mailbox ${mb.uri}: messaging not started`
    : !mailboxInfo ? `mailbox ${mb.uri} (${short(mb.did)}): connecting…`
    : `mailbox ${mb.uri} (${short(mb.did)}): bound · personal group ${messenger.personal() ? 'yes' : devices.length > 1 ? 'waiting to be added by another device (M§12.3)' : 'pending'} · this device's MLS state is kept in this browser's storage`;
  $('mailbox-status').textContent = status;
  const convs = messenger ? messenger.conversations(now()).filter((c) => c.kind !== 'personal') : [];
  const rows = convs.map((c) => ({
    group: c.group, active: c.group === activeConv,
    name: c.peer ? nameOf(c.peer) || '(unnamed)' : c.kind === 'group' ? groupName(c) : c.kind,
    did: c.peer || c.group,
    meta: `${c.members.length} identit${c.members.length === 1 ? 'y' : 'ies'}, epoch ${c.epoch}${c.pending ? `, ${c.pending} pending` : ''}${c.hub_down ? ', hub unreachable' : ''}${c.predecessors?.length ? ', continued from a group whose hub is gone' : ''}`,
  }));
  const ul = $('conv-list');
  rebuildIf(ul, JSON.stringify(rows), () => {
    if (!rows.length) ul.innerHTML = '<li class="muted small">none yet: open a contact and choose Message</li>';
    for (const r of rows) {
      const li = document.createElement('li');
      li.className = r.active ? 'active' : '';
      li.innerHTML = '<span class="name"></span> <code class="did"></code> <span class="muted small meta"></span>';
      li.querySelector('.name').textContent = r.name;
      li.querySelector('.did').textContent = r.did;
      li.querySelector('.meta').textContent = r.meta;
      li.onclick = () => { activeConv = r.group; renderMessages(); };
      ul.append(li);
    }
  });
  const rl = $('msg-request-list');
  const reqs = messenger ? Object.entries(/** @type {Record<string, IntroductionRequest>} */ (messenger.requests())) : [];
  rl.innerHTML = reqs.length ? '' : '<li class="muted small">none</li>';
  for (const [id, r] of reqs) { const li = document.createElement('li'); li.innerHTML = '<code class="did"></code> <span class="small purpose"></span>'; li.querySelector('.did').textContent = r.from; li.querySelector('.purpose').textContent = `“${r.purpose}” (${id})`; rl.append(li); }
  if (activeConv && !convs.some((c) => c.group === activeConv)) {
    const next = convs.find((c) => c.predecessors?.includes(activeConv));   // M§7.5: the conversation moved on
    if (next) activeConv = next.group;
  }
  const conv = convs.find((c) => c.group === activeConv);
  $('thread-title').textContent = conv ? (conv.peer ? nameOf(conv.peer) || '(unnamed)' : conv.kind === 'group' ? groupName(conv) : conv.kind) : 'no conversation open';
  // M§7.3: a group's members, each removable by any member identity; any contact not in it can be added
  const isGroup = conv?.kind === 'group';
  $('group-members').classList.toggle('hidden', !isGroup);
  if (isGroup) {
    const members = conv.members.map((m) => [m, m === identity.identity ? 'you ' : `${nameOf(m) || short(m)} `]);
    const ml = $('group-member-list');
    rebuildIf(ml, JSON.stringify([conv.group, members]), () => {
      for (const [m, label] of members) {
        const span = document.createElement('span'); span.className = 'member';
        span.textContent = label;
        if (m !== identity.identity) { const b = document.createElement('button'); b.type = 'button'; b.textContent = 'Remove'; b.dataset.member = m; b.onclick = () => removeMember(conv.group, m); span.append(b); }
        ml.append(span, ' ');
      }
    });
    const candidates = contacts.filter((c) => !conv.members.includes(c.did)).map((c) => [c.did, c.name || short(c.did)]);
    const sel = $('add-member-select');
    rebuildIf(sel, JSON.stringify([conv.group, candidates]), () => {
      for (const [did, label] of candidates) { const o = document.createElement('option'); o.value = did; o.textContent = label; sel.append(o); }
    });
    $('btn-add-member').disabled = !sel.options.length;
    $('btn-add-member').onclick = () => sel.value && addMember(conv.group, sel.value);
  }
  $('thread-did').textContent = conv?.peer || '';
  // C§5: a recorded conversation says who records; C§9: with the record-keeper, only call records go there
  const recorders = (conv?.recorders || []).map((r) => `${r.subject === identity.identity ? 'you' : nameOf(r.subject) || short(r.subject)} (device ${short(r.device)})`);
  const keeperConv = conv && conv.peer && conv.peer === settings.record_keeper;
  $('thread-meta').textContent = conv ? `group ${conv.group} · hub ${short(conv.hub.did)} (${conv.hub.did === mb?.did ? 'our mailbox' : 'their mailbox'}) · epoch ${conv.epoch}`
    + (conv.recorded ? ` · ⏺ RECORDED by ${recorders.join(', ')} (C§5)${keeperConv ? ': your record-keeper; call records go here (C§9)' : ''}` : '') : '';
  $('thread-meta').classList.toggle('warn', !!conv?.recorded);
  // C§5: content and receipts wait until the user accepts every recorder present; a new recorder asks again
  const ask = conv && conv.recorders_pending?.length && !messenger.is_recorder();
  $('recording-ask').classList.toggle('hidden', !ask);
  $('btn-leave').classList.toggle('hidden', !conv || conv.kind === 'personal');
  if (conv) $('btn-leave').onclick = () => leaveConversation(conv.group);
  // M§7.4: any member may move the group to another hub; this client offers its own mailbox
  $('btn-move-hub').classList.toggle('hidden', !conv || conv.kind === 'personal' || conv.hub.did === mb?.did);
  if (conv) $('btn-move-hub').onclick = () => moveHub(conv.group);
  if (ask) {
    $('btn-decline-recording').onclick = () => leaveConversation(conv.group);
    $('recording-ask-text').textContent = `${conv.recorders_pending.map((r) => `${nameOf(r.subject) || short(r.subject)} records this conversation on device ${short(r.device)}`).join('; ')}. `
      + 'Nothing you write, and no receipt, is sent here until you accept. Declining is leaving the conversation (C§5, M§7).';
    $('btn-accept-recording').onclick = () => acceptRecording(conv.group);
  }
  const th = $('thread');
  th.innerHTML = '';
  const timeline = conv ? /** @type {TimelineEntry[]} */ (messenger.timeline(conv.group)) : [];
  const thread = timeline.filter((m) => !m.call);
  // M§10.3: each identity's watermark is a content id; the seq it names is the thread's
  const marks = conv ? /** @type {Record<string, string>} */ (messenger.read_marks(conv.group)) : {};
  const seqOf = (id) => thread.find((m) => m.object.id === id)?.seq ?? -1;
  const theirRead = Math.max(-1, ...Object.entries(marks).filter(([who]) => who !== identity.identity).map(([, id]) => seqOf(id)));
  // M§7.3: roster changes, each before the first message the hub ordered after it
  const roster = conv ? /** @type {RosterEntry[]} */ (messenger.roster_log(conv.group)) : [];
  const rosterDiv = (r) => { const d = document.createElement('div'); d.className = 'msg roster muted small'; d.textContent = rosterLine(r); d.dataset.epoch = r.epoch; return d; };
  let ri = 0;
  for (const m of timeline) {
    while (ri < roster.length && m.seq != null && m.group === roster[ri].group && roster[ri].seq != null && roster[ri].seq < m.seq) th.append(rosterDiv(roster[ri++]));
    const d = document.createElement('div');
    if (m.call) {
      // M§13.3: this identity's call events for the peer, interleaved by the pinned rule
      d.className = 'msg call';
      d.textContent = `${m.call.outcome === 'declined' ? 'Declined call' : 'Missed call'} · ${new Date(m.call.at * 1000).toLocaleTimeString()}`;
      d.dataset.session = m.call.session;
      th.append(d);
      continue;
    }
    d.className = `msg${m.mine ? ' mine' : ''}${m.from_archive ? ' archive' : ''}`;
    d.innerHTML = '<span class="who"></span><span class="text"></span><span class="seq"></span><span class="read"></span>';
    d.querySelector('.who').textContent = m.mine ? 'you' : nameOf(m.sender) || short(m.sender);
    if (m.object.kind === 'audio' && m.object.blob) {
      const id = m.object.id, st = media[id];
      const text = d.querySelector('.text');
      if (st?.state === 'ready') {
        // one player per message, kept across re-renders (replacing it mid-play aborts the playback)
        if (!st.el) {
          const a = document.createElement('audio'); a.controls = true; a.src = st.url; a.dataset.id = id;
          a.onplay = () => { if (!m.mine) driveMailbox(messenger.played(m.group, id, now())).catch(() => {}); };   // M§10.4
          st.el = a;
        }
        text.append(st.el);
      } else text.textContent = st?.state === 'failed' ? `(voice message: ${st.why})` : '(voice message, fetching…)';
      text.append(` ${Math.round((m.object.duration_ms || 0) / 1000)} s${m.object.purpose === 'voicemail' ? ` voicemail${m.object.session ? ` for call ${short(m.object.session)}` : ''}` : ''}`);
      if (!st) setTimeout(() => fetchBlob(m.group, m), 0);
    } else d.querySelector('.text').textContent = m.object.text || `(${m.object.kind})`;
    d.querySelector('.seq').textContent = m.seq == null ? 'pending' : `#${m.seq}${m.mine && m.delivered && Object.keys(m.delivered).length ? ' ✓✓' : ''}`;
    const played = m.mine && m.played && Object.keys(m.played).length ? ' · played' : '';
    d.querySelector('.read').textContent = (m.mine && m.seq != null && m.seq <= theirRead ? 'read' : '') + played;
    th.append(d);
  }
  while (ri < roster.length) th.append(rosterDiv(roster[ri++]));
  $('thread-marks').textContent = conv ? Object.entries(marks).map(([who, id]) => `${who === identity.identity ? 'you' : nameOf(who) || short(who)} read through #${seqOf(id)}`).join(' · ') : '';
  th.scrollTop = th.scrollHeight;
  const canWrite = conv && conv.may_send !== false && !messenger.is_recorder();   // C§5: a recorder never speaks; nor does content reach one not accepted
  $('compose-text').disabled = !canWrite; $('compose-send').disabled = !canWrite;
  $('compose-voice').disabled = !canWrite || !blobEndpoint();
  renderRecords();
  // M§10.3: the thread is on screen, so its last content is read; the machine decides whether a watermark goes out
  const last = [...thread].reverse().find((m) => m.seq != null && m.object.object === 'content');
  if (conv && last && !$('view-messages').classList.contains('hidden') && lastRead[conv.group] !== last.object.id) {
    lastRead[conv.group] = last.object.id;
    setTimeout(() => { if (messenger) driveMailbox(messenger.read_through(conv.group, last.object.id, now())).catch(() => {}); }, 0);
  }
}

(async () => {
  await init();
  settings = (await store.get(key('settings'))) || {};
  if (settings.tn_nodes && !settings.nodes) { settings.nodes = settings.tn_nodes; delete settings.tn_nodes; }   // stage 4's name
  try {
    const r = await fetch('config.json');
    if (r.ok) { served = await r.json(); log(`operator defaults from ${location.origin}/config.json: ${Object.keys(served).join(', ') || 'none'}`, 'spec-gap 114'); }
  } catch { /* no operator config: every setting is the person's or built in */ }
  contacts = (await store.get(key('contacts'))) || [];
  purposes = (await store.get(key('purposes'))) || {};
  grantAudiences = (await store.get(key('grant-audiences'))) || {};
  links = (await store.get(key('links'))) || [];
  identity = await store.get(key('identity'));
  devices = (await store.get(key('devices'))) || [];
  revoked = (await store.get(key('revoked'))) || [];
  documents = (await store.get(key('documents'))) || {};
  hintSeq = (await store.get(key('hint_seq'))) || 0;

  const fresh = !identity;
  if (fresh) {
    // §7.3: no key is made until the person chooses: a new identity here, or an existing one from its file
    show('welcome');
    await new Promise((resolve) => {
      $('welcome-continue').onclick = async () => {
        identity = JSON.parse(create_identity(null, null, $('welcome-name').value.trim(), now()));
        await store.set(key('identity'), identity); resolve();
      };
      $('welcome-import').onclick = () => $('import-file').click();
      $('import-file').onchange = async (e) => { const f = e.target.files[0]; if (f) await importFromText(await f.text()); };
    });
  }

  if (!devices.some((d) => d.device === identity.device)) { devices.unshift({ device: identity.device, enrolled: Math.floor(now()) }); await store.set(key('devices'), devices); }
  renderHeader();
  renderSettings();
  const params = new URLSearchParams(location.search);
  if (params.get('contact') && params.get('token')) {
    // a contact link: add them, and introduce ourselves with the single-use token once the relay is bound
    const to = params.get('contact'), token = params.get('token'), name = params.get('name') || '';
    history.replaceState(null, '', location.pathname + (slot ? `?as=${slot}` : ''));
    onBound = async () => { await addContact(name, to); await sendIntroduction(to, `opened your contact link`, token); };
  }
  await startEngine();
  renderContacts();
  renderLinks();
  show('contacts');
  log(`identity ${identity.identity}`, '§7.3');
  log(`device   ${identity.device} (delegated, §7.4)`);

  for (const b of /** @type {NodeListOf<HTMLButtonElement>} */ (document.querySelectorAll('nav button[data-view]'))) b.onclick = () => { if (!call) { show(b.dataset.view); if (b.dataset.view === 'messages') renderMessages(); } else notify('finish the call first'); };
  $('btn-log-toggle').onclick = () => $('log-panel').classList.toggle('hidden');
  $('me-did').onclick = () => navigator.clipboard?.writeText(identity.identity).then(() => notify('your DID is on the clipboard'));
  // the form is read and cleared before the save is awaited: clearing after it wiped whatever was typed meanwhile
  $('contact-add').onsubmit = async (e) => {
    e.preventDefault();
    const [name, did, number] = ['contact-name', 'contact-did', 'contact-number'].map((id) => { const v = $(id).value; $(id).value = ''; return v; });
    await addContact(name, did, number);
  };
  $('call-number').onsubmit = (e) => { e.preventDefault(); callNumber($('call-tn').value); };
  $('set-did-web-use').onclick = () => useDidWeb($('set-did-web').value);
  $('btn-did-doc').onclick = downloadDidDocument;
  $('set-binding-save').onclick = () => saveBinding($('set-binding').value);
  $('set-numbers-save').onclick = saveNumbers;
  $('btn-add-document').onclick = async () => { await addDocument($('set-document').value); $('set-document').value = ''; };
  $('introduce-form').onsubmit = (e) => { e.preventDefault(); sendIntroduction($('introduce-form').dataset.to, $('introduce-purpose').value.trim()); };
  $('introduce-cancel').onclick = () => $('introduce-form').classList.add('hidden');
  $('compose').onsubmit = async (e) => { e.preventDefault(); const t = $('compose-text').value; $('compose-text').value = ''; await sendText(t); };
  $('compose-voice').onclick = () => toggleVoice();
  $('btn-new-group').onclick = () => {
    const ul = $('group-picker-list'); ul.innerHTML = '';
    for (const c of contacts) { const li = document.createElement('li'); li.innerHTML = '<label><input type="checkbox"> <span></span></label>'; li.querySelector('input').value = c.did; li.querySelector('span').textContent = c.name || short(c.did); ul.append(li); }
    if (!contacts.length) ul.innerHTML = '<li class="muted small">no contacts yet</li>';
    $('group-picker').classList.remove('hidden');
  };
  $('btn-cancel-group').onclick = () => $('group-picker').classList.add('hidden');
  $('btn-create-group').onclick = () => {
    const dids = [.../** @type {NodeListOf<HTMLInputElement>} */ (document.querySelectorAll('#group-picker-list input:checked'))].map((i) => i.value);
    $('group-picker').classList.add('hidden');
    if (dids.length) createGroup(dids);
  };
  $('btn-voicemail').onclick = leaveVoicemail;
  $('btn-contact-link').onclick = newContactLink;
  $('btn-accept').onclick = () => accept(false);
  $('btn-screen').onclick = () => accept(true);
  $('btn-decline').onclick = decline;
  $('btn-hangup').onclick = hangup;
  $('btn-add-video').onclick = () => sendUpdate(false);
  $('btn-escalate').onclick = () => sendUpdate(true);
  $('btn-answer-update').onclick = answerUpdate;
  $('btn-reject-update').onclick = rejectUpdate;
  $('set-name-save').onclick = async () => { identity.display_name = $('set-name').value.trim(); await store.set(key('identity'), identity); location.reload(); };
  $('set-first-contact').onchange = async (e) => { settings.first_contact_required = e.target.checked; await saveSettings(); location.reload(); };
  $('set-seal').onchange = async (e) => { settings.seal = e.target.checked; await saveSettings(); engine.setSeal(settings.seal); log(`call bodies ${settings.seal ? 'sealed to the callee when its key resolves' : 'sent in clear'}`, '§10.4'); };
  $('set-seal-presence').onchange = async (e) => { settings.seal_presence = e.target.checked; await saveSettings(); location.reload(); };
  $('set-recording-accept').onchange = async (e) => { settings.recording_accept = e.target.value; await saveSettings(); location.reload(); };
  $('presence-select').onchange = async (e) => { settings.presence = e.target.value || null; await saveSettings(); presenceSet(settings.presence); };
  $('audience-form').onsubmit = async (e) => {
    e.preventDefault();
    const name = $('audience-name').value.trim();
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(name)) { $('audience-status').textContent = 'a-z, 0-9 and -, starting with a letter (P§6)'; return; }
    $('audience-status').textContent = '';
    $('audience-name').value = '';
    await audienceSet(name, $('audience-state').value);
  };
  for (const id of ['in-recording', 'call-recording']) {
    $(`${id}-accept`).onclick = () => callRecording(true);
    $(`${id}-decline`).onclick = () => callRecording(false);
  }
  $('set-record-keeper-save').onclick = () => setRecordKeeper($('set-record-keeper').value.trim());
  $('btn-become-keeper').onclick = becomeRecordKeeper;
  $('set-read-disclosed').onchange = async (e) => { settings.read_disclosed = e.target.checked; await saveSettings(); if (messenger) { messenger.set_read_disclosed(settings.read_disclosed, now()); await store.set(key('messenger'), JSON.parse(messenger.save())); } log(`read receipts ${settings.read_disclosed ? 'disclosed to the conversation' : 'kept to your own devices'}`, 'M§10.5'); };
  $('set-network-save').onclick = async () => {
    settings.relay = $('set-relay').value.trim();
    try { settings.ice = $('set-ice').value.trim() ? JSON.parse($('set-ice').value) : undefined; } catch { return alert('ICE servers must be a JSON array'); }
    settings.nodes = noneable($('set-nodes').value, true);
    settings.publish_hint = $('set-publish-hint').checked;
    const mbUri = noneable($('set-mailbox').value), mbDid = $('set-mailbox-did').value.trim();
    settings.mailbox = mbUri === null ? null : mbUri ? { uri: mbUri, did: mbDid } : undefined;
    await saveSettings(); ice = null; renderSettings(); connect(); startMessaging();
  };
  $('btn-export').onclick = exportToFile;
  $('device-add').onsubmit = async (e) => {
    e.preventDefault();
    const did = $('device-did').value.trim();
    if (!/^did:key:/.test(did)) return alert('a device DID starts with did:key:');
    if (!devices.some((d) => d.device === did)) devices.push({ device: did });
    await store.set(key('devices'), devices);
    $('device-did').value = '';
    renderDevices();
    reconcileDevices();   // M§12.3: with a mailbox, the new device joins the personal group and every conversation
  };
  $('btn-import').onclick = () => $('import-file').click();
  $('import-file').onchange = async (e) => { const f = e.target.files[0]; if (f) await importFromText(await f.text()); };

  // Test and automation surface (the headless test drives the screens through the DOM; this exposes state only).
  /** @type {any} */ (window).dsip = {
    identity: () => identity.identity,
    state: () => (call ? engine.state(call.sid) || 'PREPARING' : null),   // null = no call; PREPARING = media being set up, no session yet
    session: () => call?.sid || null,
    recording: () => (call?.sid ? engine.recording(call.sid) : null),
    recordingText: () => $('call-recording-text').textContent || $('in-recording-text').textContent,
    holding: () => !!call?.media?.holding,
    seal: () => engine.seal(),
    setSeal: async (on) => { settings.seal = !!on; await saveSettings(); engine.setSeal(on); },
    relay: () => relayInfo?.did || null,
    rebuildContacts: () => { shownContacts = null; renderContacts(); },   // tests: the rows rebuilt as when another row changes
    inboundPackets: () => (call?.media ? call.media.inboundPackets() : Promise.resolve(0)),
    remoteKinds: () => ($('remote').srcObject ? $('remote').srcObject.getTracks().map((t) => t.kind).sort() : []),
    exportIdentity: (pass) => exportIdentity(identity, pass),
    importIdentity: async (text, pass) => (await enrol(await importIdentity(text, pass))).identity,
    device: () => identity.device,
    devices: () => devices.map((d) => d.device),
    revoked: () => revoked.map((r) => r.device),
    relayText: () => $('relay-status').textContent,
    addDocument,
    didDocument: () => JSON.stringify(ownDocument()),
    useDidWeb,
    setBinding: saveBinding,
    setNumbers: async ({ gateway, nodes, policy }) => { settings.gateway = gateway === null ? null : gateway || undefined; if (nodes !== undefined) settings.nodes = nodes; settings.tn_policy = policy ? JSON.parse(policy) : undefined; await saveSettings(); renderSettings(); },
    setNetwork: async ({ relay: url, ice: servers, nodes, publish }) => {
      if (url !== undefined) settings.relay = url || undefined;
      if (servers !== undefined) settings.ice = servers || undefined;
      if (nodes !== undefined) settings.nodes = nodes;
      if (publish !== undefined) settings.publish_hint = publish;
      await saveSettings(); ice = null; renderSettings(); connect();
    },
    served: () => served,
    network: () => $('network-effective').textContent,
    iceServers,
    discover,
    callRelay: () => (call && callRelays.get(call.sid)?.url) || null,
    callRelays: () => [...callRelays.values()].map((r) => r.url),
    route: () => $('call-route').textContent,
    mediaPath: () => (call?.media ? call.media.path() : Promise.resolve(null)),
    bindingStatus,
    callNumber,
    numberLine: () => $('call-number-line').textContent,
    inNumbers: () => $('in-numbers').textContent,
    inWarning: () => $('in-tn-warning').textContent,
    downgrade: () => $('call-downgrade').textContent,
    contacts: () => contacts.map((c) => c.did),
    presence: (did) => presenceShown.get(did) || null,
    watchPresence: (did) => presenceWatch(did),   // subscribe now, not at the next tick (a test after a grant)
    presenceBadge: (did) => [...document.querySelectorAll('#contact-list li')].find((li) => li.querySelector('.did').textContent === did)?.querySelector('.presence').textContent || null,
    setPresence: async (state) => { settings.presence = state || null; $('presence-select').value = state || ''; await saveSettings(); presenceSet(settings.presence); },
    setAudience: (name, state) => audienceSet(name, state || null),
    audiences: () => ({ ...(settings.presence_audiences || {}) }),
    sealing: () => sealing,                                   // P§12: {sealed, audiences: {label: tag}, reason?}
    setSealPresence: async (on) => { settings.seal_presence = !!on; await saveSettings(); },   // applies at the next load
    contactStatus: (did) => [...document.querySelectorAll('#contact-list li')].find((li) => li.querySelector('.did').textContent === did)?.querySelector('.status').textContent || null,
    requests: () => engine.requests(),
    saved: () => lastPersist,   // resolves once the latest contact-file write is in storage
    links: () => links.map((l) => l.url),
    note: () => $('call-note').textContent,
    mode: () => $('call-mode').textContent,
    // messaging (stage 6)
    mailbox: () => mailboxInfo?.did || null,
    mailboxText: () => $('mailbox-status').textContent,
    setMailbox: async (m) => { settings.mailbox = m === null ? null : m || undefined; await saveSettings(); renderSettings(); startMessaging(); },
    conversations: () => (messenger ? messenger.conversations(now()) : []),
    thread: (gid) => (messenger ? messenger.thread(gid || activeConv) : []),
    activeConversation: () => activeConv,
    openConversation: (gid) => { activeConv = gid; renderMessages(); },
    messagePeer,
    sendText,
    setRecordKeeper,
    becomeRecordKeeper,
    isRecorder: () => !!messenger?.is_recorder(),
    records: () => (messenger ? messenger.records() : []),
    heldRecords: () => (messenger ? messenger.held_records() : 0),
    acceptRecording,
    leaveConversation,
    createGroup,
    addMember,
    removeMember,
    moveHub,
    rosterLog: (gid) => (messenger ? messenger.roster_log(gid || activeConv) : []),
    rosterLines: () => [...document.querySelectorAll('#thread .msg.roster')].map((d) => d.textContent),
    personalGroup: () => messenger?.personal() || null,
    messengerSaved: () => store.get(key('messenger')),
    readMarks: (gid) => (messenger ? messenger.read_marks(gid || activeConv) : {}),
    setReadDisclosed: async (v) => { settings.read_disclosed = !!v; await saveSettings(); messenger?.set_read_disclosed(!!v, now()); renderSettings(); },
    reconcileDevices,
    archiveKeys: () => (messenger ? messenger.archive_keys() : []),
    addDevice: async (did) => { if (!devices.some((d) => d.device === did)) devices.push({ device: did }); await store.set(key('devices'), devices); renderDevices(); return reconcileDevices(); },
    // voice and blobs (round 2B)
    recordVoice: async (ms) => { await toggleVoice(); await new Promise((r) => setTimeout(r, ms)); const done = new Promise((r) => { const t = setInterval(() => { if (!recorder && lastVoice) { clearInterval(t); r(); } }, 100); }); await toggleVoice(); await done; return lastVoice; },
    lastVoice: () => lastVoice,
    // voicemail and call history (round 2C)
    voicemailOffered: () => pendingVoicemail,
    leaveVoicemail: async (ms) => { await leaveVoicemail(); await new Promise((r) => setTimeout(r, ms)); lastVoice = null; await leaveVoicemail(); await until(() => lastVoice, 30000); return lastVoice; },
    calls: () => messenger.calls(),
    // external join (round 2C)
    available: () => messenger.available(),
    // successor groups (round 2D)
    setHubTimeout: async (s) => { settings.hub_timeout_s = s; await saveSettings(); messenger?.set_hub_timeout(s); },
    setGapTimeout: async (s) => { settings.gap_timeout_s = s; await saveSettings(); messenger?.set_gap_timeout(s); },
    rekey,
    outages: () => messenger.outages(),
    joinAvailable,
    timeline: (gid) => messenger.timeline(gid || activeConv),
    media: (id) => (media[id] ? { state: media[id].state, from: media[id].from, size: media[id].size, why: media[id].why } : null),
    playAudio: async (id) => { const a = /** @type {HTMLAudioElement | null} */ (document.querySelector(`audio[data-id="${id}"]`)); if (!a) return false; await a.play().catch(() => {}); return true; },
    blobEndpoint,
  };
})();
