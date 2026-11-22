// @ts-check
// WebRTC for one call: the browser's RTCPeerConnection and the local stream. Local candidates go to the call glue,
// which holds them until the session is ACTIVE and sends them in signed `info`. Remote candidates that arrive before
// the remote description is set wait here.
//
// Spec: WebRTC Media Binding B§2–B§6 (SDP in `transports[].sdp`, one answer per offer), §12.12 (candidates in
// `info`, ACTIVE-only), §14.1 (no media before a signed answer), §14.4 (screening: receive only), C§4 (media held
// while a recording waits on acceptance).

/**
 * What the call screen listens for. Every handler is optional.
 * @typedef {object} MediaHandlers
 * @property {(c: { candidate: string, sdp_mid: string, sdp_m_line_index: number } | null) => void} [candidate]
 * @property {(stream: MediaStream) => void} [track]
 * @property {(state: RTCPeerConnectionState) => void} [state]
 */

export class Media {
  /** @param {RTCIceServer[]} iceServers @param {MediaHandlers} on */
  constructor(iceServers, on) {
    this.pc = new RTCPeerConnection({ iceServers });
    this.on = on;
    /** @type {MediaStream | null} */
    this.localStream = null;
    // every remote track joins one stream: a track added later by an update (video added to an audio call) arrives
    // with a stream of its own, and showing that stream instead would drop the audio
    this.remoteStream = new MediaStream();
    /** @type {RTCIceCandidateInit[]} */
    this.pendingRemote = [];
    /** @type {Map<RTCRtpSender, MediaStreamTrack> | null} */
    this.held = null;
    this.pc.onicecandidate = ({ candidate }) => {
      // Firefox marks the end of each m-section with an empty candidate string; the binding carries real candidates
      // (`^candidate:`, B§ Appendix A) and one end_of_candidates, which the final null event supplies.
      if (candidate && !candidate.candidate) return;
      this.on.candidate?.(candidate
        ? { candidate: candidate.candidate, sdp_mid: candidate.sdpMid ?? '0', sdp_m_line_index: candidate.sdpMLineIndex ?? 0 }
        : null);
    };
    this.pc.ontrack = (ev) => {
      for (const t of this.remoteStream.getTracks()) if (t.kind === ev.track.kind && t !== ev.track) this.remoteStream.removeTrack(t);
      if (!this.remoteStream.getTracks().includes(ev.track)) this.remoteStream.addTrack(ev.track);
      this.on.track?.(this.remoteStream);
    };
    this.pc.onconnectionstatechange = () => this.on.state?.(this.pc.connectionState);
  }

  /** @param {boolean} video */
  async capture(video) {
    const s = await navigator.mediaDevices.getUserMedia({ audio: true, video });
    this.localStream = s;
    s.getTracks().forEach((t) => this.pc.addTrack(t, s));
    return s;
  }

  /** An offer to send (§16.3). */
  async offer() {
    const o = await this.pc.createOffer();
    await this.pc.setLocalDescription(o);
    return o.sdp;
  }

  /** Answer a remote offer; with `screening`, receive only (§14.4). */
  /** @param {string} offerSdp @param {boolean} screening */
  async answer(offerSdp, screening) {
    await this.pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
    if (screening) this.pc.getTransceivers().forEach((t) => { t.direction = 'recvonly'; });
    const a = await this.pc.createAnswer();
    await this.pc.setLocalDescription(a);
    await this.flushRemote();
    return a.sdp;
  }

  /** @param {string} sdp */
  async acceptAnswer(sdp) {
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
    await this.flushRemote();
  }

  /** Discard the offer made for an update the far end refused, or that lost a glare (B§5.2, §12.8 rule 5). */
  async rollback() {
    if (this.pc.signalingState === 'have-local-offer') await this.pc.setLocalDescription({ type: 'rollback' });
  }

  /** @param {{ candidate: string, sdp_mid?: string, sdp_m_line_index?: number }} c */
  async addRemoteCandidate(c) {
    const cand = { candidate: c.candidate, sdpMid: c.sdp_mid, sdpMLineIndex: c.sdp_m_line_index };
    if (this.pc.remoteDescription) await this.pc.addIceCandidate(cand).catch(() => {});
    else this.pendingRemote.push(cand);
  }

  async flushRemote() {
    const batch = this.pendingRemote; this.pendingRemote = [];
    for (const c of batch) await this.pc.addIceCandidate(c).catch(() => {});
  }

  /** Add a camera track for an `update` (escalation to video). */
  async addVideo() {
    if (this.localStream?.getVideoTracks().length) return;
    const v = await navigator.mediaDevices.getUserMedia({ video: true });
    const local = this.localStream ?? v;
    this.localStream = local;
    // the camera joins the stream the audio is in, so the far side sees one stream with both
    if (local !== v) v.getTracks().forEach((t) => local.addTrack(t));
    v.getTracks().forEach((t) => this.pc.addTrack(t, local));
  }

  /** Leave screening (§14.4 step 3): capture audio (and video if asked) and send on the transceivers that were
   *  receive-only; the caller then sees an `update` with `answered_by: "user"`. */
  /** @param {boolean} video */
  async unscreen(video) {
    const s = await navigator.mediaDevices.getUserMedia({ audio: true, video });
    for (const track of s.getTracks()) {
      const t = this.pc.getTransceivers().find((x) => x.receiver.track?.kind === track.kind);
      if (t) { t.direction = 'sendrecv'; await t.sender.replaceTrack(track); } else this.pc.addTrack(track, s);
    }
    this.localStream = s;
    return s;
  }

  /** Send nothing until `resume` (C§4: the other side records, and the user has not accepted it): every sender's
   *  track is taken off, and kept to put back. */
  async hold() {
    this.held ??= new Map();
    for (const s of this.pc.getSenders()) if (s.track) { this.held.set(s, s.track); await s.replaceTrack(null); }
  }

  /** Send again what `hold` took off (§14.1: called once the signed answer made the call active). */
  async resume() {
    if (!this.held) return;
    for (const [s, t] of this.held) await s.replaceTrack(t).catch(() => {});
    this.held = null;
  }

  /** Whether `hold` keeps our media off the wire. */
  get holding() { return !!this.held; }

  /** Inbound RTP packets received so far (for tests and the call screen). */
  async inboundPackets() {
    let n = 0;
    const stats = await this.pc.getStats();
    stats.forEach((s) => { if (s.type === 'inbound-rtp') n += s.packetsReceived || 0; });
    return n;
  }

  /** The candidate pair in use (`local`/`remote` candidate types, `protocol`, `relayed`, `rtt_ms`), or null. */
  async path() {
    const stats = await this.pc.getStats();
    /** @type {Record<string, any>} */
    const by = {}; stats.forEach((s) => { by[s.id] = s; });
    /** @type {any} */
    let pair = null;
    stats.forEach((s) => { if (s.type === 'candidate-pair' && (s.nominated || s.selected) && s.state === 'succeeded') pair = pair && !s.nominated ? pair : s; });
    if (!pair) stats.forEach((s) => { if (s.type === 'transport' && s.selectedCandidatePairId && by[s.selectedCandidatePairId]) pair = by[s.selectedCandidatePairId]; });
    if (!pair) return null;
    const l = by[pair.localCandidateId] || {}, r = by[pair.remoteCandidateId] || {};
    return { local: l.candidateType || '?', remote: r.candidateType || '?', protocol: l.protocol || r.protocol || '?', relayed: l.candidateType === 'relay' || r.candidateType === 'relay',
      rtt_ms: pair.currentRoundTripTime != null ? Math.round(pair.currentRoundTripTime * 1000) : null };
  }

  close() {
    this.pc.close();
    this.localStream?.getTracks().forEach((t) => t.stop());
    this.localStream = null;
  }
}
