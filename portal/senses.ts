// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ExchangeMethod } from "./contracts.js";
import type { ChannelProbe, ChannelRequest } from "./engine.js";
import { checkAbort, domain, hex, refuse, unhex } from "./bytes.js";
import { contextDigest, type Channels } from "./wire.js";

type MotionPermission = typeof DeviceMotionEvent & { requestPermission?: () => Promise<string> };
export class BrowserChannelProbe implements ChannelProbe {
  private audio: AudioContext | null = null;
  private microphone: MediaStream | null = null;
  private motionAllowed = false;
  private motionAt = 0;
  private generation = 0;
  private readonly movement = (event: DeviceMotionEvent): void => {
    const acceleration = event.acceleration;
    if (acceleration && Math.hypot(acceleration.x ?? 0, acceleration.y ?? 0, acceleration.z ?? 0) >= 0.8) this.motionAt = performance.now();
  };
  async prepare(method: ExchangeMethod): Promise<void> {
    this.close();
    const generation = this.generation;
    if (method === "optical") return;
    const audio = new AudioContext();
    this.audio = audio;
    try {
      const resumed = audio.resume();
      let permission: Promise<string> = Promise.resolve("granted");
      if (method === "optical-audio-motion") {
        const sensor = typeof DeviceMotionEvent === "undefined" ? null : DeviceMotionEvent as MotionPermission;
        if (!sensor) refuse("motion-permission");
        if (sensor.requestPermission) permission = sensor.requestPermission();
      }
      const [, permitted] = await Promise.all([resumed, permission]);
      if (generation !== this.generation) refuse("cancelled");
      if (permitted !== "granted") refuse("motion-permission");
      if (method === "optical-audio-motion") {
        this.motionAllowed = true;
        window.addEventListener("devicemotion", this.movement);
      }
      const microphone = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false }, video: false });
      if (generation !== this.generation) { microphone.getTracks().forEach(track => track.stop()); refuse("cancelled"); }
      this.microphone = microphone;
    } catch (error) { if (generation === this.generation) this.close(); throw error; }
  }
  close(): void {
    ++this.generation;
    window.removeEventListener("devicemotion", this.movement);
    this.motionAllowed = false; this.motionAt = 0;
    this.microphone?.getTracks().forEach(track => track.stop()); this.microphone = null;
    void this.audio?.close(); this.audio = null;
  }
  async collect(request: ChannelRequest, signal: AbortSignal): Promise<Channels> {
    checkAbort(signal);
    const audio = this.audio, microphone = this.microphone;
    if (!audio || audio.state !== "running" || !microphone) refuse("sound-not-prepared");
    const bound = await contextDigest(request.context);
    const nonceA = unhex(request.nonceA, 32), nonceB = unhex(request.nonceB, 32);
    const seed = await domain("copresence.sound.v1", bound, nonceA, nonceB);
    const tokenA = (await domain("copresence.sound-token.v1", seed, new Uint8Array([0]))).slice(0, 4);
    const tokenB = (await domain("copresence.sound-token.v1", seed, new Uint8Array([1]))).slice(0, 4);
    checkAbort(signal);
    const own = request.side === "A" ? tokenA : tokenB, peer = request.side === "A" ? tokenB : tokenA;
    const localBase = request.side === "A" ? 1500 : 3500, peerBase = request.side === "A" ? 3500 : 1500;
    const nibbles = (bytes: Uint8Array): number[] => Array.from(bytes).flatMap(byte => [byte >>> 4, byte & 15]);
    const emitted = nibbles(own), expected = nibbles(peer);
    const gain = audio.createGain(); gain.gain.value = 0.07; gain.connect(audio.destination);
    const oscillators: OscillatorNode[] = [];
    const start = audio.currentTime + 0.12;
    for (let repeat = 0; repeat < 4; ++repeat) for (let i = 0; i < emitted.length; ++i) {
      const oscillator = audio.createOscillator();
      oscillator.frequency.value = localBase + emitted[i] * 80;
      oscillator.connect(gain);
      const at = start + repeat * 1.6 + i * 0.18;
      oscillator.start(at); oscillator.stop(at + 0.11); oscillators.push(oscillator);
    }
    const source = audio.createMediaStreamSource(microphone), analyser = audio.createAnalyser();
    analyser.fftSize = 2048; analyser.smoothingTimeConstant = 0;
    source.connect(analyser);
    const bins = new Float32Array(analyser.frequencyBinCount);
    const samples: number[] = [];
    let silence = true, last = -1, stable = 0;
    const started = performance.now();
    try {
      await new Promise<void>((resolve, reject) => {
        let interval: ReturnType<typeof setInterval>;
        const cleanup = (): void => { clearInterval(interval); signal.removeEventListener("abort", abort); };
        const abort = (): void => { cleanup(); reject(new Error("copresence:cancelled")); };
        signal.addEventListener("abort", abort, { once: true });
        interval = setInterval(() => {
          if (performance.now() - started > 7200) { cleanup(); reject(new Error("copresence:sound-unmatched")); return; }
          analyser.getFloatFrequencyData(bins);
          let best = -Infinity, symbol = -1;
          for (let n = 0; n < 16; ++n) {
            const index = Math.round((peerBase + n * 80) * analyser.fftSize / audio.sampleRate);
            const level = Math.max(bins[index - 1] ?? -Infinity, bins[index] ?? -Infinity, bins[index + 1] ?? -Infinity);
            if (level > best) { best = level; symbol = n; }
          }
          if (best < -50) { silence = true; stable = 0; return; }
          if (symbol === last) ++stable; else { last = symbol; stable = 1; }
          if (silence && stable >= 2) {
            silence = false; samples.push(symbol);
            if (samples.length > 32) samples.shift();
            if (samples.length >= expected.length && expected.every((n, i) => samples[samples.length - expected.length + i] === n)) {
              cleanup(); resolve();
            }
          }
        }, 20);
        if (signal.aborted) abort();
      });
      // A peer may have begun listening after this device. Keep repeated tokens audible.
      await new Promise<void>((resolve, reject) => {
        const abort = (): void => { clearTimeout(timer); reject(new Error("copresence:cancelled")); };
        const timer = setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, Math.max(0, 6400 - (performance.now() - started)));
        signal.addEventListener("abort", abort, { once: true });
        if (signal.aborted) abort();
      });
      if (request.context.required_layers.motion) {
        if (!this.motionAllowed) refuse("motion-not-prepared");
        await new Promise<void>((resolve, reject) => {
          const deadline = performance.now() + 2000;
          const interval = setInterval(() => {
            if (signal.aborted) { clearInterval(interval); reject(new Error("copresence:cancelled")); }
            else if (this.motionAt >= started && this.motionAt <= performance.now()) { clearInterval(interval); resolve(); }
            else if (performance.now() > deadline) { clearInterval(interval); reject(new Error("copresence:motion-unobserved")); }
          }, 40);
        });
      }
      return { sound: hex(seed), motion: request.context.required_layers.motion ? hex(await domain("copresence.motion.v1", bound, nonceA, nonceB)) : null };
    } finally {
      for (const oscillator of oscillators) { try { oscillator.stop(); } catch { /* Already stopped. */ } oscillator.disconnect(); }
      source.disconnect(); analyser.disconnect(); gain.disconnect();
    }
  }
}
