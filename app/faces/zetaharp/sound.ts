// SPDX-License-Identifier: AGPL-3.0-or-later
import { amplitude, MAX_HEIGHT, MIN_HEIGHT, termCount, thetaPrime } from "./math.js";

export interface SoundFrame {
  height: number;
  velocity: number;
  volume: number;
  degrees: boolean;
  solo?: number | null;
}

interface Voice {
  oscillator: OscillatorNode;
  gain: GainNode;
}

interface Band {
  count: number;
  amplitudeSquared: number;
  weight: number;
  weightedLog: number;
}

const INDIVIDUALS = 24;
const BANDS = 8;
const LOW_HZ = 8;
const HIGH_HZ = 12_000;
const AUDIO_ERROR = "zetaharp:audio-unavailable";

export class HarpSound {
  private context: AudioContext | null = null;
  private master: GainNode | null = null;
  private voices: Voice[] = [];
  private requested = false;
  private running = false;
  private disposed = false;
  private revision = 0;
  private cachedCount = -1;
  private bands: Band[] = [];
  private frame: SoundFrame | null = null;
  private readonly pageHide = () => { void this.disable(); };

  constructor() {
    window.addEventListener("pagehide", this.pageHide);
  }

  async enable(): Promise<void> {
    if (this.disposed) throw new Error(AUDIO_ERROR);
    const revision = ++this.revision;
    this.requested = true;
    try {
      if (!this.context) this.create();
      const context = this.context;
      if (!context) throw new Error(AUDIO_ERROR);
      await context.resume();
      if (this.disposed || !this.requested) {
        if (context.state === "running") await context.suspend();
        return;
      }
      if (revision !== this.revision) return;
      if (context.state !== "running") throw new Error(AUDIO_ERROR);
      this.running = true;
      if (this.frame) this.update(this.frame);
    } catch {
      if (revision === this.revision) {
        this.requested = false;
        this.running = false;
        this.silence();
      }
      throw new Error(AUDIO_ERROR);
    }
  }

  async disable(): Promise<void> {
    const revision = ++this.revision;
    this.requested = false;
    this.running = false;
    this.silence();
    const context = this.context;
    if (!context || context.state === "closed") return;
    try {
      await context.suspend();
      if (revision !== this.revision && this.requested && !this.disposed) {
        await context.resume();
        if (this.requested && !this.disposed && context.state === "running") {
          this.running = true;
          if (this.frame) this.update(this.frame);
        } else if (context.state === "running") {
          await context.suspend();
        }
      }
    } catch {
      this.running = false;
      this.silence();
    }
  }

  update(frame: SoundFrame): string {
    if (frame === null || typeof frame !== "object" || Array.isArray(frame) ||
        !Number.isFinite(frame.height) || frame.height < MIN_HEIGHT || frame.height > MAX_HEIGHT ||
        !Number.isFinite(frame.velocity) || !Number.isFinite(frame.volume) ||
        frame.volume < 0 || frame.volume > 1 || typeof frame.degrees !== "boolean" ||
        (frame.solo != null && (!Number.isSafeInteger(frame.solo) || frame.solo < 1 || frame.solo > termCount(frame.height)))) {
      this.running = false;
      this.silence();
      throw new Error("zetaharp:invalid-audio-frame");
    }
    this.frame = { ...frame };
    const count = termCount(frame.height);
    this.plan(count);
    const individual = Math.min(count, INDIVIDUALS);
    const derivative = thetaPrime(frame.height);
    if (frame.solo != null) {
      const rawHz = Math.abs(frame.velocity * (derivative - Math.log(frame.solo)) / (2 * Math.PI));
      const hz = frame.degrees && rawHz > 0
        ? 440 * 2 ** (Math.round(12 * Math.log2(rawHz / 440)) / 12) : rawHz;
      const audible = Number.isFinite(hz) && rawHz >= LOW_HZ && rawHz <= HIGH_HZ && hz >= LOW_HZ && hz <= HIGH_HZ;
      this.setVoice(0, hz, audible && this.running ? amplitude(frame.solo) * frame.volume * 0.025 : 0);
      for (let index = 1; index < INDIVIDUALS + BANDS; index += 1) this.setVoice(index, 0, 0);
      return `Selected term n=${frame.solo}: ${frame.degrees ? "artistic semitone snapping" : "raw frequency law"}; one volume; no bands; ` +
        `vₜ ${frame.velocity.toPrecision(4)} height units/s; ` +
        (audible ? `${hz.toFixed(3)} Hz.` : "rate outside 8–12,000 Hz muted.");
    }
    let muted = 0;
    for (let index = 0; index < INDIVIDUALS + BANDS; index += 1) {
      const exists = index < individual ||
        (index >= INDIVIDUALS && index - INDIVIDUALS < this.bands.length);
      if (!exists) {
        this.setVoice(index, 0, 0);
        continue;
      }
      const band = index >= INDIVIDUALS ? this.bands[index - INDIVIDUALS] : null;
      const logTerm = band ? band.weightedLog / band.weight : Math.log(index + 1);
      const strength = band ? Math.sqrt(band.amplitudeSquared) : amplitude(index + 1);
      const rawHz = Math.abs(frame.velocity * (derivative - logTerm) / (2 * Math.PI));
      const hz = frame.degrees && rawHz > 0
        ? 440 * 2 ** (Math.round(12 * Math.log2(rawHz / 440)) / 12)
        : rawHz;
      const audible = Number.isFinite(hz) && rawHz >= LOW_HZ && rawHz <= HIGH_HZ &&
        hz >= LOW_HZ && hz <= HIGH_HZ;
      if (!audible) muted += 1;
      this.setVoice(index, hz, audible && this.running ? strength * frame.volume * 0.025 : 0);
    }
    const mode = frame.degrees ? "artistic semitone snapping" : "Truth Audio";
    return `${mode}: ${count} terms; ${individual} individual voices; ${this.bands.length} energy-preserving bands; ` +
      `vₜ ${frame.velocity.toPrecision(4)} height units/s; one volume; ${muted} voices or bands outside 8–12,000 Hz muted.`;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.requested = false;
    this.running = false;
    this.revision += 1;
    window.removeEventListener("pagehide", this.pageHide);
    this.silence();
    for (const voice of this.voices) {
      voice.oscillator.stop();
      voice.oscillator.disconnect();
      voice.gain.disconnect();
    }
    this.voices = [];
    this.master?.disconnect();
    const context = this.context;
    this.context = null;
    this.master = null;
    if (context && context.state !== "closed") void context.close().catch(() => {});
  }

  private create(): void {
    if (typeof AudioContext !== "function") throw new Error(AUDIO_ERROR);
    const context = new AudioContext();
    const oscillators: OscillatorNode[] = [];
    const gains: GainNode[] = [];
    const started: OscillatorNode[] = [];
    let master: GainNode | null = null;
    const voices: Voice[] = [];
    try {
      master = context.createGain();
      master.gain.value = 1;
      master.connect(context.destination);
      for (let index = 0; index < INDIVIDUALS + BANDS; index += 1) {
        const oscillator = context.createOscillator();
        oscillators.push(oscillator);
        const gain = context.createGain();
        gains.push(gain);
        oscillator.type = "sine";
        oscillator.frequency.value = LOW_HZ;
        gain.gain.value = 0;
        oscillator.connect(gain);
        gain.connect(master);
        oscillator.start();
        started.push(oscillator);
        voices.push({ oscillator, gain });
      }
    } catch {
      for (const oscillator of started) oscillator.stop();
      for (const oscillator of oscillators) oscillator.disconnect();
      for (const gain of gains) gain.disconnect();
      master?.disconnect();
      void context.close().catch(() => {});
      throw new Error(AUDIO_ERROR);
    }
    this.context = context;
    this.master = master;
    this.voices = voices;
  }

  private plan(count: number): void {
    if (count === this.cachedCount) return;
    this.cachedCount = count;
    const first = Math.min(count, INDIVIDUALS);
    const bandCount = Math.min(BANDS, count - first);
    const bands = Array.from({ length: bandCount }, () => ({
      count: 0, amplitudeSquared: 0, weight: 0, weightedLog: 0,
    }));
    const low = Math.log(first + 0.5);
    const width = Math.log(count + 0.5) - low;
    for (let term = first + 1; term <= count; term += 1) {
      const index = Math.min(bandCount - 1, Math.floor(bandCount * (Math.log(term) - low) / width));
      const band = bands[index];
      const strength = amplitude(term);
      band.count += 1;
      band.amplitudeSquared += strength * strength;
      band.weight += strength;
      band.weightedLog += strength * Math.log(term);
    }
    this.bands = bands.filter(band => band.count > 0);
  }

  private setVoice(index: number, hz: number, gain: number): void {
    const context = this.context;
    const voice = this.voices[index];
    if (!context || !voice || context.state === "closed") return;
    if (hz >= LOW_HZ && hz <= HIGH_HZ) {
      voice.oscillator.frequency.setTargetAtTime(hz, context.currentTime, 0.035);
    }
    voice.gain.gain.setTargetAtTime(gain, context.currentTime, 0.04);
  }

  private silence(): void {
    const context = this.context;
    if (!context || context.state === "closed") return;
    for (const voice of this.voices) {
      voice.gain.gain.cancelScheduledValues(context.currentTime);
      voice.gain.gain.setValueAtTime(0, context.currentTime);
    }
  }
}
