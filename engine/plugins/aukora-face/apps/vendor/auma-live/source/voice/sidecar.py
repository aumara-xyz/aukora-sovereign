#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Aumara and Peter Viviani
"""Auma Live Linux CPU voice organ; existing WebSocket protocol, no authority.
Mic PCM16/16kHz -> Silero VAD v6 -> faster-whisper tiny.en CPU int8.
Reply text -> Kokoro CPU int8 Aurora blend -> PCM16/24kHz.
No microphone capture, transcript persistence, provider calls, or key access.
Models and the entire environment are verified by launch.py before Python executes.
Runtime networking is restricted to loopback by the operator's service sandbox.
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "ORT_DISABLE_TELEMETRY"):
    os.environ[name] = "1"
os.environ["ONNX_PROVIDER"] = "CPUExecutionProvider"

import numpy as np

# The sidecar runs from inside a materialized release, whose tree is verified file-for-file (strip manifest). Importing a
# sibling module would otherwise write __pycache__/ there and the NEXT launch would refuse the release as tampered.
sys.dont_write_bytecode = True


# kokoro's phonemizer logs a "words count mismatch" WARNING on almost every
# short line — hundreds of lines of noise in the pm2 err log that buried the
# one message that mattered (the Errno 48 bind race). Quiet it to ERROR.
logging.getLogger("phonemizer").setLevel(logging.ERROR)

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.environ.get("AUKORA_VOICE_MODELS_DIR", os.path.join(HERE, "models"))

PORT = int(os.environ.get("AUKORA_VOICE_PORT", "7512"))
HOST = "127.0.0.1"  # loopback only — never configurable outward
ALLOWED_ORIGINS = set(filter(None, os.environ.get("AUKORA_VOICE_ORIGINS", "").split(",")))

SR_IN = 16000          # mic sample rate (browser downsamples to this)
SR_OUT = 24000         # kokoro output rate
FRAME = 512            # VAD frame @ 16 kHz = 32 ms
VAD_CTX = 64           # silero v6 wants 64 samples of left-context per frame

# --- turn-taking tuning (frames are 32 ms) ---
# ONE clean endpointing path (the GLaDOS/LiveKit rule: prove the flat baseline
# before adding semantics). Speculative eager-decode and the 3-tier adaptive
# commit were removed 2026-07-04 — they fired the mind on half-sentence guesses,
# which is what made her feel dumb (answering before the owner finished).
START_PROB = 0.55      # speech starts above this…
START_PROB_HER = float(os.environ.get("AUKORA_VOICE_BARGE_PROB", "0.78"))
                       # …but while SHE is audible the bar is higher. Echo
                       #   cancellation ducks the near-end mic during her
                       #   playback, so this bar decides whether interrupting
                       #   her is possible at all.
END_PROB = 0.35        # below this counts toward end-of-utterance
MIN_START_FRAMES = 4       # 128 ms of speech to open an utterance
MIN_START_FRAMES_HER = int(os.environ.get("AUKORA_VOICE_BARGE_FRAMES", "9"))
                           # 288 ms accumulated to count as a real interruption.
                           #   While she is audible, a sub-bar frame DECAYS the
                           #   run by one instead of zeroing it: real speech
                           #   dips below any bar at unvoiced consonants
                           #   (s/f/t/k) and inter-word gaps, and a hard reset
                           #   made short interjections ("wait", "stop")
                           #   mathematically unable to interrupt her — the
                           #   felt symptom was a voice that could only be
                           #   interrupted between her sentences. Her own
                           #   residual echo stays below the raised bar, so it
                           #   never accumulates 9 net frames.
PREROLL_FRAMES = int(os.environ.get("AUKORA_VOICE_PREROLL_FRAMES", "16"))
                           # 512 ms kept from before speech started, so the
                           #   first consonant is never the part that is lost
MAX_UTTER_SEC = 25         # force-close runaway utterances
END_SILENCE_FRAMES = int(os.environ.get("AUKORA_VOICE_END_SILENCE_FRAMES", "20"))
                           # ~640 ms of quiet ends the turn. At 384 ms an
                           #   ordinary mid-sentence breath ended the turn and
                           #   she answered half a thought; past ~700 ms the
                           #   lane starts to feel like waiting on a machine.

# Beam width for the faster-whisper fallback only. mlx-whisper's decoder
# raises NotImplementedError when beam_size is passed, so the MLX path stays
# greedy and leans on the vocabulary prompt for accuracy.
BEAM_SIZE = int(os.environ.get("AUKORA_VOICE_BEAM_SIZE", "5"))
# Whisper conditions on a prompt, so naming this system's proper nouns is the
# difference between hearing them and inventing near-homophones. Deployment
# varying: the Host passes its own list, this is the fallback.
VOCABULARY = os.environ.get(
    "AUKORA_VOICE_VOCABULARY",
    "Aukora, Auma, AUMLOK, Cordis, KIRA, Aura, Luminara, Lingwa, Zeta Harp, "
    "tesseract, DeepSeek, Nebius, Qwen.",
)

TTS_MAX_TEXT = 400
TTS_QUEUE_MAX = 64
TTS_CHUNK = 2400           # samples per binary frame (100 ms @ 24 kHz)
WIRE_ERROR_MAX = 160
STT_DECODE_TIMEOUT_SEC = 12.0
STT_RECOVERY_FLUSH_SEC = 0.05

STT_POOL = ThreadPoolExecutor(1, thread_name_prefix="stt")
POCKET_POOL = ThreadPoolExecutor(1, thread_name_prefix="pocket-compat")
TTS_POOL = ThreadPoolExecutor(1, thread_name_prefix="tts")        # kokoro (ONNX session is shared + unlocked → keep size 1)

# How long, after the last audio frame we actually pushed to a client, we keep
# the VAD start-bar raised so her own voice can't barge her. A BOUNDED lease
# (never inf): if the client's "she stopped" signal is ever lost, the bar
# self-heals this many seconds later instead of latching the mic half-deaf.
HER_LEASE_SEC = 1.5


# ---------------------------------------------------------------------------
# engines
# ---------------------------------------------------------------------------

class Stt:
    """Pinned faster-whisper tiny.en, Linux CPU only, no registry lookup."""
    kind = "faster-whisper tiny.en CPU int8"
    def __init__(self):
        from faster_whisper import WhisperModel
        self._fw = WhisperModel(os.path.join(MODELS, "whisper-tiny.en"),
            device="cpu", compute_type="int8", cpu_threads=2, num_workers=1,
            local_files_only=True)
    def decode(self, audio):
        segs, _ = self._fw.transcribe(audio, language="en", beam_size=BEAM_SIZE,
            initial_prompt=VOCABULARY, without_timestamps=True,
            condition_on_previous_text=False)
        return clean_text(" ".join(s.text for s in segs))


def clean_text(s: str) -> str:
    """Strip whisper's cut-off-audio artifacts (junk tokens on partials)."""
    s = s.strip()
    for junk in ("//", "♪", "[BLANK_AUDIO]", "[ Silence ]", "(silence)", "[Music]", "(music)"):
        s = s.replace(junk, " ")
    s = " ".join(s.split())
    # a bare run of dots/punctuation is not speech
    if not any(ch.isalnum() for ch in s):
        return ""
    return s


class Vad:
    """Silero VAD v6 (ONNX) — one shared session, per-connection state."""

    def __init__(self):
        import faster_whisper
        import onnxruntime as ort
        path = os.path.join(os.path.dirname(faster_whisper.__file__),
                            "assets", "silero_vad_v6.onnx")
        opts = ort.SessionOptions()
        opts.log_severity_level = 3
        self.sess = ort.InferenceSession(path, opts, providers=["CPUExecutionProvider"])

    def fresh_state(self):
        return {
            "h": np.zeros((1, 1, 128), dtype=np.float32),
            "c": np.zeros((1, 1, 128), dtype=np.float32),
            "ctx": np.zeros(VAD_CTX, dtype=np.float32),
        }

    def step(self, st, frame: np.ndarray) -> float:
        """frame: float32[512] @ 16 kHz → speech probability."""
        inp = np.concatenate([st["ctx"], frame]).reshape(1, VAD_CTX + FRAME)
        out, st["h"], st["c"] = self.sess.run(None, {"input": inp, "h": st["h"], "c": st["c"]})
        st["ctx"] = frame[-VAD_CTX:]
        return float(np.asarray(out).reshape(-1)[0])


class Tts:
    """Kokoro-82M with named 'presences' (pure voices + blends)."""

    def __init__(self):
        from kokoro_onnx import Kokoro
        import onnxruntime as ort
        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 2
        opts.enable_cpu_mem_arena = False
        session = ort.InferenceSession(os.path.join(MODELS, "kokoro-v1.0.int8.onnx"),
            sess_options=opts, providers=["CPUExecutionProvider"])
        self.k = Kokoro.from_session(session, os.path.join(MODELS, "voices-v1.0.bin"))
        style = self.k.get_voice_style
        blend = lambda pairs: sum(style(n) * w for n, w in pairs).astype(np.float32)
        # name → (style, lang, base_speed, label, hint)
        self.presences = {
            "aurora":      (blend([("bf_emma", 0.65), ("af_nicole", 0.35)]), "en-gb", 1.04,
                            "Aurora", "her own blend — British warmth with a breath of static"),
            "emma":        (style("bf_emma"), "en-gb", 1.0, "Emma", "British, warm"),
            "isabella":    (style("bf_isabella"), "en-gb", 1.0, "Isabella", "British, lower"),
            "alice":       (style("bf_alice"), "en-gb", 1.0, "Alice", "British, bright"),
            "continental": (blend([("bf_emma", 0.55), ("ff_siwis", 0.45)]), "en-gb", 1.0,
                            "Continental", "European blend (experimental)"),
            "nicole":      (style("af_nicole"), "en-us", 1.0, "Nicole", "a whisper"),
        }
        self.default = "aurora"

    def voice_list(self):
        # engine tag: kokoro voices are the richer blends but DON'T stream — they
        # synthesize the whole chunk before any audio plays (0.6s floor, seconds
        # under load), so the client can steer live voice to the fast pocket path.
        return [{"id": k, "label": v[3], "hint": v[4], "engine": "kokoro"} for k, v in self.presences.items()]

    def synth(self, text: str, voice: str, speed: float) -> np.ndarray:
        """Blocking — call on TTS_POOL. Returns int16 mono @ 24 kHz."""
        style, lang, base, _, _ = self.presences.get(voice) or self.presences[self.default]
        samples, sr = self.k.create(text, voice=style, speed=base * speed, lang=lang)
        assert sr == SR_OUT
        return (np.clip(samples, -1.0, 1.0) * 32767).astype(np.int16)


# ---------------------------------------------------------------------------
# per-connection duplex session
# ---------------------------------------------------------------------------

class _SocketGone(Exception):
    """Raised inside TTS synthesis when a ws write fails — the connection is gone,
    so the worker should stop (not spin) and let s.close() reap it."""


def _wire_error_message(action, error):
    """Return a bounded diagnostic without exposing engine paths or input text."""
    kind = type(error).__name__.strip()
    message = f"{action} failed"
    if kind:
        message += f" ({kind})"
    return message[:WIRE_ERROR_MAX]


def _restart_voice_process():
    """Replace a process whose single STT worker can no longer make progress."""
    executable = sys.executable
    script = os.path.abspath(__file__)
    try:
        os.execv("/usr/bin/python3", ["/usr/bin/python3", "-I", "-B", os.environ["AUKORA_VOICE_LAUNCHER"], os.environ["AUKORA_VOICE_RUNTIME"], os.environ["AUKORA_VOICE_ENV_SHA256"]])
    except OSError as e:
        print(f"[voice] process recovery failed: {type(e).__name__}", flush=True)
        os._exit(70)


class _NoPocket:
    # Linux has no Pocket engine; retain the injected Session contract.
    VOICES = {}


class Session:
    def __init__(self, ws, engines, loop, *,
                 stt_decode_timeout=STT_DECODE_TIMEOUT_SEC,
                 restart_process=_restart_voice_process):
        self.ws = ws
        self.stt, self.vad, self.tts, self.pocket, self.default_voice = engines
        self.loop = loop
        self.stt_decode_timeout = stt_decode_timeout
        self.restart_process = restart_process
        self.vst = self.vad.fresh_state()
        self.leftover = np.zeros(0, dtype=np.float32)
        self.preroll = deque(maxlen=PREROLL_FRAMES)
        self.utter: list = []
        self.speaking = False
        self.speech_run = 0
        self.silence_run = 0
        self.listen_epoch = 0             # invalidates decodes only when listening state resets
        self.her_until = 0.0              # while now < her_until, VAD bar is raised
        self.tts_q: asyncio.Queue = asyncio.Queue(TTS_QUEUE_MAX)
        self.tts_cancel = 0               # cancellation generation
        self.tts_task = loop.create_task(self._tts_worker())
        self.decode_tasks = set()

    # ---- mic / VAD / STT ----
    # ONE clean path: accumulate speech, and when END_SILENCE_FRAMES of quiet
    # have passed, decode the WHOLE utterance once and send it. No speculation,
    # no partials — the mind only ever sees a complete, real sentence.

    def feed(self, pcm16: bytes):
        audio = np.frombuffer(pcm16, dtype=np.int16).astype(np.float32) / 32768.0
        self.leftover = np.concatenate([self.leftover, audio])
        while len(self.leftover) >= FRAME:
            frame, self.leftover = self.leftover[:FRAME], self.leftover[FRAME:]
            self._frame(frame)

    def _frame(self, frame: np.ndarray):
        prob = self.vad.step(self.vst, frame)
        now = time.monotonic()
        her = now < self.her_until
        # Every frame enters the ring, so the pre-speech window is the true
        # contiguous audio just before the utterance. Appending only while
        # idle spliced stale, non-adjacent frames onto the front of speech.
        self.preroll.append(frame)
        if not self.speaking:
            if prob >= (START_PROB_HER if her else START_PROB):
                self.speech_run += 1
                if self.speech_run >= (MIN_START_FRAMES_HER if her else MIN_START_FRAMES):
                    self.speaking = True
                    self.silence_run = 0
                    self.utter = list(self.preroll)
                    self.send({"t": "vad", "speaking": True})
            elif her:
                # Leaky while her audio is up: consonant dips and AEC ducking
                # cost one frame each instead of the whole run.
                self.speech_run = max(0, self.speech_run - 1)
            else:
                self.speech_run = 0
            return
        # in an utterance
        self.utter.append(frame)
        self.silence_run = self.silence_run + 1 if prob < END_PROB else 0
        too_long = len(self.utter) * FRAME / SR_IN > MAX_UTTER_SEC
        if self.silence_run >= END_SILENCE_FRAMES or too_long:
            self._end_utterance()

    def _end_utterance(self):
        audio = np.concatenate(self.utter) if self.utter else np.zeros(0, dtype=np.float32)
        gap_ms = int(self.silence_run * FRAME / SR_IN * 1000)
        self.speaking = False
        self.speech_run = 0
        self.silence_run = 0
        self.utter = []
        self.send({"t": "vad", "speaking": False})
        dur = len(audio) / SR_IN
        if dur < 0.25:
            return
        listen_epoch = self.listen_epoch
        task = self.loop.create_task(self._decode_final(audio, dur, gap_ms, listen_epoch))
        self.decode_tasks.add(task)
        task.add_done_callback(self.decode_tasks.discard)
        return task

    async def _decode_final(self, audio, dur, gap_ms, listen_epoch):
        t0 = time.monotonic()
        decode = self.loop.run_in_executor(STT_POOL, self.stt.decode, audio)
        try:
            done, _ = await asyncio.wait({decode}, timeout=self.stt_decode_timeout)
            if done:
                text = await decode
            else:
                decode.cancel()
                text = None
        except Exception as e:
            print(f"[voice] stt decode error: {type(e).__name__}", flush=True)
            if listen_epoch == self.listen_epoch:
                await self._write_json({
                    "t": "err",
                    "where": "stt",
                    "msg": _wire_error_message("speech recognition", e),
                })
            return
        if text is None:
            print(f"[voice] stt decode exceeded {self.stt_decode_timeout:.1f}s; "
                  "restarting the local listener", flush=True)
            if listen_epoch == self.listen_epoch:
                await self._write_json({
                    "t": "err",
                    "where": "stt",
                    "msg": "speech recognition timed out; local listener restarting",
                })
            # The WebSocket write is awaited above. One short event-loop turn lets
            # aiohttp flush the bounded diagnostic before exec closes the channel.
            await asyncio.sleep(STT_RECOVERY_FLUSH_SEC)
            self.restart_process()
            return
        print(f"[timing] endpoint={gap_ms}ms stt={int((time.monotonic()-t0)*1000)}ms dur={dur:.2f}s", flush=True)
        if listen_epoch != self.listen_epoch:
            return
        self.send({"t": "final", "text": text, "dur": round(dur, 2)})

    def reset(self):
        self.vst = self.vad.fresh_state()
        self.leftover = np.zeros(0, dtype=np.float32)
        self.preroll.clear()
        self.utter = []
        self.speaking = False
        self.speech_run = 0
        self.silence_run = 0
        self.listen_epoch += 1
        # F1: drop any raised her-bar on reset. The client sends {"t":"reset"} on
        # every channel (re)open, so this makes close→reopen a real recovery from
        # a stuck bar — previously ONLY a full socket reconnect cleared it.
        self.her_until = 0.0

    # ---- TTS ----

    async def say(self, msg):
        # The client increments its own ttsPending for THIS id before sending, and
        # only settles it on a matching tts_end. So every id we accept MUST get a
        # terminal tts_end — even on the drop paths below — or the client's "she is
        # audible" flag (and the sidecar her-bar it drives) never comes back down.
        cid = int(msg.get("id", 0))
        text = str(msg.get("text", ""))[:TTS_MAX_TEXT].strip()
        if not text:
            self.send({"t": "tts_end", "id": cid})
            return
        voice = str(msg.get("voice", "")) or self.default_voice
        # H5: coerce an unknown voice (a stale client pick, a name that no longer
        # exists) to the default rather than KeyError-ing deep in the worker.
        if voice not in getattr(self.pocket, "VOICES", {}) and voice not in self.tts.presences:
            voice = self.default_voice
        # KOKORO ONLY: the first chunk of a turn is split at a word boundary
        # (~30 chars) so the head clears kokoro's ~0.6s per-call floor sooner.
        # Pocket streams from the first frame, so splitting would only hurt it.
        parts = [text]
        if msg.get("first") and voice not in getattr(self.pocket, "VOICES", {}) and len(text) > 45:
            cut = text.rfind(" ", 12, 34)
            if cut < 0:
                cut = text.find(" ", 34)
            if 0 < cut < len(text) - 8:
                parts = [text[:cut], text[cut + 1:]]
        item = (self.tts_cancel, cid, parts, voice, float(msg.get("speed", 1.0)))
        try:
            self.tts_q.put_nowait(item)
        except asyncio.QueueFull:
            if await self._write_json({"t": "err", "where": "tts", "id": cid, "msg": "queue full"}):
                await self._write_json({"t": "tts_end", "id": cid})

    def cancel_tts(self):
        self.tts_cancel += 1
        while not self.tts_q.empty():
            try:
                self.tts_q.get_nowait()
            except asyncio.QueueEmpty:
                break
        self.send({"t": "tts_cancelled"})

    def _bump_her(self):
        # F2 pairing: while audio is actually flowing to the client, keep the
        # her-bar raised so her own voice can't self-barge. It lapses
        # HER_LEASE_SEC after the LAST frame we send — so a long (>8s) kokoro
        # reply never self-barges mid-sentence, and a lost client "off" self-heals.
        self.her_until = max(self.her_until, time.monotonic() + HER_LEASE_SEC)

    async def _tts_worker(self):
        # Bulletproof consumer: NO single item may kill this loop. A dead worker
        # means the queue fills and she goes permanently mute until reconnect —
        # that was a real hard-mute path. Every item that reaches processing emits
        # exactly ONE terminal tts_end (in `finally`) so the client's ttsPending —
        # and the her-bar it drives — always settles back down.
        while True:
            gen, cid, parts, voice, speed = await self.tts_q.get()
            if gen != self.tts_cancel:
                continue  # cancelled before we dequeued it; client already zeroed via tts_cancelled
            try:
                await self._say_one(gen, cid, parts, voice, speed)
            except _SocketGone:
                return  # socket is gone; the connection's finally:s.close() cancels us
            except Exception as e:
                print(f"[voice] tts item error: {type(e).__name__}", flush=True)
                if not await self._write_json({
                    "t": "err",
                    "where": "tts",
                    "id": cid,
                    "msg": _wire_error_message("voice synthesis", e),
                }):
                    return
            # Keep the stream boundary on the same awaited writer as the PCM.
            # WebSocket ordering only helps after writes are issued in order;
            # scheduling begin/end as detached tasks allowed binary frames to
            # overtake their metadata under load.
            if not await self._write_json({"t": "tts_end", "id": cid}):
                return

    async def _say_one(self, gen, cid, parts, voice, speed):
        begun = False
        t0 = time.monotonic()

        if voice in getattr(self.pocket, "VOICES", {}):
            # Preserve streaming error/terminal and cancellation behavior for injected engines.
            q = asyncio.Queue()
            def produce():
                try:
                    for pcm in self.pocket.stream(voice, parts[0], lambda: gen == self.tts_cancel):
                        self.loop.call_soon_threadsafe(q.put_nowait, ("pcm", pcm))
                    self.loop.call_soon_threadsafe(q.put_nowait, ("end", None))
                except Exception as error:
                    self.loop.call_soon_threadsafe(q.put_nowait, ("error", error))
            self.loop.run_in_executor(POCKET_POOL, produce)
            while True:
                event, payload = await q.get()
                if event == "end":
                    break
                if event == "error":
                    raise payload
                if gen != self.tts_cancel:
                    continue
                if not begun:
                    if not await self._write_json({"t": "tts_begin", "id": cid, "sr": SR_OUT}):
                        raise _SocketGone()
                    begun = True
                self._bump_her()
                try:
                    await self.ws.send_bytes(payload.tobytes())
                except Exception:
                    raise _SocketGone()
            return

        # kokoro path (blends / legacy presences)
        for text in parts:
            pcm = await self.loop.run_in_executor(
                TTS_POOL, self.tts.synth, text, voice, max(0.6, min(1.6, speed)))
            if gen != self.tts_cancel:
                break  # cancelled while synthesizing — drop silently
            if not begun:
                print(f"[timing] tts first-audio={int((time.monotonic()-t0)*1000)}ms "
                      f"(kokoro, {len(parts)} part(s), head={len(text)}ch)", flush=True)
                if not await self._write_json({"t": "tts_begin", "id": cid, "sr": SR_OUT}):
                    raise _SocketGone()
                begun = True
            for i in range(0, len(pcm), TTS_CHUNK):
                if gen != self.tts_cancel:
                    break
                self._bump_her()
                try:
                    await self.ws.send_bytes(pcm[i:i + TTS_CHUNK].tobytes())
                except Exception:
                    raise _SocketGone()

    # ---- plumbing ----

    def send(self, obj):
        self.loop.create_task(self._send(obj))

    async def _send(self, obj):
        await self._write_json(obj)

    async def _write_json(self, obj):
        try:
            await self.ws.send_json(obj)
            return True
        except Exception:
            return False

    def close(self):
        for task in self.decode_tasks:
            task.cancel()
        self.tts_task.cancel()


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

def origin_ok(request) -> bool:
    origin = request.headers.get("Origin", "")
    return (not origin) or origin in ALLOWED_ORIGINS


# ---------------------------------------------------------------------------
# lazy engines — LOADED ON FIRST USE, DROPPED AFTER IDLE
# ---------------------------------------------------------------------------
#
# **CONSTRUCTION IS THE LOAD, AND THIS USED TO HAPPEN AT STARTUP.** `Stt.__init__` imports mlx_whisper and resolves
# the model directory; `Tts` and `PocketTts` pull their weights; `Vad` loads the ONNX session. All four ran before
# the sidecar served anything, and the old code then WARMED both TTS engines with a synthetic utterance — so the
# whole set sat in RAM all day whether or not Peter ever opened Auma Live.
#
# The engines are now held HERE and reached through a proxy, so every existing call site keeps working unchanged:
# `stt.transcribe(...)` resolves the engine on the way in. The proxy deliberately holds NO reference to the engine
# — it asks the owner each time — which is what lets the sweeper drop one and have the next call reload it.

VOICE_IDLE_SECONDS = float(os.environ.get("AUMA_VOICE_IDLE_SECONDS") or 600.0)
# How often the sweeper looks. Bounded below so a tiny idle value cannot spin, and above so an idle engine is not
# held far past its deadline.
VOICE_SWEEP_SECONDS = max(1.0, min(30.0, VOICE_IDLE_SECONDS / 4.0))


MODEL_FLOOR = int(os.environ.get("AUMA_VOICE_MEMORY_FLOOR") or 50)
# The SAME floor, read the SAME way, as `scripts/lib/heavy-run-cli.mjs:60` — one policy, two readers (this sidecar is
# Python, so it mirrors the read rather than importing it; the value and the refusal name are what must agree).


def memory_level():
    """Available fraction of host AND cgroup memory; unreadable stays refused."""
    try:
        values = {}
        with open("/proc/meminfo") as stream:
            for line in stream:
                key, value = line.split(":", 1)
                values[key] = int(value.strip().split()[0]) * 1024
        fractions = [100 * values["MemAvailable"] // values["MemTotal"]]
        for limit_path, used_path in [
            ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"),
            ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.usage_in_bytes")]:
            if os.path.isfile(limit_path):
                with open(limit_path) as f: limit = f.read().strip()
                if limit != "max":
                    with open(used_path) as f: used = int(f.read())
                    limit = int(limit)
                    if limit > 0: fractions.append(max(0,100 * (limit-used)//limit))
        return min(fractions)
    except (OSError, ValueError, KeyError):
        return None


class LazyEngines:
    """Holds engines that are built on first use and dropped once idle.

    Every load and unload prints a NAMED line, because the point of the exercise is that Peter can watch the RAM
    come back — and a limit that does not print did not happen.
    """

    def __init__(self, idle_seconds=VOICE_IDLE_SECONDS, clock=time.monotonic, log=print,
                 level=memory_level, floor=MODEL_FLOOR):
        self.idle_seconds = idle_seconds
        self._clock = clock
        self._log = log
        self._level = level
        self._floor = floor
        self.refusals = 0
        self._live = {}          # name -> (engine, last_used_monotonic)
        self.loads = 0
        self.unloads = 0

    def get(self, name, factory):
        """The engine, loading it if it is not live. Every call counts as a use."""
        entry = self._live.get(name)
        if entry is None:
            # THE FLOOR IS CHECKED AT THE MOMENT OF LOAD, not at boot: construction is the load, and every engine here
            # is heavy. The refusal is NAMED, so a lane reading the log knows which floor refused what.
            level = self._level()
            # **FAIL CLOSED.** An unreadable level is NOT permission: a gate that opens when its instrument is broken
            # opens under exactly the conditions it exists for. `AUMA_VOICE_MEMORY_FLOOR=0` is the deliberate way to
            # disable this (the sidecar is macOS-only anyway, where sysctl is always present).
            if level is None:
                self.refusals += 1
                raise MemoryError(f"memory-level-unreadable: Linux host/cgroup available memory could not be read, so loading "
                                  f"'{name}' cannot be shown to be safe — nothing was loaded")
            if level < self._floor:
                self.refusals += 1
                raise MemoryError(f"memory-below-model-floor: Linux available memory percent is {level} and loading "
                                  f"'{name}' needs {self._floor} — nothing was loaded")
            t0 = time.time()
            engine = factory()
            self._live[name] = [engine, self._clock()]
            self.loads += 1
            self._log(f"[voice-engine] LOAD {name} in {time.time() - t0:.1f}s "
                      f"(idle-unload in {self.idle_seconds:.0f}s)")
            return engine
        entry[1] = self._clock()
        return entry[0]

    def sweep(self):
        """Drop every engine idle past the deadline — and ALL of them while the floor is not met.

        **THE WATCHDOG: A LOAD-TIME FLOOR IS NOT ENOUGH.** A resident model can be sitting there when the machine fills
        up, and the next load is not the problem — the memory already held is. So while the level is KNOWN to be below
        the floor, the sweeper releases everything it holds and says so.
        """
        now = self._clock()
        dropped = []
        level = self._level()
        if level is not None and level < self._floor:
            for name in list(self._live):
                del self._live[name]
                self.unloads += 1
                dropped.append(name)
            if dropped:
                self._log(f"[voice-engine] WATCHDOG level {level} < {self._floor}: dropped {', '.join(sorted(dropped))}")
            return dropped
        for name, entry in list(self._live.items()):
            idle = now - entry[1]
            if idle >= self.idle_seconds:
                del self._live[name]
                self.unloads += 1
                dropped.append(name)
                self._log(f"[voice-engine] UNLOAD {name} after {idle:.0f}s idle")
        return dropped

    def live(self):
        """The names currently resident."""
        return sorted(self._live)

    async def sweeper(self, interval=None):
        """Drop idle engines forever. Cancelled when the sidecar stops."""
        every = VOICE_SWEEP_SECONDS if interval is None else interval
        while True:
            await asyncio.sleep(every)
            try:
                self.sweep()
            except Exception as error:            # a sweeper that dies stops reclaiming memory silently
                self._log(f"[voice-engine] sweep failed: {type(error).__name__}")


class _EngineProxy:
    """Forwards to a live engine, loading it on the way in. Holds no reference of its own."""

    __slots__ = ("_owner", "_name", "_factory")

    def __init__(self, owner, name, factory):
        self._owner = owner
        self._name = name
        self._factory = factory

    def __getattr__(self, attribute):
        return getattr(self._owner.get(self._name, self._factory), attribute)

    def __repr__(self):
        return f"<engine {self._name} live={self._name in self._owner.live()}>"


async def main():
    from aiohttp import WSMsgType, web

    t0 = time.time()
    # **NOTHING IS LOADED HERE.** These four are proxies; the engines appear on first use and leave when idle.
    print("[voice] engines are lazy — nothing loads until the first open or voice use", flush=True)
    engines = LazyEngines()
    stt = _EngineProxy(engines, "stt", Stt)
    vad = _EngineProxy(engines, "vad", Vad)
    tts = _EngineProxy(engines, "tts", Tts)
    asyncio.create_task(engines.sweeper())
    # **`PocketTts.VOICES` IS READ OFF THE CLASS, NOT THE PROXY.** Touching the proxy here would construct the
    # engine during startup — reinstating exactly the load this change removes, and doing it invisibly.
    default_voice = "aurora"
    # **THE WARM-UP IS GONE, AND IT WAS THE LARGEST COST.** Two synthetic utterances pulled BOTH TTS engines and
    # their weights into RAM before the sidecar served anything. The first real turn now pays that instead — once,
    # on the path that actually needed it — and the idle sweeper gives the memory back afterwards.
    print(f"[voice] ready in {time.time() - t0:.1f}s — engines load on first use, "
          f"idle-unload {VOICE_IDLE_SECONDS:.0f}s, default={default_voice}", flush=True)
    def voice_list():
        return tts.voice_list()

    started = time.time()

    async def health(request):
        if not origin_ok(request):
            return web.json_response({"error": "origin"}, status=403)
        return web.json_response({
            "ok": True,
            "organ": "voice-sidecar",
            "authority": "none — rendering and hearing only; model dispatch stays in the Aukora UI host",
            "engines": {"stt": Stt.kind, "tts": "kokoro-82M CPU int8", "vad": "silero-vad v6 (onnx)"},
            "voices": [],
            "default_voice": default_voice,
            "uptimeSec": round(time.time() - started, 1),
            "egress": "offline by configuration, not measured — 127.0.0.1 only, all models local files",
        })

    async def ws_handler(request):
        if not origin_ok(request):
            return web.Response(status=403, text="origin not allowed")
        ws = web.WebSocketResponse(max_msg_size=2 ** 22, heartbeat=30)
        await ws.prepare(request)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(STT_POOL, lambda: (stt.kind, vad.fresh_state()))
            await loop.run_in_executor(TTS_POOL, lambda: tts.default)
        except Exception as error:
            await ws.send_json({"t": "err", "where": "startup", "msg": _wire_error_message("voice engines", error)})
            await ws.close(code=1011, message=b"voice engines unavailable")
            return ws
        s = Session(ws, (stt, vad, tts, _NoPocket(), default_voice), loop)
        await ws.send_json({
            "t": "ready",
            "engines": {"stt": Stt.kind, "tts": "kokoro-82M CPU int8", "vad": "silero-v6"},
            "voices": voice_list(),
            "default_voice": default_voice,
            "sr_in": SR_IN, "sr_out": SR_OUT,
        })
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    s.feed(msg.data)
                elif msg.type == WSMsgType.TEXT:
                    try:
                        m = json.loads(msg.data)
                    except Exception:
                        continue
                    t = m.get("t")
                    if t == "tts":
                        await s.say(m)
                    elif t == "tts_cancel":
                        s.cancel_tts()
                    elif t == "her":
                        # F2: NEVER latch to inf. "on" grants a bounded lease that the
                        # TTS worker refreshes per audio frame while she's actually
                        # speaking; if the client's "off" is ever lost (tab backgrounded
                        # mid-playback, socket hiccup), the bar self-heals in ~HER_LEASE_SEC.
                        s.her_until = (time.monotonic() + HER_LEASE_SEC) if m.get("on") else time.monotonic() + 0.3
                    elif t == "reset":
                        s.reset()
                elif msg.type == WSMsgType.ERROR:
                    break
        finally:
            s.close()
        return ws

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_get("/ws", ws_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, PORT)
    # H1: the restart-flap fix. On a pm2 restart the previous process may still
    # hold the listen socket for a beat — bind used to raise Errno 48 and pm2
    # crash-looped. Retry with backoff instead of dying, so a restart is clean.
    for attempt in range(20):
        try:
            await site.start()
            break
        except OSError as e:
            if getattr(e, "errno", None) in (48, 98) and attempt < 19:
                print(f"[voice] port {PORT} busy, waiting for the old process to release "
                      f"({attempt + 1}/20)…", flush=True)
                await asyncio.sleep(0.5)
                continue
            raise
    print(f"aukora voice sidecar — local duplex organ at http://{HOST}:{PORT} "
          f"(no authority; egress is OFFLINE BY CONFIGURATION, NOT MEASURED, and model dispatch stays in the Aukora UI host)", flush=True)

    # H1: graceful shutdown. Catch SIGTERM/SIGINT (pm2 sends SIGINT then SIGKILL),
    # cleanly tear down the aiohttp runner so the socket is RELEASED before the
    # replacement process binds, and stop the thread pools. No more Errno 48.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - non-posix
            pass
    try:
        await stop.wait()
    finally:
        print("[voice] shutting down — releasing socket + pools", flush=True)
        await runner.cleanup()
        STT_POOL.shutdown(wait=False)
        TTS_POOL.shutdown(wait=False)
        POCKET_POOL.shutdown(wait=False)


if __name__ == "__main__":
    try:
        if "--probe" in sys.argv:
            v = Vad(); probability = v.step(v.fresh_state(), np.zeros(FRAME, dtype=np.float32))
            text = Stt().decode(np.zeros(SR_IN, dtype=np.float32))
            pcm = Tts().synth("Ready.", "aurora", 1.0)
            assert 0 <= probability <= 1 and pcm.dtype == np.int16 and len(pcm) > 0
            print(json.dumps({"vad": "ok", "stt": "ok", "tts": "ok", "pcm_samples": len(pcm)}))
        else:
            asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
