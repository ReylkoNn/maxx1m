"""Standalone WebRTC sender/receiver probe (no microphone, no server).

Run with the same interpreter that launches the client, e.g.:

    I:\\.m1b\\dv\\Scripts\\python max1m_desktop\\diagnose_webrtc.py

It checks, in order:
  1. the libopus encoder inside PyAV actually encodes a frame;
  2. two real VoicePeerSession objects connect over loopback ICE and
     exchange non-silent audio, verifying RTP packet counters grow.

Exit code 0 = the aiortc/av stack on this machine can send and receive
voice; 1 = the stack itself is broken (see the FAIL lines).
"""

import asyncio
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

LOUD_PCM = b"".join(
    struct.pack("<h", 10000 if i % 2 == 0 else -10000) for i in range(960)
)


class _StubAudioIO:
    """Synthetic microphone (constant loud tone) + recording speaker."""

    remote_volume = 1.0

    def __init__(self):
        self.written = []

    def read(self):
        return LOUD_PCM

    def write(self, pcm):
        self.written.append(pcm)


def _peak(frames) -> int:
    peak = 0
    for frame in frames:
        for i in range(0, len(frame) - 1, 2):
            value = abs(int.from_bytes(frame[i : i + 2], "little", signed=True))
            if value > peak:
                peak = value
    return peak


def _check_opus_encoder() -> bool:
    print("[1/2] libopus encoder ...", flush=True)
    try:
        import av

        ctx = av.CodecContext.create("libopus", "w")
        ctx.sample_rate = 48000
        ctx.layout = "mono"
        ctx.format = "s16"
        frame = av.AudioFrame(format="s16", layout="mono", samples=960)
        frame.sample_rate = 48000
        frame.planes[0].update(LOUD_PCM)
        packets = ctx.encode(frame)
        print(f"      OK (av={av.__version__}, encoded {len(packets)} packet(s))")
        return True
    except Exception as exc:  # noqa: BLE001 - diagnostic must report anything
        print(f"      FAIL: {type(exc).__name__}: {exc}")
        return False


async def _run_loopback() -> bool:
    print("[2/2] two-session loopback (host ICE, synthetic tone) ...", flush=True)
    from app.webrtc_manager import VoicePeerSession

    alice_io, bob_io = _StubAudioIO(), _StubAudioIO()
    holders = {}

    def _make(name, io):
        def on_ice(pid, candidate, channel):
            other = holders.get("bob" if name == "alice" else "alice")
            if other is not None:
                asyncio.ensure_future(other.add_ice(candidate))

        return VoicePeerSession(f"probe-{name}", io, on_ice, None, ice_servers=[])

    alice = _make("alice", alice_io)
    bob = _make("bob", bob_io)
    holders["alice"], holders["bob"] = alice, bob
    alice.call_id = bob.call_id = "diagnose-call"
    try:
        await alice.create()
        await bob.create()
        offer = await alice.create_offer()
        answer = await bob.handle_offer(offer)
        await alice.handle_answer(answer)
        await asyncio.sleep(6.0)

        ok = True
        for name, session, io in (("alice", alice, alice_io), ("bob", bob, bob_io)):
            report = await session.pc.getStats()
            summary = {}
            for stat in report.values():
                if stat.type == "inbound-rtp":
                    summary["in_packets"] = stat.packetsReceived
                elif stat.type == "outbound-rtp":
                    summary["out_packets"] = stat.packetsSent
            heard = _peak(io.written)
            print(
                f"      {name}: state={session.pc.connectionState} "
                f"stats={summary} heard_frames={len(io.written)} heard_peak={heard}"
            )
            if summary.get("out_packets", 0) <= 0:
                print(f"      FAIL: {name} sent zero RTP packets")
                ok = False
            if heard <= 0:
                print(f"      FAIL: {name} received only silence")
                ok = False
        return ok
    except Exception as exc:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        print(f"      FAIL: {type(exc).__name__}: {exc}")
        return False
    finally:
        await alice.close()
        await bob.close()


def main() -> int:
    try:
        import aiortc

        print(f"aiortc module: {aiortc.__file__}")
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: aiortc does not import: {type(exc).__name__}: {exc}")
        return 1
    ok = _check_opus_encoder()
    ok = asyncio.run(_run_loopback()) and ok
    print("RESULT:", "OK - WebRTC stack can send and receive voice" if ok else "FAIL - WebRTC stack is broken on this machine")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
