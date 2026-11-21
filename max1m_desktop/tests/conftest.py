import os
import sys
import types

os.environ["QT_QPA_PLATFORM"] = "offscreen"

# Delivery tests do not access audio devices or create the WebRTC event loop.
sys.modules.setdefault("pyaudio", types.ModuleType("pyaudio"))
rtc_stub = types.ModuleType("app.webrtc_manager")
rtc_stub.rtc = types.SimpleNamespace()
rtc_stub.SCREEN_QUALITY_PRESETS = {}
sys.modules["app.webrtc_manager"] = rtc_stub
