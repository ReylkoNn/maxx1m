import pytest
from app.ice_config import filter_relay_sdp, ice_relay_only, ice_server_settings


def test_default_and_configured_turn():
    assert len(ice_server_settings({})) == 2
    config = ice_server_settings({
        "MAX1M_STUN_URLS": "stun:example.test:3478",
        "MAX1M_TURN_URL": "turns:turn.example.test:5349?transport=tcp",
        "MAX1M_TURN_USERNAME": "user",
        "MAX1M_TURN_PASSWORD": "secret",
    })
    assert config[0] == {"urls": ["stun:example.test:3478"]}
    assert config[1]["urls"] == ["turns:turn.example.test:5349?transport=tcp"]
    assert config[1]["credential"] == "secret"


def test_multi_url_turn_and_strict_scheme_validation():
    config = ice_server_settings({
        "MAX1M_STUN_URLS": "",
        "MAX1M_TURN_URLS": "turn:turn.example.test:3478?transport=udp, turn:turn.example.test:3478?transport=tcp, turns:turn.example.test:5349",
        "MAX1M_TURN_USERNAME": "u",
        "MAX1M_TURN_PASSWORD": "p",
    })
    assert config == [{
        "urls": [
            "turn:turn.example.test:3478?transport=udp",
            "turn:turn.example.test:3478?transport=tcp",
            "turns:turn.example.test:5349",
        ],
        "username": "u",
        "credential": "p",
    }]
    # aiortc silently ignores stuns: and turns:...?transport=udp — reject fail-closed.
    with pytest.raises(ValueError):
        ice_server_settings({"MAX1M_STUN_URLS": "stuns:stun.example.test:5349"})
    with pytest.raises(ValueError):
        ice_server_settings({
            "MAX1M_TURN_URL": "turns:turn.example.test:5349?transport=udp",
            "MAX1M_TURN_USERNAME": "u",
            "MAX1M_TURN_PASSWORD": "p",
        })
    with pytest.raises(ValueError):
        ice_server_settings({"MAX1M_STUN_URLS": "stun:example.test:70000"})


def test_bad_turn_fails_closed_without_credentials_in_error():
    with pytest.raises(ValueError) as error:
        ice_server_settings({"MAX1M_TURN_URL": "https://example.test", "MAX1M_TURN_PASSWORD": "super-secret"})
    assert "super-secret" not in str(error.value)
    with pytest.raises(ValueError):
        ice_server_settings({"MAX1M_TURN_URL": "turn:host"})


def test_can_disable_default_stun():
    assert ice_server_settings({"MAX1M_STUN_URLS": ""}) == []


def test_relay_only_requires_turn_and_omits_stun():
    assert ice_relay_only({}) is False
    assert ice_relay_only({"MAX1M_ICE_RELAY_ONLY": "true"}) is True
    with pytest.raises(ValueError):
        ice_relay_only({"MAX1M_ICE_RELAY_ONLY": "maybe"})
    with pytest.raises(ValueError):
        ice_server_settings({"MAX1M_ICE_RELAY_ONLY": "1"})
    servers = ice_server_settings({
        "MAX1M_ICE_RELAY_ONLY": "1",
        "MAX1M_TURN_URL": "turn:127.0.0.1:3478?transport=udp",
        "MAX1M_TURN_USERNAME": "alice",
        "MAX1M_TURN_PASSWORD": "secret",
    })
    assert servers == [{
        "urls": ["turn:127.0.0.1:3478?transport=udp"],
        "username": "alice",
        "credential": "secret",
    }]


def test_filter_relay_sdp_removes_non_relay_candidates():
    sdp = (
        "v=0\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
        "a=candidate:1 1 udp 2122260223 192.0.2.10 50000 typ host\r\n"
        "a=candidate:2 1 udp 1686052607 198.51.100.5 50001 typ srflx raddr 192.0.2.10 rport 50000\r\n"
        "a=candidate:3 1 udp 41885439 203.0.113.9 61000 typ relay raddr 0.0.0.0 rport 0\r\n"
        "a=end-of-candidates\r\n"
    )
    filtered = filter_relay_sdp(sdp)
    assert "typ host" not in filtered
    assert "typ srflx" not in filtered
    assert "typ relay" in filtered
    assert "m=audio" in filtered
