import pytest

from wildburrow import plugins
from wildburrow.config import PREFIX, ConfigError
from wildburrow.transports.ssh import SSHTransport


def test_builtin_plugins_are_registered() -> None:
    assert set(plugins.available("transport")) >= {"ssh"}
    assert set(plugins.available("auth")) >= {"key", "password"}


def test_settings_are_read_from_the_plugin_prefix() -> None:
    transport = plugins.load("transport", "ssh", {f"{PREFIX}SSH_PORT": "2200"})
    assert isinstance(transport, SSHTransport)
    assert transport.settings.port == 2200


def test_unknown_plugin_lists_installed_ones() -> None:
    installed = ", ".join(sorted(plugins.available("auth")))
    with pytest.raises(ConfigError, match=f"unknown auth plugin 'oidc'; installed: {installed}$"):
        plugins.load("auth", "oidc", {})


def test_missing_plugin_setting_names_the_variable() -> None:
    with pytest.raises(ConfigError) as error:
        plugins.load("auth", "password", {})
    assert str(error.value) == f"missing required setting(s): {PREFIX}AUTH_PASSWORD_HASH"


def test_plugin_errors_name_the_plugin() -> None:
    with pytest.raises(ConfigError, match=r"^auth plugin 'key': authorized_keys: no keys found$"):
        plugins.load("auth", "key", {f"{PREFIX}AUTH_KEY_AUTHORIZED_KEYS": "# nothing"})


def test_an_empty_kind_says_none_are_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugins, "entry_points", lambda group: [])
    with pytest.raises(ConfigError, match=r"^unknown dns plugin 'x'; installed: none$"):
        plugins.load("dns", "x", {})
