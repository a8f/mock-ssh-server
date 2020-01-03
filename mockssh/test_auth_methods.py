import codecs
import platform

from os.path import join
from pytest import raises


def test_ssh_password(password_server):
    for uid in password_server.users:
        with password_server.client(uid) as c:
            _, stdout, _ = c.exec_command("ls /")
            assert "etc" in (codecs.decode(bit, "utf8")
                             for bit in stdout.read().split())

            _, stdout, _ = c.exec_command("hostname")
            assert (codecs.decode(stdout.read().strip(), "utf8") ==
                    platform.node())


def test_ssh_keyfile(server):
    for uid in server.users:
        with server.client(uid) as c:
            _, stdout, _ = c.exec_command("ls /")
            assert "etc" in (codecs.decode(bit, "utf8")
                             for bit in stdout.read().split())

            _, stdout, _ = c.exec_command("hostname")
            assert (codecs.decode(stdout.read().strip(), "utf8") ==
                    platform.node())


def test_ssh_mixed(mixed_server):
    assert mixed_server._users["key-user"][0] is not None
    assert mixed_server._users["password-user"][0] is None
    for uid in mixed_server.users:
        with mixed_server.client(uid) as c:
            _, stdout, _ = c.exec_command("ls /")
            assert "etc" in (codecs.decode(bit, "utf8")
                             for bit in stdout.read().split())

            _, stdout, _ = c.exec_command("hostname")
            assert (codecs.decode(stdout.read().strip(), "utf8") ==
                    platform.node())


def test_ssh_auto(auto_server):
    assert auto_server._users["key-user"][0] is not None
    assert auto_server._users["password-user"][0] is None
    assert auto_server._users["password-like-key-user"][0] is None
    for uid in auto_server.users:
        with auto_server.client(uid) as c:
            _, stdout, _ = c.exec_command("ls /")
            assert "etc" in (codecs.decode(bit, "utf8")
                             for bit in stdout.read().split())

            _, stdout, _ = c.exec_command("hostname")
            assert (codecs.decode(stdout.read().strip(), "utf8") ==
                    platform.node())


def test_add_user_password(server):
    with raises(KeyError):
        server.client("new-user")

    server.add_user("new-user", "password", keytype="password")
    with server.client("new-user") as c:
        _, stdout, _ = c.exec_command("echo 42")
        assert codecs.decode(stdout.read().strip(), "utf8") == "42"


def test_add_user_keyfile(server, user_key_path):
    with raises(KeyError):
        server.client("new-user")

    server.add_user("new-user", user_key_path)
    with server.client("new-user") as c:
        _, stdout, _ = c.exec_command("echo 42")
        assert codecs.decode(stdout.read().strip(), "utf8") == "42"


def test_add_user_auto_keyfile(custom_server, user_key_path):
    with raises(KeyError):
        custom_server.client("new-user")

    custom_server.add_user("new-user", user_key_path, keytype="autopass")
    with custom_server.client("new-user") as c:
        _, stdout, _ = c.exec_command("echo 42")
        assert codecs.decode(stdout.read().strip(), "utf8") == "42"


def test_add_user_auto_password(custom_server):
    with raises(KeyError):
        custom_server.client("new-user")

    custom_server.add_user("new-user", "password", keytype="autopass")
    with custom_server.client("new-user") as c:
        _, stdout, _ = c.exec_command("echo 42")
        assert codecs.decode(stdout.read().strip(), "utf8") == "42"


def test_add_user_auto_password_like_keyfile(custom_server):
    with raises(KeyError):
        custom_server.client("new-user")

    custom_server.add_user("new-user", join("not", "real", "file"),
                           keytype="autopass")
    with custom_server.client("new-user") as c:
        _, stdout, _ = c.exec_command("echo 42")
        assert codecs.decode(stdout.read().strip(), "utf8") == "42"
