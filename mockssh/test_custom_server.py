import codecs
import platform
import subprocess
import tempfile

from .conftest import CUSTOM_HOST, CUSTOM_PORT
from pytest import raises


def test_correct_properties(custom_server):
    assert custom_server.port == CUSTOM_PORT
    assert custom_server.host == CUSTOM_HOST


def test_ssh_session(custom_server):
    for uid in custom_server.users:
        with custom_server.client(uid) as c:
            _, stdout, _ = c.exec_command("ls /")
            assert "etc" in (codecs.decode(bit, "utf8")
                             for bit in stdout.read().split())

            _, stdout, _ = c.exec_command("hostname")
            assert (codecs.decode(stdout.read().strip(), "utf8") ==
                    platform.node())


def test_ssh_failed_commands(custom_server):
    for uid in custom_server.users:
        with custom_server.client(uid) as c:
            _, _, stderr = c.exec_command("rm /")
            stderr = codecs.decode(stderr.read(), "utf8")
            assert (stderr.startswith("rm: cannot remove") or
                    stderr.startswith("rm: /: is a directory"))


def test_multiple_connections1(custom_server):
    _test_multiple_connections(custom_server)


def test_multiple_connections2(custom_server):
    _test_multiple_connections(custom_server)


def test_multiple_connections3(custom_server):
    _test_multiple_connections(custom_server)


def test_multiple_connections4(custom_server):
    _test_multiple_connections(custom_server)


def test_multiple_connections5(custom_server):
    _test_multiple_connections(custom_server)


def _test_multiple_connections(custom_server):
    # This test will deadlock without ea1e0f80aac7253d2d346732eefd204c6627f4c8
    fd, pkey_path = tempfile.mkstemp()
    user, (key_file, private_key) = list(custom_server._users.items())[0]
    with open(pkey_path, "w") as pkfile:
        with open(key_file, "r") as kfile:
            pkfile.write(kfile.read())
    ssh_command = 'ssh -oStrictHostKeyChecking=no '
    ssh_command += "-i %s -p %s %s@localhost " % (pkey_path, custom_server.port, user)
    ssh_command += 'echo hello'
    p = subprocess.check_output(ssh_command, shell=True)
    assert p.decode('utf-8').strip() == 'hello'


def test_invalid_user(custom_server):
    with raises(KeyError) as exc:
        custom_server.client("unknown-user")
    assert exc.value.args[0] == "unknown-user"


def test_add_user(custom_server, user_key_path):
    with raises(KeyError):
        custom_server.client("new-user")

    custom_server.add_user("new-user", user_key_path)
    with custom_server.client("new-user") as c:
        _, stdout, _ = c.exec_command("echo 42")
        assert codecs.decode(stdout.read().strip(), "utf8") == "42"
