import codecs
import platform
import subprocess
import tempfile

from pytest import raises


def test_ssh_session(server):
    for uid in server.users:
        with server.client(uid) as c:
            _, stdout, _ = c.exec_command("ls /")
            assert "etc" in (codecs.decode(bit, "utf8")
                             for bit in stdout.read().split())

            _, stdout, _ = c.exec_command("hostname")
            assert (codecs.decode(stdout.read().strip(), "utf8") ==
                    platform.node())


def test_ssh_failed_commands(server):
    for uid in server.users:
        with server.client(uid) as c:
            _, _, stderr = c.exec_command("rm /")
            stderr = codecs.decode(stderr.read(), "utf8")
            assert (stderr.startswith("rm: cannot remove") or
                    stderr.startswith("rm: /: is a directory"))


def test_multiple_connections1(server):
    _test_multiple_connections(server)


def test_multiple_connections2(server):
    _test_multiple_connections(server)


def test_multiple_connections3(server):
    _test_multiple_connections(server)


def test_multiple_connections4(server):
    _test_multiple_connections(server)


def test_multiple_connections5(server):
    _test_multiple_connections(server)


def _test_multiple_connections(server):
    # This test will deadlock without ea1e0f80aac7253d2d346732eefd204c6627f4c8
    fd, pkey_path = tempfile.mkstemp()
    user, (key_file, private_key) = list(server._users.items())[0]
    with open(pkey_path, "w") as pkfile:
        with open(key_file, "r") as kfile:
            pkfile.write(kfile.read())
    ssh_command = 'ssh -oStrictHostKeyChecking=no '
    ssh_command += "-i %s -p %s %s@localhost " % (pkey_path, server.port, user)
    ssh_command += 'echo hello'
    p = subprocess.check_output(ssh_command, shell=True)
    assert p.decode('utf-8').strip() == 'hello'


def test_invalid_user(server):
    with raises(KeyError) as exc:
        server.client("unknown-user")
    assert exc.value.args[0] == "unknown-user"


def test_add_user(server, user_key_path):
    with raises(KeyError):
        server.client("new-user")

    server.add_user("new-user", user_key_path)
    with server.client("new-user") as c:
        _, stdout, _ = c.exec_command("echo 42")
        assert codecs.decode(stdout.read().strip(), "utf8") == "42"
