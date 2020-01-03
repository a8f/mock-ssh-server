import logging
import errno
import os
import select
import socket
import subprocess
import threading

try:
    from queue import Queue
except ImportError:  # Python 2.7
    from Queue import Queue

import paramiko

from mockssh import sftp

__all__ = [
    "Server",
]

SERVER_KEY_PATH = os.path.join(os.path.dirname(__file__), "server-key")


class Handler(paramiko.ServerInterface):
    log = logging.getLogger(__name__)

    def __init__(self, server, client_conn):
        self.server = server
        self.thread = None
        self.command_queues = {}
        client, _ = client_conn
        self.transport = t = paramiko.Transport(client)
        t.add_server_key(paramiko.RSAKey(filename=SERVER_KEY_PATH))
        t.set_subsystem_handler("sftp", sftp.SFTPServer)

    def run(self):
        self.transport.start_server(server=self)
        while True:
            channel = self.transport.accept()
            if channel is None:
                break
            if channel.chanid not in self.command_queues:
                self.command_queues[channel.chanid] = Queue()
            t = threading.Thread(target=self.handle_client, args=(channel,))
            t.setDaemon(True)
            t.start()

    def handle_client(self, channel):
        try:
            command = self.command_queues[channel.chanid].get(block=True)
            self.log.debug("Executing %s", command)
            p = subprocess.Popen(command, shell=True,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            channel.sendall(stdout)
            channel.sendall_stderr(stderr)
            channel.send_exit_status(p.returncode)
        except Exception:
            self.log.error("Error handling client (channel: %s)", channel,
                           exc_info=True)
        finally:
            channel.close()

    def check_auth_publickey(self, username, key):
        try:
            key_path, known_public_key = self.server._users[username]
            if key_path is None:
                raise ValueError("Tried to use a key to authorize user " +
                                 username + " who uses a plaintext password")
        except KeyError:
            self.log.debug("Unknown user '%s'", username)
            return paramiko.AUTH_FAILED
        if known_public_key == key:
            self.log.debug("Accepting public key for user '%s'", username)
            return paramiko.AUTH_SUCCESSFUL
        self.log.debug("Rejecting public ley for user '%s'", username)
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        try:
            none, saved_password = self.server._users[username]
            if none is not None:
                raise ValueError("Tried to use a password to authorize user " +
                                 username + " who uses a key file")
            if password == saved_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        except KeyError:
            self.log.debug("Unknown user '%s'", username)
            return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        self.command_queues.setdefault(channel.get_id(), Queue()).put(command)
        return True

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "publickey,password"


class Server(object):

    log = logging.getLogger(__name__)

    def __init__(self, users, host="127.0.0.1", port=0, auth="auto"):
        """
        auth: how to authenticate users from users.
                   One of: - "key" to handle users as uid -> private key path
                           - "password" to handle users as uid -> password
                           - "mixed" to handle users as
                               uid -> (auth_type, password/key path)
                           - "auto" to handle users as uid -> s where s is
                               assumed to be a path if it is a file we can open
                               or a plaintext password otherwise
        """
        self._host = host
        self._port = port
        self._socket = None
        self._thread = None
        self._users = {}
        if auth == "auto":
            for uid, password_or_key_path in users.items():
                self.add_user(uid, password_or_key_path, keytype="autopass")
        elif auth == "key":
            for uid, key_path in users.items():
                self.add_user(uid, key_path, keytype="auto")
        elif auth == "password":
            for uid, password in users.items():
                self.add_user(uid, password, keytype="password")
        elif auth == "mixed":
            for uid, (auth_type, password_or_key_path) in users.items():
                if auth_type == "auto":
                    self.add_user(uid, password_or_key_path, keytype="autopass")
                elif auth_type == "key":
                    self.add_user(uid, password_or_key_path, keytype="auto")
                elif auth_type == "password":
                    self.add_user(uid, password_or_key_path, keytype="password")
                else:
                    raise ValueError("Invalid auth_type " + auth_type)
        else:
            raise ValueError("Invalid auth_type " + auth_type)

    def add_user(self, uid, password_or_key_path, keytype="autopass"):
        """
        keytype: type of key to use or
                 "auto" to detect from the file or
                 "autopass" to detect from the file or if the file can't be
                            read then treat key as a password
        """
        if keytype == "auto" or keytype == "autopass":
            try:
                with open(password_or_key_path, "r") as file:
                    line = file.readline().rstrip()
                if line.strip() == "-----BEGIN RSA PRIVATE KEY-----":
                    keytype = "ssh-rsa"
                elif line.strip() == "-----BEGIN DSA PRIVATE KEY-----":
                    keytype = "ssh-dss"
                elif line.strip() == "-----BEGIN EC PRIVATE KEY-----":
                    keytype = "ssh-ecdsa"
                else:
                    try:
                        if line.split(" ")[0] == "ssh-ed25519":
                            keytype = "ssh-ed25519"
                        else:
                            raise IndexError()
                    except IndexError:
                        raise ValueError(password_or_key_path +
                                         " is not a valid supported private key file")
            except EnvironmentError as e:
                # We really only want to except FileNotFoundError and PermissionError
                # but Python2 doesn't have those, so instead except EnvironmentError
                # and if the error code isn't ENOENT (FileNotFoundError) or
                # EPERM (PermissionError) then raise the error
                if e.errno != errno.ENOENT and e.errno != errno.EPERM:
                    raise e
                if keytype == "autopass":
                    keytype = "password"
                else:
                    raise e

        if keytype == "ssh-rsa":
            key = paramiko.RSAKey.from_private_key_file(password_or_key_path)
        elif keytype == "ssh-dss":
            key = paramiko.DSSKey.from_private_key_file(password_or_key_path)
        elif keytype == "ssh-ecdsa":
            key = paramiko.ECDSAKey.from_private_key_file(password_or_key_path)
        elif keytype == "ssh-ed25519":
            key = paramiko.Ed25519Key.from_private_key_file(password_or_key_path)
        elif keytype == "password":
            key = password_or_key_path
        else:
            raise ValueError("Unable to handle key of type {}".format(keytype))

        self._users[uid] = (None if keytype == "password" else password_or_key_path,
                            key)

    def __enter__(self):
        self._socket = s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, self.port))
        except PermissionError as e:
            if self.port < 1024:
                e.strerror += " (unprivileged users can only use port numbers >= 1024)"
            raise e
        s.listen(5)
        self._thread = t = threading.Thread(target=self._run)
        t.setDaemon(True)
        t.start()
        return self

    def _run(self):
        sock = self._socket
        while sock.fileno() > 0:
            self.log.debug("Waiting for incoming connections ...")
            rlist, _, _ = select.select([sock], [], [], 1.0)
            if rlist:
                conn, addr = sock.accept()
                self.log.debug("... got connection %s from %s", conn, addr)
                handler = Handler(self, (conn, addr))
                t = threading.Thread(target=handler.run)
                t.setDaemon(True)
                t.start()

    def __exit__(self, *exc_info):
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        self._thread.join()
        self._socket = None
        self._thread = None

    def client(self, uid):
        private_key_path, key_or_pass = self._users[uid]
        c = paramiko.SSHClient()
        host_keys = c.get_host_keys()
        key = paramiko.RSAKey.from_private_key_file(SERVER_KEY_PATH)
        host_keys.add(self.host, "ssh-rsa", key)
        host_keys.add("[%s]:%d" % (self.host, self.port), "ssh-rsa", key)
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
        if private_key_path is None:
            c.connect(hostname=self.host,
                      port=self.port,
                      username=uid,
                      password=key_or_pass,
                      allow_agent=False,
                      look_for_keys=False)
        else:
            c.connect(hostname=self.host,
                      port=self.port,
                      username=uid,
                      key_filename=private_key_path,
                      allow_agent=False,
                      look_for_keys=False)
        return c

    @property
    def port(self):
        return self._socket.getsockname()[1] if self._port == 0 else self._port

    @property
    def host(self):
        return self._host

    @property
    def users(self):
        return self._users.keys()
