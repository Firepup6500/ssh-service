#!/usr/bin/env python3
import sys

from zope.interface import implementer, interface

from twisted.conch import avatar, recvline
from twisted.conch.insults import insults
from twisted.conch.checkers import InMemorySSHKeyDB, SSHPublicKeyChecker
from twisted.conch.ssh import connection, factory, keys, session, userauth
from twisted.conch.ssh.transport import SSHServerTransport
from twisted.cred import portal
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.internet import protocol, reactor
from twisted.python import components, log, failure

from typing import Callable, Any, Union

from random import randint

# log.startLogging(sys.stderr)

__print__ = print
NoneType = type(None)


# Override default print to always flush, otherwise it doesn't show up in systemd logs
def print(*args, **kwargs) -> None:
    kwargs["flush"] = True
    __print__(*args, **kwargs)


def err(
    _stuff: Union[NoneType, Exception, failure.Failure] = None,
    _why: Union[str, NoneType] = None,
    **kw,
) -> None:
    """Write a failure to the log.

    The C{_stuff} and C{_why} parameters use an underscore prefix to lessen
    the chance of colliding with a keyword argument the application wishes
    to pass.  It is intended that they be supplied with arguments passed
    positionally, not by keyword.

    @param _stuff: The failure to log. If C{_stuff} is L{None} a new
        L{Failure} will be created from the current exception state.  If
        C{_stuff} is an C{Exception} instance it will be wrapped in a
        L{Failure}.
    @type _stuff: L{None}, C{Exception}, or L{Failure}.

    @param _why: The source of this failure.  This will be logged along with
        C{_stuff} and should describe the context in which the failure
        occurred.
    @type _why: C{str}
    """
    if _stuff is None:
        _stuff = failure.Failure()
    if isinstance(_stuff, failure.Failure):
        # Hijack logging for ssh commands, the error has to be thrown to disconnect the user, and is perfectly safe to ignore
        if (
            _stuff.getErrorMessage()
            != "'NoneType' object has no attribute 'loseConnection'"
        ):
            log.msg(failure=_stuff, why=_why, isError=1, **kw)
        else:
            log.msg("Ignoring failed ssh command", why=_why, isError=1, **kw)
    elif isinstance(_stuff, Exception):
        log.msg(failure=failure.Failure(_stuff), why=_why, isError=1, **kw)
    else:
        log.msg(repr(_stuff), why=_why, isError=1, **kw)


log.deferr = err
log.err = err

"""
Example of running a custom protocol as a shell session over an SSH channel.

Warning! This implementation is here to help you understand how Conch SSH
server works. You should not use this code in production.

Re-using a private key is dangerous, generate one.

For this example you can use:

$ ckeygen -t rsa -f /opt/ssh-service-keys/keys/host_key
$ ckeygen -t rsa -f /opt/ssh-service-keys/keys/admin1
$ ckeygen -t rsa -f /opt/ssh-service-keys/keys/admin2
$ ckeygen -t rsa -f /opt/ssh-service-keys/keys/guest

Re-using DH primes and having such a short primes list is dangerous, generate
your own primes. Store your primes in "primes.py" under the variable name "PRIMES"

In this example the implemented SSH server identifies itself using an RSA host
key and authenticates clients using username "user" and password "password" or
using a SSH RSA key.

# Clean the previous server key as we should now have a new one
$ ssh-keygen -f ~/.ssh/known_hosts -R [localhost]:5022
# Connect with password
$ ssh -p 5022 user@localhost
# Connect with the SSH client key.
$ ssh -p 5022 -i ssh-keys/client_rsa user@localhost
"""

KEY_DIR = "/opt/ssh-service-keys/keys/"

# Path to RSA SSH keys used by the server.
SERVER_RSA_PRIVATE = KEY_DIR + "host_key"
SERVER_RSA_PUBLIC = KEY_DIR + "host_key.pub"

# Path to RSA SSH keys accepted by the server.
ADMIN1_RSA_PUBLIC = KEY_DIR + "admin1.pub"
ADMIN2_RSA_PUBLIC = KEY_DIR + "admin2.pub"
GUEST_RSA_PUBLIC = KEY_DIR + "guest.pub"

# We have to know how the script is being ran.
if len(sys.argv) < 2:
    raise ValueError("Script state must be passed as first arg.")
__state__ = sys.argv[1]
commonCmds = ["help", "clear", "quit", "exit", "cd", "null"]
states: dict[str, dict[str, Any]] = {
    "universe": {
        "port": 22,
        "motd": [
            "CONNECTED TO UNIVERSAL NODE $RNDID",
            "",
            "FOR OFFICIAL USE ONLY.",
            "",
            "REQUESTED SERVICE IS RESTRICTED",
            "",
            "Due to technical restrictions, ^C and ^D do not work on this server.",
        ],
        "cmds": ["uptime"],
    },
    "space": {
        "port": 22,
        "motd": [
            "CONNECTED TO SPACE.DATACENTER.FIREPI",
            "",
            "FOR FIREPUP'S USE ONLY.",
            "",
            "REQUESTED SERVICE IS RESTRICTED",
            "",
            "Due to technical restrictions, ^C and ^D do not work on this server.",
        ],
        "cmds": ["status"],
    },
    "test": {
        "port": 5022,
        "motd": [
            "Connected to the test ssh server@firepi",
            "",
            "Due to technical restrictions, ^C and ^D do not work on this server.",
        ],
        "cmds": ["debug"],
    },
}
for state in states:
    states[state]["cmds"].extend(commonCmds)
if __state__ not in states:
    raise ValueError(f"Invalid state. Must be one of: {list(states.keys())}")

# Pre-computed big prime numbers used in Diffie-Hellman Group Exchange as
# described in RFC4419.
# This is a short list with a single prime member and only for keys of size
# 1024 and 2048.
# You would need a list for each SSH key size that you plan to support in your
# server implementation.
# You can use OpenSSH ssh-keygen to generate these numbers.
# See the MODULI GENERATION section from the ssh-keygen man pages.
# See moduli man pages to find out more about the format used by the file
# generated using ssh-keygen.
# For Conch SSH server we only need the last 3 values:
# * size
# * generator
# * modulus
#
# The format required by the Conch SSH server is:
#
# {
#   size1: [(generator1, modulus1), (generator1, modulus2)],
#   size2: [(generator4, modulus3), (generator1, modulus4)],
# }
#
# twisted.conch.openssh_compat.primes.parseModuliFile provides a parser for
# reading OpenSSH moduli file.
from primes import PRIMES


class SshAvatar(avatar.ConchUser):
    username: bytes

    def __init__(self, username: bytes):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({b"session": session.SSHSession})


@implementer(portal.IRealm)
class SshRealm:
    def requestAvatar(
        self, avatarId: bytes, mind, *interfaces: tuple[interface.InterfaceClass]
    ):
        return interfaces[0], SshAvatar(avatarId), lambda: None


@implementer(session.ISession, session.ISessionSetEnv)
class SshSession:
    env: dict[bytes, bytes] = {}
    avatar: SshAvatar
    username: str
    term: bytes
    windowSize: tuple[int]
    ptyAttrs: list[tuple[int]]

    def __init__(self, avatar: SshAvatar):
        self.avatar = avatar
        self.username = avatar.username.decode()

    def getPty(
        self, term: bytes, windowSize: tuple[int], attrs: list[tuple[int]]
    ) -> None:
        self.term = term
        self.windowSize = windowSize
        self.ptyAttrs = attrs

    def setEnv(self, name: bytes, value: bytes) -> None:
        self.env[name] = value

    def execCommand(self, proto: session.SSHSessionProcessProtocol, cmd: bytes) -> None:
        """
        We don't support command execution sessions.
        """
        proto.write("Nice try\r\n")
        proto.loseConnection()  # This errors, but honestly that's fine. Causes the user to get dropped from the server, which is what we want this to do anyways.

    def windowChanged(self, windowSize: tuple[int]) -> None:
        self.windowSize = windowSize

    def openShell(self, transport: session.SSHSessionProcessProtocol) -> None:
        protocol = insults.ServerProtocol(SshProtocol, self)
        protocol.makeConnection(transport)
        transport.makeConnection(session.wrapProtocol(protocol))

    def eofReceived(self) -> None: ...

    def closed(self) -> None: ...


class SshProtocol(recvline.HistoricRecvLine):
    cmdMap: dict[str, Callable[[Any, list[str]], bool]] = {}
    helpMap: dict[str, dict[str, Union[str, list[str]]]] = {
        "help": {
            "desc": "Provides help with availible commands",
            "usage": ["help", "help <command>"],
        },
        "clear": {"desc": "Clears the terminal", "usage": ["clear"]},
        "quit": {"desc": "Closes the connection", "usage": ["quit", "exit"]},
        "exit": {"desc": "Closes the connection", "usage": ["exit", "quit"]},
        "cd": {"desc": "Changes the current directory", "usage": ["cd <directory>"]},
        "uptime": {
            "desc": "Displays the current node's system uptime",
            "usage": ["uptime"],
        },
        "status": {"desc": "Displays the current system status", "usage": ["status"]},
    }
    user: SshSession = ...
    username: str = ...

    def __init__(self, user: SshSession):
        self.user = user
        self.username = user.username
        for cmd in states[__state__]["cmds"]:
            try:
                self.cmdMap[cmd] = getattr(self, cmd)
            except ValueError:
                self.cmdMap[cmd] = self.null
        print(f'Initalized new terminal for user "{user.username}"')

    # Commands

    def null(self, params) -> bool:
        self.writeLines(["Command not implemented"])
        return True

    def uptime(self, params) -> bool:
        self.writeLines(
            [
                "!!! NOTICE !!!",
                "Due to exceeding bit limits, the system uptime on this node is aproximate.",
                "",
                "Uptime: ~13.8 Billion Years",
            ]
        )
        return True

    def status(self, params) -> bool:
        self.writeLines(
            [
                "=== System status ===",
                "",
                "Current power reserves: 12y 5m 3d 9h 3m 21s",
                "Lighting status: In direct sunlight",
                "Incoming power: +4683MW",
                "System load: Minimal",
                "System power draw: -4683MW",
                "Net power gain/loss: 0W",
                "",
                "Overall status: OK.",
            ]
        )
        return True

    def clear(self, params) -> bool:
        self.terminal.reset()
        return False

    def quit(self, params) -> bool:
        self.terminal.loseConnection()

    def exit(self, params) -> bool:
        self.terminal.loseConnection()

    def help(self, params):
        h = ["===== Help ====="]
        if not params:
            h.append("Availible commands:")
            h.extend(self.cmdMap.keys())
        else:
            cmd = params[0]
            if cmd in self.cmdMap:
                if cmd in self.helpMap:
                    myHelp = self.helpMap[params[0]]
                    h.extend([f"Help for {params[0]}", myHelp["desc"], "", "Usage:"])
                    h.extend(myHelp["usage"])
                else:
                    h.append("Command not implemented")
            else:
                h.extend(
                    [
                        "Unknown command",
                        "Run help with no args to see a list of commands",
                    ]
                )
        self.writeLines(h)
        return True

    def cd(self, params: str) -> bool:
        self.writeLines(["Operation not permitted."])
        return True

    # End of commands

    def prompt(self, newFirst=True):
        self.writeLines(["$ "], newFirst)

    def writeLines(self, lines, firstNew=False):
        for line in lines:
            if firstNew:
                self.terminal.nextLine()
            firstNew = True
            id = randint(0, 999)
            if id < 10:
                id = f"00{id}"
            elif id < 100:
                id = f"0{id}"
            else:
                id = f"{id}"
            self.terminal.write(line.replace("$RNDID", id))

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.clear("")
        self.writeLines(states[__state__]["motd"])
        self.prompt()

    def lineReceived(self, line):
        print("IN:", line)
        sline = line.strip().decode()
        if sline:
            cmd = sline.split()[0]
            params = sline.split()[1:]
            print(f'Got command "{cmd}", with args {params}')
            if cmd in self.cmdMap:
                self.prompt(self.cmdMap[cmd](params))
            else:
                self.writeLines([cmd + ": command not found"])
                self.prompt()
        else:
            self.prompt(False)


components.registerAdapter(
    SshSession, SshAvatar, session.ISession, session.ISessionSetEnv
)


class SshFactory(factory.SSHFactory):
    protocol = SSHServerTransport
    services = {
        b"ssh-userauth": userauth.SSHUserAuthServer,
        b"ssh-connection": connection.SSHConnection,
    }

    def __init__(self):
        # In order for passwords to match, they have to be bytes. Since the admin key below is a string and not bytes, it's impossible for that passowrd to ever work.
        passwdDB = InMemoryUsernamePasswordDatabaseDontUse(
            admin="Impossible",
            guest=b"password",
        )
        sshDB = SSHPublicKeyChecker(
            InMemorySSHKeyDB(
                {
                    b"admin": [
                        keys.Key.fromFile(ADMIN1_RSA_PUBLIC),
                        keys.Key.fromFile(ADMIN2_RSA_PUBLIC),
                    ],
                    b"guest": [keys.Key.fromFile(GUEST_RSA_PUBLIC)],
                }
            )
        )
        self.portal = portal.Portal(SshRealm(), [passwdDB, sshDB])

    def getPublicKeys(self):
        return {b"ssh-rsa": keys.Key.fromFile(SERVER_RSA_PUBLIC)}

    def getPrivateKeys(self):
        return {b"ssh-rsa": keys.Key.fromFile(SERVER_RSA_PRIVATE)}

    def getPrimes(self):
        return PRIMES


if __name__ == "__main__":
    print("Initalizing TCP Listener", flush=True)
    reactor.listenTCP(states[__state__]["port"], SshFactory())
    print("Now ready to accept ssh connections.", flush=True)
    reactor.run()
