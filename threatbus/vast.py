import asyncio
import json
import logging
import urllib.parse


def str_escape(x):
    return '"' + x.replace('"', '\\"') + '"'


async def spawn(*args):
    """Spawns a process asynchronously."""
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    logger = logging.getLogger("threat-bus")
    logger.debug(stderr.decode().strip())
    return stdout.decode().strip()


class VAST:
    def __init__(self, config):
        self.logger = logging.getLogger("threat-bus.vast")
        self.app = config.executable
        self.window = config.time_window
        self.max_results = config.max_results
        self.logger.debug(f"capping VAST results at '{self.max_results}' events")

    def make_expression(self, intel):
        """Creates a VAST expression from an intel item."""
        # FIXME: type queries currently prevent this from working.
        # filter = '#type == "zeek::conn"'
        # if self.window:
        #    filter = f"#time > {self.window} ago && {filter}"
        # pred = VAST.make_predicate(intel.type, [intel.value])
        # return f'{filter} && {pred}'
        return VAST.make_predicate(intel.type, [intel.value])

    async def status(self):
        try:
            return json.loads(await spawn(self.app, "status"))
        except json.decoder.JSONDecodeError:
            self.logger.critical(f"failed to connect to remote VAST node")
        except FileNotFoundError:
            self.logger.critical(f"could not find {self.app} in PATH")

    async def export(self, expr, window=None):
        self.logger.debug(f"spawning {self.app} process for expression {expr}")
        stdout = await spawn(
            self.app, "export", "-e", str(self.max_results), "json", expr
        )
        return stdout.splitlines()

    def path(self):
        """Retrieves the full path to the VAST binary"""
        return self.app

    @staticmethod
    def make_conjunction(xs):
        return "({})".format(" && ".join(xs))

    @staticmethod
    def make_disjunction(xs):
        return "({})".format(" || ".join(xs))

    @staticmethod
    def make_predicate(intel_type, values):
        assert values
        # Combine singleton values into a set query.
        def condense(lhs, rhs):
            if len(rhs) == 1:
                return f"{lhs} == {rhs[0]}"
            else:
                return f"{lhs} in {{{', '.join(rhs)}}}"

        # IP addresses
        if intel_type in ["ip-src", "ip-dst"]:
            return condense(":addr", values)
        # URLs
        elif intel_type in ["url", "uri"]:

            def make_http_log_expr(x):
                result = urllib.parse.urlsplit(x)
                host = result.hostname
                path = result.path
                if not host and path and path[0] != "/":
                    # If there is no protocol in the URI, then the "host" part will
                    # be prepended to "path". We're "fixing" this behavior by
                    # manually splitting at the first "/".
                    host, path = tuple(path.split("/", 1))
                    path = "/" + path  # bring back leading slash
                host = f"host == {str_escape(host)}" if host else None
                path = f"uri == {str_escape(path)}" if path else None
                if host and path:
                    return VAST.make_conjunction([host, path])
                if host:
                    return host
                if path:
                    return path
                return None

            return VAST.make_disjunction(map(make_http_log_expr, values))
        # Domains
        elif intel_type == "domain":
            return condense("host", list(map(str_escape, values)))
        # Other
        elif intel_type == "http-method":
            return condense("method", list(map(str_escape, values)))
        else:
            logger = logging.getLogger("threat-bus")
            logger.critical("unsupported intel type:", intel_type)
