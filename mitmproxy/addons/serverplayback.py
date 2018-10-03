import hashlib
import urllib
import typing
import re

from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import exceptions
from mitmproxy import io
from mitmproxy import command
import mitmproxy.types


class ServerPlayback:
    def __init__(self):
        self.flowmap = {}
        self.stop = False
        self.final_flow = None
        self.configured = False

    def load(self, loader):
        loader.add_option(
            "server_replay_kill_extra", bool, False,
            "Kill extra requests during replay."
        )
        loader.add_option(
            "server_replay_nopop", bool, False,
            """
            Don't remove flows from server replay state after use. This makes it
            possible to replay same response multiple times.
            """
        )
        loader.add_option(
            "server_replay_refresh", bool, True,
            """
            Refresh server replay responses by adjusting date, expires and
            last-modified headers, as well as adjusting cookie expiration.
            """
        )
        loader.add_option(
            "server_replay_use_headers", typing.Sequence[str], [],
            "Request headers to be considered during replay."
        )
        loader.add_option(
            "server_replay", typing.Sequence[str], [],
            "Replay server responses from a saved file."
        )
        loader.add_option(
            "server_replay_ignore_content", bool, False,
            "Ignore request's content while searching for a saved flow to replay."
        )
        loader.add_option(
            "server_replay_ignore_params", typing.Sequence[str], [],
            """
            Request's parameters to be ignored while searching for a saved flow
            to replay.
            """
        )
        loader.add_option(
            "server_replay_ignore_param_regex", str, "\d{13,13}",
            """
            Regex to ignore a request's parameter while searching for a saved flow to replay
            """
        )
        loader.add_option(
            "server_replay_ignore_payload_params", typing.Sequence[str], [],
            """
            Request's payload parameters (application/x-www-form-urlencoded or
            multipart/form-data) to be ignored while searching for a saved flow
            to replay.
            """
        )
        loader.add_option(
            "server_replay_ignore_host", bool, False,
            """
            Ignore request's destination host while searching for a saved flow
            to replay.
            """
        )

    @command.command("replay.server")
    def load_flows(self, flows: typing.Sequence[flow.Flow]) -> None:
        """
            Replay server responses from flows.
        """
        self.flowmap = {}
        for i in flows:
            if i.response:  # type: ignore
                ctx.log.warn("=========================Add flow to flowmap=====================\n");
                sh = self._hash(i)
                l = self.flowmap.setdefault(sh, [])
                l.append(i)
                ctx.log.warn("Flows: {}\n".format(l))
                ctx.log.warn("Flows hash: {}\n".format(sh))
                ctx.log.warn("===================Finished adding flow to flowmap===============\n");
        ctx.master.addons.trigger("update", [])
        ctx.log.warn("=========================Finished loading all flows=======================")

    @command.command("replay.server.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.load_flows(flows)

    @command.command("replay.server.stop")
    def clear(self) -> None:
        """
            Stop server replay.
        """
        self.flowmap = {}
        ctx.master.addons.trigger("update", [])

    def count(self):
        return sum([len(i) for i in self.flowmap.values()])

    def _hash(self, flow):
        """
            Calculates a loose hash of the flow request.
        """
        r = flow.request
        ctx.log.warn("Flow request url is: {}\n".format(r.url))

        _, _, path, _, query, _ = urllib.parse.urlparse(r.url)
        queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)

        # key: typing.List[typing.Any] = [str(r.port), str(r.scheme), str(r.method), str(path)]
        key = [str(r.port), str(r.scheme), str(r.method), str(path)]  # type: List[Any]
        ctx.log.warn("Initial key: {}".format(key))
        if not ctx.options.server_replay_ignore_content:
            if ctx.options.server_replay_ignore_payload_params and r.multipart_form:
                key.extend(
                    (k, v)
                    for k, v in r.multipart_form.items(multi=True)
                    if k.decode(errors="replace") not in ctx.options.server_replay_ignore_payload_params
                )
            elif ctx.options.server_replay_ignore_payload_params and r.urlencoded_form:
                key.extend(
                    (k, v)
                    for k, v in r.urlencoded_form.items(multi=True)
                    if k not in ctx.options.server_replay_ignore_payload_params
                )
            else:
                r.raw_content = re.sub(',"dateTime":"(.+?)"', '', '{}'.format(r.raw_content))
                key.append(str(r.raw_content))

        if not ctx.options.server_replay_ignore_host:
            key.append(r.host)

        filtered = []
        ignore_params = ctx.options.server_replay_ignore_params or []
        if ignore_params:
            ignore_params = ignore_params[0].split(' ');
        ctx.log.warn("ignore_params: {}".format(ignore_params))
        ignore_param_regex = ctx.options.server_replay_ignore_param_regex

        ctx.log.warn("Unfiltered queriesArray: {}\n".format(queriesArray))
        for p in queriesArray:
            if p[0] not in ignore_params:
                filtered.append(p) 
        ctx.log.warn("Filtered by params, queriesArray: {}\n".format(filtered))

        for p in filtered:
            if ignore_param_regex and not re.compile(ignore_param_regex).match(p[0]):
                key.append(p[0])
                key.append(p[1])
            else:
                ctx.log.warn("Filtered param {} by regex".format(p))

        ignore_headers = ctx.options.server_replay_use_headers or []
        if ignore_headers:
            headers = []
            ignore_headers = ignore_headers[0].split(' ');
            for i in ignore_headers:
                v = r.headers.get(i)
                headers.append((i, v))
            key.append(headers)

        ctx.log.warn("Final key before hashing: {}\n".format(key))
        result = hashlib.sha256(repr(key).encode("utf8", "surrogateescape")).digest()
        ctx.log.warn("Key hash: {}\n".format(result))
        return result


    def next_flow(self, request):
        """
            Returns the next flow object, or None if no matching flow was
            found.
        """
        ctx.log.warn("----------------------------Start Hashing Request-------------------------\n")
        hsh = self._hash(request)
        ctx.log.warn("--------------------------Finished Hashing Request--------------------------")
        if hsh in self.flowmap:
            if ctx.options.server_replay_nopop:
                return self.flowmap[hsh][0]
            else:
                ret = self.flowmap[hsh].pop(0)
                if not self.flowmap[hsh]:
                    del self.flowmap[hsh]
                return ret

    def configure(self, updated):
        if not self.configured and ctx.options.server_replay:
            self.configured = True
            try:
                flows = io.read_flows_from_paths(ctx.options.server_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.load_flows(flows)

    def tick(self):
        if self.stop and not self.final_flow.live:
            ctx.master.addons.trigger("processing_complete")

    def request(self, f):
        ctx.log.warn("===========================Start Matching Request=========================\n")
        if self.flowmap:
            rflow = self.next_flow(f)
            ctx.log.warn("Matched response: {}".format(rflow))
            if rflow:
                response = rflow.response.copy()
                response.is_replay = True
                if ctx.options.server_replay_refresh:
                    response.refresh()
                f.response = response
                if not self.flowmap:
                    self.final_flow = f
                    self.stop = True
            elif ctx.options.server_replay_kill_extra:
                ctx.log.warn(
                    "Killing non-replay request with url {}".format(
                        f.request.url
                    )
                )
                f.reply.kill()
        ctx.log.warn("\n=======================-Finished Matching Request=========================")

