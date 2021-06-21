#
# Copyright 2019 aiohomekit team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import h11
import re

from h11 import LocalProtocolError, InformationalResponse, Response, SERVER, DONE, SEND_RESPONSE
from h11._readers import _decode_header_lines
from h11._util import validate

http_version = r"(?:HTTP|EVENT)/(?P<http_version>[0-9]\.[0-9])"

status_line = (
    r"{http_version}"
    r" "
    r"(?P<status_code>{status_code})"
    # However, there are apparently a few too many servers out there that just
    # leave out the reason phrase:
    #   https://github.com/scrapy/scrapy/issues/345#issuecomment-281756036
    #   https://github.com/seanmonstar/httparse/issues/29
    # so make it optional. ?: is a non-capturing group.
    r"(?: (?P<reason>{reason_phrase}))?".format(**globals())
)

status_line_re = re.compile(status_line.encode("ascii"))


def maybe_read_from_SEND_RESPONSE_server(buf):
    lines = buf.maybe_extract_lines()
    if lines is None:
        if buf.is_next_line_obviously_invalid_request_line():
            raise LocalProtocolError("illegal request line")
        return None
    if not lines:
        raise LocalProtocolError("no response line received")
    matches = validate(status_line_re, lines[0], "illegal status line: {!r}", lines[0])
    # Tolerate missing reason phrases
    if matches["reason"] is None:
        matches["reason"] = b""
    status_code = matches["status_code"] = int(matches["status_code"])
    class_ = InformationalResponse if status_code < 200 else Response
    if lines[0].startswith(b"EVENT"):
        class_ = HAPEventResponse   
    return class_(
        headers=list(_decode_header_lines(lines[1:])), _parsed=True, **matches
    )

class HAPConnection(h11.Connection):

    def _get_io_object(self, role, event, io_dict):
        if role == SERVER and event == SEND_RESPONSE and (SERVER, DONE) in io_dict:
            return maybe_read_from_SEND_RESPONSE_server
        return super()._get_io_object()
