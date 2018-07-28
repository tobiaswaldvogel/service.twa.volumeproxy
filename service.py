#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#     Copyright (C) 2013 Team-XBMC
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import platform
import xbmc
import xbmcaddon

import traceback
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser

ADDON        = xbmcaddon.Addon()
ADDONVERSION = ADDON.getAddonInfo('version')
ADDONNAME    = ADDON.getAddonInfo('name')
if sys.version_info[0] >= 3:
    ADDONPATH    = ADDON.getAddonInfo('path')
    ADDONPROFILE = xbmc.translatePath( ADDON.getAddonInfo('profile') )
else:
    ADDONPATH    = ADDON.getAddonInfo('path').decode('utf-8')
    ADDONPROFILE = xbmc.translatePath( ADDON.getAddonInfo('profile') ).decode('utf-8')
ICON         = ADDON.getAddonInfo('icon')

last_volume_action = time.time()

def log(txt):
    if sys.version_info[0] >= 3:
        message = '%s: %s' % ("Volume proxy", txt.encode('utf-8'))
    else:
        if isinstance (txt,str):
            txt = txt.decode("utf-8")
        message = (u'%s: %s' % ("Volume proxy", txt)).encode("utf-8")
    xbmc.log(msg=message, level=xbmc.LOGDEBUG)

def send_xpl(target,cmd):
    msg="xpl-cmnd\n{\nhop=1\nsource=xpl-kodi.default\ntarget=%s\n}\ncontrol.basic\n{\n%s\n}\n" % (target, cmd)
    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    cs.sendto(msg, ("255.255.255.255", 3865))

def vol_up():
    send_xpl("xpl-volume.default", "cmd=vol_up")

def vol_down():
    send_xpl("xpl-volume.default", "cmd=vol_down")

def vol_mute():
    send_xpl("xpl-volume.default", "cmd=mute")

def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 30
    lock = threading.Lock()
    req_body = None
    res_body = None
    res_headers = None
    res_reason = None
    res_status = None
    last_volume = 50

    def __init__(self, *args, **kwargs):
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_Application_GetProperties(self):
        self.proxy()
        if not self.res_status == 200:
            return

        try:
            if not self.res_headers['Content-Type'].startswith('application/json'):
                return

            response = json.loads(self.res_body)
            result = response['result']
            if 'volume' in result:
                result['volume'] = 50
            if 'muted' in result:
                result['muted'] = False
            response['result'] = result
            self.res_body = json.dumps(response)
        except Exception as e:
            log(traceback.format_exc())
            log(str(e))

    def do_Application_SetMute(self):
           vol_mute()
           response = dict(self.req_json)
           del response['params']
           del response['method']
           response['result'] = True
           self.res_body = json.dumps(response)

    def do_Application_SetVolume(self):
       global last_volume_action
       try:
           params = self.req_json['params']
           level = params['volume']

           now = time.time()
           with self.lock:
               log("SetVolume %f %f" % (now, last_volume_action))
               if now - last_volume_action > 0.4 or now < last_volume_action:
                   if now - last_volume_action > 5:
                       self.last_volume = 50

                   last_volume_action = now
                   if level == 'increment':
                       vol_up()
                   elif level == 'decrement':
                       vol_down()
                   else:
                       if level == 100 or level > self.last_volume:
                           vol_up()
                       else:
                           vol_down()
                       self.last_volume = level

           response = dict(self.req_json)
           del response['params']
           del response['method']
           response['result'] = 50
           self.res_body = json.dumps(response)
           return

       except Exception as e:
           log(traceback.format_exc())
           log(str(e))

    def proxy(self):
        u = urlparse.urlsplit(self.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)

        try:
            origin = (scheme, netloc)
            conn  = httplib.HTTPConnection('127.0.0.1:8080', timeout=self.timeout)
            conn.request(self.command, path, self.req_body, dict(self.headers))
            res = conn.getresponse()

            self.res_headers = res.msg

            # support streaming
#            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
#                self.response_handler(req, req_body, res, '')
#                setattr(res, 'headers', self.filter_headers(res.headers))
#                self.relay_streaming(res)
#                with self.lock:
#                    self.save_handler(req, req_body, res, '')
#                return

            res_body = res.read()
        except Exception as e:
            log(traceback.format_exc())
            log(str(e))
	    return

        content_encoding = res.msg.get('Content-Encoding', 'identity')
        self.res_body = self.decode_content_body(res_body, content_encoding)
        self.res_status = res.status
        self.res_reason = res.reason

    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return

        except socket.timeout, e:
            #a read or a write timed out.  Discard this connection
            log("Request timed out: %r" % e)
            self.close_connection = 1
            return

        content_length = int(self.headers.get('Content-Length', 0))
        self.req_body = self.rfile.read(content_length) if content_length else None

        self.res_body = None
        self.res_headers = None
        self.res_status = 200
        self.res_reason = "OK"

        try:
           if self.headers['Content-Type'].startswith('application/json'):
                self.req_json = json.loads(self.req_body)
                req_json_method = self.req_json['method']
                method = getattr(self, "do_" + req_json_method.replace('.', '_'))
                self.res_headers = httplib.HTTPMessage(StringIO("Connection: Keep-Alive\nContent-Type: application/json\n"))
                method()

        except AttributeError:
            pass
        except KeyError:
            pass
        except Exception as e:
            log(str(e))
            log(traceback.format_exc())

        if self.res_body is None:
            try:
                self.proxy()
            except Exception as e:
                log(str(e))
                log(traceback.format_exc())

        if self.res_body is None:
            self.send_error(502)
            return

        self.res_headers['Content-Length'] = str(len(self.res_body))
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, self.res_status, self.res_reason))
        for line in self.res_headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(self.res_body)
        self.wfile.flush()

#        self.log_info(self, self.req_body, self.res_headers, self.res_body)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def log_info(self, req, req_body, res_headers, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%d %s\n%s" % (req.res_status, req.res_reason, res_headers)

        log(with_color(33, req_header_text))

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            log(with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text))

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            log(with_color(32, "==== COOKIE ====\n%s\n" % cookie))

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            log(with_color(31, "==== BASIC AUTH ====\n%s\n" % token))

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                log(with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text))

        log(with_color(36, res_header_text))


        cookies = res_headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            log(with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies))

        if res_body is not None:
            res_body_text = None
            content_type = res_headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    log(with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8'))))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                log(with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text))


def proxy(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    HandlerClass.protocol_version = protocol
    httpd = ServerClass(('0.0.0.0', 2080), HandlerClass)

    sa = httpd.socket.getsockname()
    log('Serving HTTP RPC Reverse Proxy on %s port %s' % (sa[0], sa[1]))
    httpd.serve_forever()

if (__name__ == "__main__"):
    log('Volumeproxy %s started' % ADDONVERSION)
    proxy()
