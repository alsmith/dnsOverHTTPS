#!/usr/bin/python3

import argparse
import base64
import cherrypy
import dns.message
import os
import socket
import struct
import sys

def notImplemented():
    cherrypy.response.status = 501
    return {'exception': 'Not implemented'}

class Root():
    favicon_ico = None

class API():
    class Resolve():
        def __init__(self):
            self.PUT = notImplemented
            self.DELETE = notImplemented

        def GET(self, **kwargs):
            if cherrypy.request.headers.get('Content-Type') != 'application/dns-message':
                raise cherrypy.HTTPError(400)

            if 'dns' not in kwargs:
                raise cherrypy.HTTPError(400)

            try:
                result = self._dnsQuery(self._mendPadding(self._b64decode(kwargs['dns'])), cherrypy.config['dns.server'])
                cherrypy.log('%s: %s - %s' % (cherrypy.request.remote.ip, dns.message.from_wire(result).question, dns.message.from_wire(result).answer), context='DNS [GET]')
            except Exception as e:
                cherrypy.log(str(e))

            cherrypy.response.headers['Content-Type'] = 'application/dns-message'
            return result

        def POST(self):
            if cherrypy.request.headers.get('Content-Type') != 'application/dns-message':
                raise cherrypy.HTTPError(400)

            request = cherrypy.request.body.read()

            result = self._dnsQuery(self._mendPadding(self._b64decode(kwargs['dns'])), cherrypy.config['dns.server'])
            cherrypy.log('%s: %s' % (cherrypy.request.remote.ip, dns.message.from_wire(result).question), context='DNS [POST]')

            cherrypy.response.headers['Content-Type'] = 'application/dns-message'
            return result

        @staticmethod
        def _b64decode(s):
            return base64.b64decode(s+'===')

        @staticmethod
        def _dnsQuery(packet, server):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(packet, (server, 53))
            (data, _) = s.recvfrom(4096)
            s.close()
            return data

        @staticmethod
        def _mendPadding(packet):
            if struct.unpack('!HHHH', packet[4:12]) != (1, 0, 0, 1):
                return packet

            ptr = 12
            while True:
                length = int(packet[ptr])
                ptr += 1
                if not length:
                    break
                if length & 0xc0:
                    ptr += 1
                    continue
                ptr += length
                length = int(packet[ptr])
            ptr += 4

            if struct.unpack('!H', packet[ptr+1:ptr+3])[0] != 0x29:
                return packet

            (dataLength, _, paddingLength) = struct.unpack('!HHH', packet[ptr+9:ptr+15])
            if dataLength < 4:
                dataLength = 4
                packet = packet[:ptr+9] + struct.pack('!H', dataLength) + packet[ptr+11:]
                cherrypy.log('Fixing data length for %s (%s).' % (query, dataLength), context='IOS-BUG')
            if dataLength - paddingLength != 4:
                cherrypy.log('Fixing padding length for %s (%s %s).' % (query, dataLength, paddingLength), context='IOS-BUG')
                packet = packet[:ptr+13] + struct.pack('!H', dataLength-4) + bytearray(dataLength-4)

            return packet

    def __init__(self):
        self.resolve = self.Resolve()
        self.resolve.exposed = True

def main():
    parser = argparse.ArgumentParser(usage='usage: %s' % os.path.basename(__file__))

    parser.add_argument('--foreground', action='store_true', help='Don\'t daemonize')
    parser.add_argument('--config', default=os.path.join(os.path.dirname(__file__), 'config.ini'), help='Path to config.ini')
    args = parser.parse_args()

    if not args.config:
        print('config.ini file not specified')
        return 1

    if not args.foreground:
        cherrypy.process.plugins.Daemonizer(cherrypy.engine).subscribe()

    os.chdir(os.path.dirname(__file__))
    cherrypy.config.update(args.config)
    for log in ['access_file', 'error_file', 'pid_file']:
        path = cherrypy.config.get('log.%s' % log)
        if not path.startswith('/'):
            cherrypy.config.update({'log.%s' % log: os.path.join(os.path.abspath(os.path.dirname(__file__)), path)})

    if cherrypy.config.get('log.pid_file'):
        cherrypy.process.plugins.PIDFile(cherrypy.engine, cherrypy.config.get('log.pid_file')).subscribe()

    cherrypy.config.update({'server.shutdown_timeout': 0})

    rootConfig = {'/': {'tools.staticdir.on': True,
                        'tools.staticdir.root': os.path.dirname(os.path.abspath(__file__)),
                        'tools.staticdir.dir': 'static',
                        'tools.staticdir.index': 'index.html',
                        'tools.gzip.mime_types': ['text/*', 'application/*'],
                        'tools.gzip.on': True,
                        'tools.proxy.on': True,
                        'tools.proxy.local': 'Host'}}
    apiConfig  = {'/': {'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
                        'tools.gzip.mime_types': ['text/*', 'application/*'],
                        'tools.gzip.on': True,
                        'tools.proxy.on': True}}

    cherrypy.tree.mount(Root(), '/', config=rootConfig)
    cherrypy.tree.mount(API(), '/api', config=apiConfig)

    cherrypy.engine.start()
    cherrypy.engine.block()

if __name__ == '__main__':
    sys.exit(main())

