#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""httprint - print files via web

Copyright 2019 Davide Alberani <da@mimante.net>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import re
import time
import glob
import random
import shutil
import logging
import subprocess
import multiprocessing as mp

from tornado.ioloop import IOLoop
import tornado.httpserver
import tornado.options
from tornado.options import define, options
import tornado.web
from tornado import gen, escape

import configparser

API_VERSION = '1.0'
QUEUE_DIR = 'queue'
ARCHIVE = True
ARCHIVE_DIR = 'archive'
PRINT_CMD = 'lp -n %(copies)s -o sides=%(sides)s -o sides=%(media)s'

CODE_DIGITS = 4
MAX_PAGES = 10
PRINT_WITH_CODE = True

logger = logging.getLogger()
logger.setLevel(logging.INFO)

re_pages = re.compile('^Pages:\s+(\d+)$', re.M | re.I)


class HTTPrintBaseException(Exception):
    """Base class for httprint custom exceptions.

    :param message: text message
    :type message: str
    :param status: numeric http status code
    :type status: int"""
    def __init__(self, message, status=400):
        super(HTTPrintBaseException, self).__init__(message)
        self.message = message
        self.status = status


class BaseHandler(tornado.web.RequestHandler):
    """Base class for request handlers."""
    # A property to access the first value of each argument.
    arguments = property(lambda self: dict([(k, v[0].decode('utf-8'))
                                            for k, v in self.request.arguments.items()]))

    @property
    def clean_body(self):
        """Return a clean dictionary from a JSON body, suitable for a query on MongoDB.

        :returns: a clean copy of the body arguments
        :rtype: dict"""
        return escape.json_decode(self.request.body or '{}')

    def write_error(self, status_code, **kwargs):
        """Default error handler."""
        if isinstance(kwargs.get('exc_info', (None, None))[1], HTTPrintBaseException):
            exc = kwargs['exc_info'][1]
            status_code = exc.status
            message = exc.message
        else:
            message = 'internal error'
        self.build_error(message, status=status_code)

    def initialize(self, **kwargs):
        """Add every passed (key, value) as attributes of the instance."""
        for key, value in kwargs.items():
            setattr(self, key, value)

    def build_error(self, message='', status=400):
        """Build and write an error message.

        :param message: textual message
        :type message: str
        :param status: HTTP status code
        :type status: int
        """
        self.set_status(status)
        self.write({'error': True, 'message': message})

    def build_success(self, message='', status=200):
        """Build and write a success message.

        :param message: textual message
        :type message: str
        :param status: HTTP status code
        :type status: int
        """
        self.set_status(status)
        self.write({'error': False, 'message': message})

    def _run(self, cmd, fname, callback=None):
        p = subprocess.Popen(cmd, close_fds=True)
        p.communicate()
        if callback:
            callback(cmd, fname, p)

    def _archive(self, cmd, fname, p):
        if os.path.isfile('%s.keep' % fname):
            return
        if self.cfg.archive:
            if not os.path.isdir(self.cfg.archive_dir):
                os.makedirs(self.cfg.archive_dir)
            for fn in glob.glob(fname + '*'):
                shutil.move(fn, self.cfg.archive_dir)
        for fn in glob.glob(fname + '*'):
            try:
                os.unlink(fn)
            except Exception:
                pass

    def run_subprocess(self, cmd, fname, callback=None):
        """Execute the given action.

        :param cmd: the command to be run with its command line arguments
        :type cmd: list
        """
        p = mp.Process(target=self._run, args=(cmd, fname, callback))
        p.start()

    def print_file(self, fname):
        copies = 1
        sides = "two-sided-long-edge"
        media = "A4"

        config = configparser.ConfigParser()
        config.read(fname + '.info')
        printconf = config['print']
        copies = printconf.getint('copies')
        if copies < 1:
            copies = 1
        sides = printconf.get('sides')
        media = printconf.get('media')
        
        print_cmd = self.cfg.print_cmd.split(' ')
        cmd = [x % {'copies': copies, 'sides': sides, 'media': media} for x in print_cmd] + [fname]
        print (cmd)
        self.run_subprocess(cmd, fname, self._archive)

class PrintHandler(BaseHandler):
    """File print handler."""
    @gen.coroutine
    def post(self, code=None):
        if not code:
            self.build_error("empty code")
            return
        remote_ip = self.request.headers.get("X-Real-IP") or \
            self.request.headers.get("X-Forwarded-For") or \
            self.request.remote_ip
        if remote_ip not in ('127.0.0.1', '::1', 'localhost'):
            self.build_error("invalid caller")
            return
        files = [x for x in sorted(glob.glob(self.cfg.queue_dir + '/%s-*' % code))
                 if not x.endswith('.info') and not x.endswith('.keep')]
        if not files:
            self.build_error("no matching files")
            return
        self.print_file(files[0])
        self.build_success("file sent to printer")

class QueryHandler(BaseHandler):
    """File print handler."""
    @gen.coroutine
    def post(self, code=None, ppd=None):
        if not code:
            self.build_error("empty code")
            return
        files = [x for x in sorted(glob.glob(self.cfg.queue_dir + '/%s-*' % code))
                 if not x.endswith('.info') and not x.endswith('.keep')]
        if not files:
            self.build_error("no matching files")
            return
        
        #questa e' una prova per leggere il file di configurazione
        #e farsi mandare il file da stampare
        config = configparser.ConfigParser()
        config.read(files[0] + '.info')
        printconf = config['print']
        self.build_success(printconf['name'])



class UploadHandler(BaseHandler):
    """File upload handler."""
    def generateCode(self):
        filler = '%0' + str(self.cfg.code_digits) + 'd'
        existing = set()
        re_code = re.compile('(\d{' + str(self.cfg.code_digits) + '})-.*')
        for fname in glob.glob(self.cfg.queue_dir + '/*'):
            fname = os.path.basename(fname)
            match = re_code.match(fname)
            if not match:
                continue
            fcode = match.group(1)
            existing.add(fcode)
        code = None
        for i in range(10**self.cfg.code_digits):
            intCode = random.randint(0, (10**self.cfg.code_digits)-1)
            code = filler % intCode
            if code not in existing:
                break
        return code

    @gen.coroutine
    def post(self):
        if not self.request.files.get('file'):
            self.build_error("no file uploaded")
            return
        copies = 1

        #questi per ora stanno qui perche' non sso come implemtare la parte web
        sides = "two-sided-long-edge"
        media = "A4"
        color = False


        try:
            copies = int(self.get_argument('copies'))
            if copies < 1:
                copies = 1
        except Exception:
            pass
        if copies > self.cfg.max_pages:
            self.build_error('you have asked too many copies')
            return
        fileinfo = self.request.files['file'][0]
        webFname = fileinfo['filename']
        extension = ''
        try:
            extension = os.path.splitext(webFname)[1]
        except Exception:
            pass
        if not os.path.isdir(self.cfg.queue_dir):
            os.makedirs(self.cfg.queue_dir)
        now = time.strftime('%Y%m%d%H%M%S')
        code = self.generateCode()
        fname = '%s-%s%s' % (code, now, extension)
        pname = os.path.join(self.cfg.queue_dir, fname)
        try:
            with open(pname, 'wb') as fd:
                fd.write(fileinfo['body'])
        except Exception as e:
            self.build_error("error writing file %s: %s" % (pname, e))
            return

        #questo l'ho aggiuto io. ho qualche dubbio su dove settare la variabile config
        config = configparser.ConfigParser()
        config['print'] = {}
        printconf = config['print']
        printconf['name'] = '%s' % webFname
        printconf['date'] = '%s' % now
        printconf['copies'] = '%d' % copies
        printconf['sides'] = '%s' % sides
        printconf['media'] = '%s' % media
        printconf['color'] = '%s' % color
        try:
            with open(pname + '.info', 'w') as configfile:
                 config.write(configfile)
        except Exception:
            pass

        failure = False
        if self.cfg.check_pdf_pages or self.cfg.pdf_only:
            try:
                p = subprocess.Popen(['pdfinfo', pname], stdout=subprocess.PIPE)
                out, _ = p.communicate()
                if p.returncode != 0 and self.cfg.pdf_only:
                    self.build_error('the uploaded file does not seem to be a PDF')
                    failure = True
                out = out.decode('utf-8', errors='ignore')
                pages = int(re_pages.findall(out)[0])
                if pages * copies > self.cfg.max_pages and self.cfg.check_pdf_pages and not failure:
                    self.build_error('too many pages to print (%d)' % (pages * copies))
                    failure = True
            except Exception:
                if not failure:
                    self.build_error('unable to get PDF information')
                    failure = True
                pass
        if failure:
            for fn in glob.glob(pname + '*'):
                try:
                    os.unlink(fn)
                except Exception:
                    pass
            return
        if self.cfg.print_with_code:
            self.build_success("go to the printer and enter this code: %s" % code)
        else:
            self.print_file(pname)
            self.build_success("file sent to printer")


class TemplateHandler(BaseHandler):
    """Handler for the template files in the / path."""
    @gen.coroutine
    def get(self, *args, **kwargs):
        """Get a template file."""
        page = 'index.html'
        if args and args[0]:
            page = args[0].strip('/')
        arguments = self.arguments
        self.render(page, **arguments)


def serve():
    """Read configuration and start the server."""
    define('port', default=7777, help='run on the given port', type=int)
    define('address', default='', help='bind the server at the given address', type=str)
    define('ssl_cert', default=os.path.join(os.path.dirname(__file__), 'ssl', 'httprint_cert.pem'),
            help='specify the SSL certificate to use for secure connections')
    define('ssl_key', default=os.path.join(os.path.dirname(__file__), 'ssl', 'httprint_key.pem'),
            help='specify the SSL private key to use for secure connections')
    define('code-digits', default=CODE_DIGITS, help='number of digits of the code', type=int)
    define('max-pages', default=MAX_PAGES, help='maximum number of pages to print', type=int)
    define('queue-dir', default=QUEUE_DIR, help='directory to store files before they are printed', type=str)
    define('archive', default=True, help='archive printed files', type=bool)
    define('archive-dir', default=ARCHIVE_DIR, help='directory to archive printed files', type=str)
    define('print-with-code', default=True, help='a code must be entered for printing', type=bool)
    define('pdf-only', default=True, help='only print PDF files', type=bool)
    define('check-pdf-pages', default=True, help='check that the number of pages of PDF files do not exeed --max-pages', type=bool)
    define('print-cmd', default=PRINT_CMD, help='command used to print the documents')
    define('debug', default=False, help='run in debug mode', type=bool)
    tornado.options.parse_command_line()
    
    if options.debug:
        logger.setLevel(logging.DEBUG)

    ssl_options = {}
    if os.path.isfile(options.ssl_key) and os.path.isfile(options.ssl_cert):
        ssl_options = dict(certfile=options.ssl_cert, keyfile=options.ssl_key)

    init_params = dict(listen_port=options.port, logger=logger, ssl_options=ssl_options, cfg=options)

    _upload_path = r'upload/?'
    _print_path = r'print/(?P<code>\d+)'
    _query_path = r'query/(?P<code>\d+)'
    _query_path_ppd = r'query/(?P<code>\d+)/(?P<ppd>\d+)'
    application = tornado.web.Application([
            (r'/api/%s' % _upload_path, UploadHandler, init_params),
            (r'/api/v%s/%s' % (API_VERSION, _upload_path), UploadHandler, init_params),
            (r'/api/%s' % _print_path, PrintHandler, init_params),
            (r'/api/v%s/%s' % (API_VERSION, _print_path), PrintHandler, init_params),
            (r'/api/%s' % _query_path, QueryHandler, init_params),
            (r'/api/v%s/%s' % (API_VERSION, _query_path), QueryHandler, init_params),
            (r'/api/%s' % _query_path_ppd, QueryHandler, init_params),
            (r'/api/v%s/%s' % (API_VERSION, _query_path_ppd), QueryHandler, init_params),
            (r'/?(.*)', TemplateHandler, init_params),
        ],
        static_path=os.path.join(os.path.dirname(__file__), 'dist/static'),
        template_path=os.path.join(os.path.dirname(__file__), 'dist/'),
        debug=options.debug)
    http_server = tornado.httpserver.HTTPServer(application, ssl_options=ssl_options or None)
    logger.info('Start serving on %s://%s:%d', 'https' if ssl_options else 'http',
                                                 options.address if options.address else '127.0.0.1',
                                                 options.port)
    http_server.listen(options.port, options.address)
    try:
        IOLoop.instance().start()
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == '__main__':
    serve()
