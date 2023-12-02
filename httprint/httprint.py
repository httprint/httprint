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
import glob
import random
import logging

from tornado.ioloop import IOLoop
import tornado.httpserver
import tornado.options
from tornado.options import define, options
import tornado.web
from tornado import gen, escape

import configparser
import pypdf
import base64
import json

from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import pytz

QUEUE_DIR = 'queue'
PPD_DIR = 'ppd'
ARCHIVE = False
ARCHIVE_DIR = 'archive'

DEFAULT_COPIES = 1
DEFAULT_SIDES = "two-sided-long-edge" #two-sided-long-edge, two-sided-short-edge, one-sided
DEFAULT_MEDIA = "A4"
DEFAULT_COLOR = False


CONV_CMD = "tfile=\"$(mktemp /tmp/foo.XXXXXXXXX)\" && cupsfilter -p %(ppd)s -m printer/foo -e -n %(copies)s -o sides=%(sides)s -o media=%(media)s %(in)s > $tfile 2>/dev/null && cp $tfile %(out)s &"

CODE_DIGITS = 6
MAX_PAGES = 10
KEEP_TIME = 720 #12h

UPLOAD_LIMIT_NUM = 5
UPLOAD_LIMIT_SEC = 30

logger = logging.getLogger()
logger.setLevel(logging.INFO)


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


    def search_document(self, code):
        # logger.info(self.request.arguments)
        token = self.get_argument("token", default="", strip=False)
        ppdstd = self.get_argument("ppdstd", default=None, strip=False)

        if not token in self.cfg.tokenlist.split(","):
            self.build_error("not allowed")
            return
        
        if not code:
            self.build_error("empty code")
            return
        
        fnamearr = [x for x in sorted(glob.glob(self.cfg.queue_dir + '/**/%s-*.pdf' % code, recursive=True))]
        
        if not fnamearr:
            self.build_error("no matching files")
            return
        
        fname = fnamearr[0]

        printconf = {}
        config = configparser.ConfigParser()

        copies = DEFAULT_COPIES
        sides = DEFAULT_SIDES
        media = DEFAULT_MEDIA
        color = DEFAULT_COLOR
        keep = not(os.path.samefile(os.path.dirname(fname), self.cfg.queue_dir)) #default keep if file in subfolder

        printconf['copies'] = '%d' % copies
        printconf['sides'] = '%s' % sides
        printconf['media'] = '%s' % media
        printconf['color'] = '%s' % color
        printconf['keep'] = '%s' % keep

        try:            
            config.read(os.path.dirname(fname)+ "/" + code + '.info')
            printconf = {**printconf, **dict(config['print'])} 
        except Exception:
            pass

        if printconf.get("random",False):
            fname = random.choice(fnamearr)

        try:
            config.read(fname + '.info')
            printconf = {**printconf, **dict(config['print'])} 
        except Exception:
            pass


        fnamesend = fname
        if ppdstd:
            fnamesend = f"{fname}.{str(ppdstd)}.raw"
            if not os.path.exists(fnamesend):
                self.build_error("not spooled")
                return

        return fname, fnamesend, printconf
    

class DownloadHandler(BaseHandler):
    """File print handler."""
    @gen.coroutine
    def get(self, code=None):
        
        p = self.search_document(code)
        if not p:
            return
        fname, fnamesend, printconf = p

        # send file
        buf_size = 4096
        self.set_header('Content-Type', 'application/octet-stream')
        self.set_header('Content-Disposition', 'attachment; filename=' + os.path.basename(fnamesend))
        self.set_header('printconf', json.dumps(printconf))
        with open(fnamesend, 'rb') as f:
            while True:
                data = f.read(buf_size)
                if not data:
                    break
                self.write(data)
        self.finish()

        if not strbool(printconf["keep"]):
            for fn in glob.glob(fname + '*'):
                try:
                    os.unlink(fn)
                except Exception:
                    pass


class InfoHandler(BaseHandler):
    """File info handler."""
    @gen.coroutine
    def get(self, code=None):
        
        p = self.search_document(code)
        if not p:
            return
        fname, fnamesend, printconf = p
        
        printconf["filename"] = os.path.basename(fnamesend)
        self.build_success(printconf)


class InfoBase64Handler(BaseHandler):
    """Old file print handler."""
    @gen.coroutine
    def get(self, code=None):

        p = self.search_document(code)
        if not p:
            return
        fname, fnamesend, printconf = p

        printconf["filename"] = os.path.basename(fnamesend)
        with open(fnamesend, 'rb') as f:
            self.build_success({"info":printconf, "data":base64.b64encode(f.read()).decode('utf-8')})

        if not strbool(printconf["keep"]):
            for fn in glob.glob(fname + '*'):
                try:
                    os.unlink(fn)
                except Exception:
                    pass


class UploadHandler(BaseHandler):
    """File upload handler."""
    def generateCode(self):
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
            code = str(intCode).zfill(self.cfg.code_digits)
            exlist = [i for i in self.cfg.code_exclude_list.split(",") if i]
            if not code.startswith(tuple(exlist)):
                if code not in existing:
                    break
        return code

    def prettycode(self, code):
        match self.cfg.code_digits:
            case 5 | 6:
                return '-'.join((code[:3], code[3:]))
            case _:
                return(code)

    @gen.coroutine
    def post(self):
        if not self.request.files.get('file'):
            self.build_error("No file uploaded")
            return
        
        fileinfo = self.request.files['file'][0]
        webFname = fileinfo['filename']

        #upload limit       
        for t in reversed(self.upload_limit_tlist):
            dtime = datetime.utcnow() - t
            if dtime.total_seconds() >= self.cfg.upload_limit_sec:
                self.upload_limit_tlist.remove(t)
        
        if len(self.upload_limit_tlist) >= self.cfg.upload_limit_num:
            self.build_error(f"Server busy. Retry to upload {webFname} later")
            return
        else:
            self.upload_limit_tlist.append(datetime.utcnow())


        copies = DEFAULT_COPIES
        sides = DEFAULT_SIDES
        media = DEFAULT_MEDIA
        color = DEFAULT_COLOR

        try:
            copies = int(self.get_argument('copies',))
            if copies < 1:
                copies = 1
        except Exception:
            pass
        try:
            v = self.get_argument('sides').lower()
            #sanitize input
            if v in ["two-sided-long-edge", "two-sided-short-edge", "one-sided"]:
                sides = v
        except Exception:
            pass
        try:
            v = self.get_argument('media').lower()
            #sanitize input
            if v in ["a3", "a4", "a5"]:
                media = v
        except Exception:
            pass
        try:
            color = strbool(self.get_argument('color'))
        except Exception:
            pass

        if copies > self.cfg.max_pages:
            self.build_error('You have asked too many copies')
            return


        extension = ''
        try:
            extension = os.path.splitext(webFname)[1].lower()
        except Exception:
            pass
        if not extension=='.pdf':
            extension = extension + ".pdf"
        if not os.path.isdir(self.cfg.queue_dir):
            os.makedirs(self.cfg.queue_dir)
        now = datetime.now().strftime('%Y%m%d%H%M%S')
        code = self.generateCode()
        fname = '%s-%s%s' % (code, now, extension)
        pname = os.path.join(self.cfg.queue_dir, fname)
        try:
            with open(pname, 'wb') as fd:
                fd.write(fileinfo['body'])
        except Exception as e:
            self.build_error("error writing file %s: %s" % (pname, e))
            return

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
                with open(pname, 'rb') as f:
                    pages = len(pypdf.PdfReader(f).pages)

                if pages * copies > self.cfg.max_pages and self.cfg.check_pdf_pages and not failure:
                    self.build_error(f"{webFname} has too many pages ({(pages * copies)})")
                    failure = True
            except Exception:
                if not failure:
                    self.build_error(f"Unable to get PDF information from {webFname}")
                    failure = True
                pass
        if failure:
            for fn in glob.glob(pname + '*'):
                try:
                    os.unlink(fn)
                except Exception:
                    pass
            return
        self.build_success(f"In order to print {webFname} go to the printer and enter this code: {self.prettycode(code)}")

        #raw
        ppds = sorted(glob.glob(self.cfg.ppd_dir + "/*.ppd"))
        for ppd in ppds:
            # logger.info("ppd: " + ppd)
            with open(ppd) as ppdfile:
                ppdstd = [x for x in ppdfile if x.startswith("*PCFileName:")]
                ppdstd = ppdstd[0].lower().split('"')[1].split(".ppd")[0]
            # logger.info("ppdstd: " + ppdstd)

            rawname = pname + "." + ppdstd + ".raw"
            cmd = CONV_CMD.split(' ')
            cmd = [x % {'in': pname, 'out': rawname, 'ppd': ppd, 'copies': copies, 'sides': sides, 'media': media} for x in cmd]
            cmd = " ".join(cmd)
            # logger.info(cmd)
            os.system(cmd)

class TemplateHandler(BaseHandler):
    """Handler for the template files in the / path."""
    @gen.coroutine
    def get(self, *args, **kwargs):
        """Get a template file."""
        page = 'index.html'
        if args and args[0]:
            page = args[0].strip('/')
        # arguments = self.arguments
        arguments = {"instance_name":self.cfg.instance_name, "max_pages":self.cfg.max_pages}
        self.render(page, **arguments)



def strbool(s):
    return s.lower() in ('true', '1', 't', 'y', 'yes')


def clean_expired(qdir, ktime):
    fnamearr = [x for x in sorted(glob.glob(f"{qdir}/*-*.pdf", recursive=False))]
    
    config = configparser.ConfigParser()
    for fname in fnamearr:
        printconf={}
        try:
            config.read(fname + '.info')
            printconf = config['print'] 
        except Exception:
            pass

        d=printconf.get("date")
        if not d:
            continue
        if strbool(printconf.get("keep","")):
            continue
        
        t=datetime.strptime(d,'%Y%m%d%H%M%S')
        tdiff = int((datetime.now() - t).total_seconds()/60)
        if tdiff < int(ktime): #this should be set in config
            continue

        logger.info(f"Document {os.path.basename(fname)} expired")

        for fn in glob.glob(fname + '*'):
            try:
                os.unlink(fn)
            except Exception:
                pass




def serve():
    """Read configuration and start the server."""

    define('port', default=7777, help='run on the given port', type=int)
    define('address', default='', help='bind the server at the given address', type=str)
    define('ssl_cert', default=os.path.join(os.path.dirname(__file__), 'ssl', 'httprint_cert.pem'),
            help='specify the SSL certificate to use for secure connections')
    define('ssl_key', default=os.path.join(os.path.dirname(__file__), 'ssl', 'httprint_key.pem'),
            help='specify the SSL private key to use for secure connections')
    define('code-digits', default=int(os.environ.get("CODE_DIGITS", CODE_DIGITS)), help='number of digits of the code', type=int)
    define('code-exclude-list', default=os.environ.get("CODE_EXCLUDE_LIST",""), help='list of codes starting with', type=str)
    define('max-pages', default=int(os.environ.get("MAX_PAGES", MAX_PAGES)), help='maximum number of pages to print', type=int)
    define('queue-dir', default=QUEUE_DIR, help='directory to store files before they are printed', type=str)
    define('ppd-dir', default=PPD_DIR, help='directory to store ppd files', type=str)
    define('pdf-only', default=True, help='only print PDF files', type=bool)
    define('check-pdf-pages', default=True, help='check that the number of pages of PDF files do not exeed --max-pages', type=bool)
    define('debug', default=False, help='run in debug mode', type=bool)
    define('tokenlist', default=os.environ.get("TOKEN_LIST",""), help='token list', type=str)
    define('keep-time', default=int(os.environ.get("KEEP_TIME",KEEP_TIME)), help='keep the document for x minutes', type=int)
    define('upload-limit-num', default=int(os.environ.get("UPLOAD_LIMIT_NUM",UPLOAD_LIMIT_NUM)), help='Max number of uploads in upload-limit-sec seconds', type=int)
    define('upload-limit-sec', default=int(os.environ.get("UPLOAD_LIMIT_SEC",UPLOAD_LIMIT_SEC)), help='Seconds for upload-limit-num', type=int)
    define('instance-name', default=os.environ.get("INSTANCE_NAME","HTTPrint"), help='instance name', type=str)

    tornado.options.parse_command_line()
    
    if options.debug:
        logger.setLevel(logging.DEBUG)

    ssl_options = {}
    if os.path.isfile(options.ssl_key) and os.path.isfile(options.ssl_cert):
        ssl_options = dict(certfile=options.ssl_cert, keyfile=options.ssl_key)

    init_params = dict(listen_port=options.port, logger=logger, ssl_options=ssl_options, cfg=options, upload_limit_tlist = [])

    _upload_path = r'upload/?'
    _download_path = r'download/(?P<code>\w+)'
    _info_path = r'info/(?P<code>\w+)'
    _infotest_path = r'infotest/(?P<code>\w+)'

    application = tornado.web.Application([
            (r'/api/%s' % _upload_path, UploadHandler, init_params),
            (r'/api/%s' % _download_path, DownloadHandler, init_params),
            (r'/api/%s' % _info_path, InfoHandler, init_params),
            (r'/api/%s' % _infotest_path, InfoBase64Handler, init_params),
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

    #clean expired documents
    sched = BackgroundScheduler(timezone=pytz.utc)
    sched.add_job(clean_expired, 'interval', args=[options.queue_dir, options.keep_time], next_run_time=datetime.utcnow(), seconds=120)
    sched.start()


    try:
        IOLoop.instance().start()
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == '__main__':
    serve()
