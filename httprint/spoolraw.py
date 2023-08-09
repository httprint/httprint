#!/usr/bin/env python3

import os
import glob
import configparser
import subprocess
import signal

DEFAULT_COPIES = 1
DEFAULT_SIDES = "two-sided-long-edge" #two-sided-long-edge, two-sided-short-edge, one-sided
DEFAULT_MEDIA = "A4"

CONV_CMD = "cupsfilter -p %(ppd)s -m printer/foo -e -n %(copies)s -o sides=%(sides)s -o media=%(media)s %(in)s > /tmp/spoolraw.tmp 2>/dev/null && cp /tmp/spoolraw.tmp %(out)s"

def main():
    #cerca i ppd
    ppds = sorted(glob.glob(os.path.dirname(os.path.realpath(__file__)) + "/ppd/*.ppd"))
    if not ppds:
        prn = subprocess.check_output("lpstat -d | awk '{print $NF}'", shell=True).decode("utf-8").strip()
        print("prn: " + prn)
        ppds = ["/etc/cups/ppd/" + prn +".ppd"]

    for ppd in ppds:
        print("ppd: " + ppd)
        #cerca il nome standard
        with open(ppd) as ppdfile:
            ppdstd = [x for x in ppdfile if x.startswith("*PCFileName:")]
            ppdstd = ppdstd[0].lower().split('"')[1].split(".ppd")[0]
        print("ppdstd: " + ppdstd)

        #cerca i file
        files = [x for x in sorted(glob.glob(os.path.dirname(os.path.realpath(__file__)) + '/queue/**/*-*', recursive=True))
            if not x.endswith('.info') and not x.endswith('.keep') and not x.endswith('.raw')]
        print(files)
        print(glob.glob(os.path.dirname(os.path.realpath(__file__))))
        for fname in files:
            rawname = fname + "." + ppdstd + ".raw"
            if not os.path.isfile(rawname):
                print ("Converto " + os.path.basename(rawname))

                #leggo la configurazione
                config = configparser.ConfigParser()
                name = "-".join(os.path.basename(fname).split("-")[1:])
                copies = DEFAULT_COPIES
                sides = DEFAULT_SIDES
                media = DEFAULT_MEDIA

                try:
                    code = os.path.basename(fname).split("-")[0]
                    config.read(os.path.dirname(fname) + "/" + code + '.info')
                    printconf = config['print']
                    name = printconf.get('name', name)
                    copies = printconf.getint('copies', copies)
                    sides = printconf.get('sides', sides)
                    media = printconf.get('media', media)
                except Exception:
                    pass

                try:
                    config.read(fname + '.info')
                    printconf = config['print']
                    name = printconf.get('name', name)
                    copies = printconf.getint('copies', copies)
                    sides = printconf.get('sides', sides)
                    media = printconf.get('media', media)
                except Exception:
                    pass

                print("Conf:",name, copies, sides, media)

                #faccio partire la conversione
                cmd = CONV_CMD.split(' ')
                cmd = [x % {'in': fname, 'out': rawname, 'ppd': ppd, 'copies': copies, 'sides': sides, 'media': media} for x in cmd]
                cmd = " ".join(cmd)
                print (cmd)
                os.system(cmd)
            else:
                print ("Salto " + os.path.basename(rawname))





if __name__ == "__main__":

    main()
