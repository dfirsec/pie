__author__ = "DFIRSec (@pulsecode)"
__version__ = "3.0"
__description__ = "Extract Indicators of Compromise (IOCs) from PDF documents."

import argparse
import io
import os
import re
import sys
from ipaddress import IPv4Address
from pathlib import Path

import pdfplumber

from utils import Processor, Termcolor

pc = Processor()
tc = Termcolor()


# Base directory
BASE_DIR = Path(__file__).resolve().parent


def extractor(file):
    fsize = os.path.getsize(file)
    if fsize > 10240000:
        sys.exit(f"{tc.RED}[ERROR]{tc.RESET} Limit file size to 10 MB or less. Your file is {(round(fsize/(1024*1024))):,} MB.")  # nopep8
    else:
        with pdfplumber.open(file) as pdf:
            for pages in pdf.pages:
                yield pages.extract_text()


def write_file(results, opt, rep):
    if rep:
        FOUT = BASE_DIR.joinpath(f"{rep.replace(' ', '_').replace('.pdf', '')}.txt")  # nopep8
        with open(FOUT, opt) as out:
            out.write(results)


def pdf_processor(pdf_doc, output, title):
    try:
        count = 0
        print(f"{tc.DOTSEP}\n{tc.GREEN} [ Gathering IOCs ]{tc.RESET}")
        pages = [page for page in extractor(file=pdf_doc)]
        text = ''.join(pages)

        # create output file
        if output:
            write_file(rep=title,
                       results=f"\nTITLE: {title} \nPATH: {pdf_doc}\n",
                       opt='w')

        # Attempt to detect specific language characters
        if pc.patts(text).get('ARABIC'):
            count += 1
            arabic = ''.join(pc.patts(text).get('ARABIC'))
            print(f"\n{tc.FOUND}{tc.BOLD}ARABIC{tc.RESET}\n{tc.SEP}\n{arabic}")  # nopep8
            if output:
                write_file(rep=title,
                           results=f"\nARABIC\n{('-') * 15}\n{arabic}",
                           opt='a')
            # remove from dict to not repeat pattern
            pc.patts(text).pop('ARABIC')

        if pc.patts(text).get('CYRILLIC'):
            count += 1
            cyrillic = ''.join(pc.patts(text).get('CYRILLIC'))
            print(f"\n{tc.FOUND}{tc.BOLD}CYRILLIC{tc.RESET}\n{tc.SEP}\n{cyrillic}")  # nopep8
            if output:
                write_file(rep=title,
                           results=f"\nCYRILLIC\n{('-') * 15}\n{cyrillic}",
                           opt='a')
            pc.patts(text).pop('CYRILLIC')

        if pc.patts(text).get('CHINESE'):
            count += 1
            chinese = ''.join(pc.patts(text).get('CHINESE'))
            print(f"\n{tc.FOUND}{tc.BOLD}CHINESE{tc.RESET}\n{tc.SEP}\n{chinese}")  # nopep8
            if output:
                write_file(rep=title,
                           results=f"\nCHINESE\n{('-') * 15}\n{chinese}",
                           opt='a')
            pc.patts(text).pop('CHINESE')

        # Detect other pc.patts(text)
        for key, pattern in pc.patts(text).items():
            if pattern:
                count += 1
                sorted_set = sorted(set(pattern))
                pattern = '\n'.join(sorted_set)
                print(f"\n{tc.FOUND}{tc.BOLD}{key}{tc.RESET}\n{tc.SEP}\n{pattern}")  # nopep8
                if output:
                    write_file(rep=title,
                               results=f"\n{key}\n{('-') * 15}\n{pattern}\n",
                               opt='a')

        if count == 0:
            print(f"{tc.YELLOW}= No IOCs found ={tc.RESET}")
            if output:
                write_file(rep=title, results="= No IOCs found =", opt='w')

    except FileNotFoundError:
        sys.exit(f"{tc.RED}[ERROR]{tc.RESET} No such file: {pdf_doc}")
    except Exception as err:
        print(f"{tc.RED}[ERROR]{tc.RESET} {err}")
    except KeyboardInterrupt:
        sys.exit()


def main():
    p = argparse.ArgumentParser(description="PDF IOC Extractor")
    p.add_argument(dest='pdf_doc', help="Path to single PDF document")
    p.add_argument('-o', '--out', dest='output',
                   action='store_true', help="Write output to file")
    args = p.parse_args()

    if len(sys.argv[1:]) == 0:
        p.print_help()
        p.exit()

    title = ''
    if '\\' in args.pdf_doc:
        title = args.pdf_doc.split('\\')[-1]
    else:
        title = args.pdf_doc.split('/')[-1]

    pdf_processor(pdf_doc=args.pdf_doc, output=args.output, title=title)


if __name__ == "__main__":
    banner = fr"""
        ____     ____   ______
       / __ \   /  _/  / ____/
      / /_/ /   / /   / __/
     / ____/  _/ /   / /___
    /_/      /___/  /_____/

    PDF IOC Extractor v{__version__}
    """

    print(f"{tc.CYAN}{banner}{tc.RESET}")
    main()
