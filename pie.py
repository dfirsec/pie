import argparse
import os
import sys
from pathlib import Path

import pdfplumber
import requests

from utils import Processor, Termcolor

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.7"
__description__ = "Extract Indicators of Compromise (IOCs) from PDF documents."

pc = Processor()
tc = Termcolor()
counter = 0

# Base directory
parent = Path(__file__).resolve().parent


def extractor(pdf):
    fsize = os.path.getsize(pdf)
    toobig = round(fsize / (1024 * 1024))
    if fsize > 10240000:
        sys.exit(f"{tc.RED}[ERROR]{tc.RESET} Limit file size to 10 MB or less. Your file is {toobig:,} MB.")
    else:
        with pdfplumber.open(pdf) as pdf:
            for page in pdf.pages:
                yield page.extract_text()


def write_file(results, opt, rep):
    if rep:
        fout = parent.joinpath(f"{rep.replace(' ', '_').replace('.pdf', '')}.txt")
        with open(fout, opt) as out:
            out.write(results)


def pdf_processor(pdf_doc, output, title):
    global counter, text
    try:
        print(f"{tc.DOTSEP}\n{tc.GREEN} [ Gathering IOCs ]{tc.RESET}")
        pages = [page for page in extractor(pdf=pdf_doc)]
        try:
            text = "".join(filter(None, pages))
        except TypeError:
            print(f"Broken sentence: {text}")
            raise

        # create output file
        if output:
            write_file(rep=title, results=f"\nTITLE: {title} \nPATH: {pdf_doc}\n", opt="w")

        def lang_proc(selection):
            global counter
            if pc.lang_patts(text).get(selection):
                counter += 1
                spec = "".join(pc.lang_patts(text).get(selection))
                print(f"\n{tc.FOUND}{tc.BOLD}{selection}{tc.RESET}\n{tc.SEP}\n{spec}")
                if output:
                    write_file(rep=title, results=f"\n{selection}\n{'-' * 15}\n{spec}", opt="a")
                # remove from dict to not repeat pattern
                pc.lang_patts(text).pop(selection)

        # Attempt to detect specific language characters
        languages = ["ARABIC", "CYRILLIC", "CHINESE", "FARSI", "HEBREW"]
        list(map(lang_proc, languages))

        # Detect other pc.patts(text)
        for key, pattern in pc.patts(text).items():
            if pattern:
                counter += 1
                sorted_set = sorted(set(pattern))
                pattern = "\n".join(sorted_set)
                print(f"\n{tc.FOUND}{tc.BOLD}{key}{tc.RESET}\n{tc.SEP}\n{pattern}")
                if output:
                    write_file(rep=title, results=f"\n{key}\n{'-' * 15}\n{pattern}\n", opt="a")

        if counter == 0:
            print(f"{tc.YELLOW}= No IOCs found ={tc.RESET}")
            if output:
                write_file(rep=title, results="= No IOCs found =", opt="w")

    except FileNotFoundError:
        sys.exit(f"{tc.RED}[ERROR]{tc.RESET} No such file: {pdf_doc}")
    except Exception as err:
        sys.exit(f"{tc.RED}[ERROR]{tc.RESET} {err}")
    except KeyboardInterrupt:
        sys.exit()


def main():
    p = argparse.ArgumentParser(description="PDF IOC Extractor")
    p.add_argument(dest="pdf_doc", help="Path to single PDF document")
    p.add_argument("-o", "--out", dest="output", action="store_true", help="Write output to file")
    args = p.parse_args()

    # check if new version is available
    try:
        latest = requests.get("https://api.github.com/repos/dfirsec/pie/releases/latest").json()["tag_name"]
        if latest != __version__:
            print(f"{tc.YELLOW}* Release {latest} of PIE is available{tc.RESET}")
    except Exception as err:
        print(err)

    if len(sys.argv[1:]) == 0:
        p.print_help()
        p.exit()

    title = ""
    if "\\" in args.pdf_doc:
        title = args.pdf_doc.split("\\")[-1]
    else:
        title = args.pdf_doc.split("/")[-1]

    pdf_processor(pdf_doc=args.pdf_doc, output=args.output, title=title)


if __name__ == "__main__":
    banner = fr"""
        ____     ____   ______
       / __ \   /  _/  / ____/
      / /_/ /   / /   / __/
     / ____/  _/ /   / /___
    /_/      /___/  /_____/

    PDF IOC Extractor {__version__}
    """

    print(f"{tc.CYAN}{banner}{tc.RESET}")
    main()
