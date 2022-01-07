import argparse
import os
import sys
from pathlib import Path

import pdfplumber
from tld import is_tld
from tld.utils import update_tld_names

from utils import Helpers, Termcolors

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.8"
__description__ = "Extract Indicators of Compromise (IOCs) from PDF documents."

helper = Helpers()
tc = Termcolors()

# Base directory
parent = Path(__file__).resolve().parent


def extractor(pdf):
    size = os.path.getsize(pdf)
    large = round(size / (1024 * 1024))
    if size > 10240000:
        sys.exit(f"{tc.RED}[ERROR]{tc.RESET} Limit file size to 10 MB or less. Your file is {large:,} MB.")
    else:
        with pdfplumber.open(pdf) as pdf_file:
            for page in pdf_file.pages:
                yield page.extract_text()


def write_file(results, opt, rep):
    if rep:
        file_output = parent.joinpath(f"{rep.replace(' ', '_').replace('.pdf', '')}.txt")
        with open(file_output, opt, encoding="utf-8") as out:
            out.write(results)


class PDFWorker:
    """Processes PDF file."""

    def __init__(self):
        self.counter = 0

    def processor(self, pdf_doc, output, title):
        try:
            print(f"{tc.DOTSEP}\n{tc.GREEN} [ Gathering IOCs ]{tc.RESET}")
            pages = list(extractor(pdf=pdf_doc))
            try:
                text = "".join(filter(None, pages))
            except TypeError:
                print(f"Broken sentence: {''.join(filter(None, pages))}")
                raise

            # create output file
            if output:
                write_file(rep=title, results=f"\nTITLE: {title} \nPATH: {pdf_doc}\n", opt="w")

            # Language detection
            def lang_proc(selection):
                if helper.lang_patts(text).get(selection):
                    self.counter += 1
                    spec = "".join(helper.lang_patts(text).get(selection))
                    print(f"\n{tc.FOUND}{tc.BOLD}{selection}{tc.RESET}\n{tc.SEP}\n{spec}")
                    if output:
                        write_file(rep=title, results=f"\n{selection}\n{'-' * 15}\n{spec}", opt="a")

                    # remove from dict to avoid repeat pattern
                    helper.lang_patts(text).pop(selection)

            # Attempt to detect specific language characters
            languages = ["ARABIC", "CYRILLIC", "CHINESE", "FARSI", "HEBREW"]
            list(map(lang_proc, languages))

            # Detect patterns
            exclude = ("gov", "foo", "bar", "py")
            for key, pattern in helper.patts(text).items():
                if pattern:
                    self.counter += 1
                    sorted_set = sorted(set(pattern))

                    if key == "DOMAIN":
                        for domain in pattern:
                            tld = domain.split(".")[-1]
                            try:
                                while not is_tld(tld) or tld in exclude:
                                    sorted_set.remove(domain)
                            except ValueError:
                                pass

                    pattern = "\n".join(sorted_set)
                    print(f"\n{tc.FOUND}{tc.BOLD}{key}{tc.RESET}\n{tc.SEP}\n{pattern}")
                    if output:
                        write_file(rep=title, results=f"\n{key}\n{'-' * 15}\n{pattern}\n", opt="a")

            if self.counter == 0:
                print(f"{tc.YELLOW}= No IOCs found ={tc.RESET}")
                if output:
                    write_file(rep=title, results="= No IOCs found =", opt="w")

        except FileNotFoundError:
            sys.exit(f"{tc.RED}[ERROR]{tc.RESET} No such file: {pdf_doc}")
        except KeyboardInterrupt:
            sys.exit()


def main():
    parser = argparse.ArgumentParser(description="PDF IOC Extractor")
    parser.add_argument(dest="pdf_doc", help="Path to single PDF document")
    parser.add_argument("-o", "--out", dest="output", action="store_true", help="Write output to file")
    args = parser.parse_args()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    title = ""
    if "\\" in args.pdf_doc:
        title = args.pdf_doc.split("\\")[-1]
    else:
        title = args.pdf_doc.split("/")[-1]

    # update/sync tld names
    # update_tld_names()

    worker = PDFWorker()
    worker.processor(pdf_doc=args.pdf_doc, output=args.output, title=title)




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
