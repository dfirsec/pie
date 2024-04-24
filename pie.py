"""Extract Indicators of Compromise (IOCs) from PDF documents."""


import argparse
import sys
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path

import pdfplumber
import requests
from utils.helpers import Helpers
from utils.termcolors import BOLD
from utils.termcolors import CYAN
from utils.termcolors import DOTSEP
from utils.termcolors import FOUND
from utils.termcolors import GREEN
from utils.termcolors import RED
from utils.termcolors import RESET
from utils.termcolors import SEP
from utils.termcolors import YELLOW

helper = Helpers()

# Base directory
root = Path(__file__).resolve().parent


class PDFWorker:
    """Processes PDF file."""

    def __init__(self) -> None:
        """Initialize match counter and TLDs filename."""
        self.counter = 0
        self.tlds_filename = "tlds-alpha-by-domain.txt"

    def extractor(self, pdf: str) -> list:
        """Open the PDF file and extract the text from each page.

        If the file size is greater than 10 MB, exit the program with an error message.

        Args:
            pdf (str): The PDF file to be read

        Returns:
            list: A list of text from each page of the PDF file.
        """
        size = Path.stat(pdf).st_size
        large = round(size / (1024 * 1024))
        file_size_limit = 10240000
        if size > file_size_limit:
            sys.exit(f"{RED}[ERROR]{RESET} Limit file size to 10 MB or less. Your file is {large:,} MB.")
        else:
            with pdfplumber.open(pdf) as pdf_file:
                return [page.extract_text() for page in pdf_file.pages if page is not None]

    def write_file(self, results: str, opt: str, report: str | None) -> None:
        """Write the results to the file, and close the file.

        Args:
            results (str): The text that will be written to the file.
            opt (str): 'w' for write, 'a' for append.
            report (Optional[str]): The path to the PDF file you want to extract text from.
        """
        if report:
            file_output = root.joinpath(f"{Path(report).name.replace(' ', '_').replace('.pdf', '')}.txt")
            with Path(file_output, opt, encoding="utf-8").open("r") as out:
                out.write(results)

    def processor(self, pdfdoc: str, output: bool, title: str) -> None:
        """Extracts the text from PDF file, and writes it to a file.

        Args:
            pdfdoc (str): The PDF document to be processed
            output (bool): The output directory
            title (str): The title of the PDF document

        Raises:
            TypeError: If the PDF document is not a string.
        """
        print(f"{GREEN}\n[ Gathering IOCs ]{RESET}\n{DOTSEP}")

        pages = list(self.extractor(pdf=pdfdoc))
        try:
            text = "".join(filter(None, pages))
        except TypeError:
            print(f"Broken sentence: {''.join(filter(None, pages))}")
            raise

        self.get_patterns(output, title, pdfdoc, text)  # get patterns from text

    def get_patterns(self, output: bool, title: str, pdfdoc: str, text: str) -> None:
        """Searches for patterns in a given text and outputs the results to a file or console.

        Args:
            output (bool): A boolean value indicating whether to output the results to a file or not
            title (str): A string representing the title of the PDF document being analyzed
            pdfdoc (str): The path or location of the PDF document being analyzed
            text (str): The text to be analyzed for patterns and IOCs (indicators of compromise)

        Returns:
            None
        """
        # header for the report
        if output:
            self.write_file(report=title, results=f"\nTITLE: {title} \nPATH: {pdfdoc}\n", opt="w")

        # detect language patterns in text.
        self.detect_language(output, title, text)

        # check for the tlds file and download if needed.
        self.tlds_file()

        # get the patterns from the text.
        for key, pvals in helper.patts(text).items():
            if pvals:
                sorted_patterns = sorted(set(pvals))
                if sorted_patterns:
                    self.counter += 1

                if key == "DOMAIN":
                    sorted_patterns = self.process_domains(set(sorted_patterns))

                if sorted_patterns:
                    self.counter += 1
                elif key == "DOMAIN":
                    self.counter -= 1

                self.print_and_write_patterns(key, set(sorted_patterns), output, title)

        if self.counter <= 0:
            print(f"{YELLOW}= No IOCs found ={RESET}")
            if output:
                self.write_file(report=title, results="= No IOCs found =", opt="w")

    def detect_language(self, output: bool, title: str, text: str) -> None:
        """Detects the language of the text.

        Args:
            output (bool): boolean value indicating whether to output the results to a file or not.
            title (str): The title of the report.
            text (str): The text to be analyzed for languages.
        """
        detected_language = helper.detect_language(text)
        languages = {"ARABIC", "CYRILLIC", "KANJI", "CHINESE", "FARSI", "HEBREW"}
        results = ""
        for language in languages:
            if detected_language.get(language) and (spec := "".join(detected_language[language])):
                self.counter += 1
                results += f"\n\n{FOUND}{BOLD}{language}{RESET}\n{SEP}\n{spec}"

        if output and results:
            self.write_file(report=title, results=results, opt="a")
        print(results)

    def tlds_file(self, age_limit_days: int = 3) -> str:
        """Checks for TLDS file.

        Args:
            age_limit_days (int, optional): The age limit in days. Defaults to 3.

        Returns:
            str: The path to the TLDS file.
        """
        filepath = Path(self.tlds_filename)
        if filepath.exists():
            self.check_tlds_file_age(filepath, age_limit_days, self.tlds_filename)
        else:
            print("[!] The TLDS file is missing, downloading file...\n")
            self.download_tlds(self.tlds_filename)

            print(f"[+] The file {self.tlds_filename} has been downloaded and saved.")

        return str(filepath.resolve())

    def check_tlds_file_age(self, filepath: Path, age_limit_days: int, filename: str) -> None:
        """Checks the age of the TLDS file.

        Args:
            filepath (Path): The path to the TLDS file.
            age_limit_days (int): The age limit in days.
            filename (str): The name of the TLDS file.

        Returns:
            None
        """
        mtime = filepath.stat().st_mtime
        mtime_datetime = datetime.fromtimestamp(mtime, tz=UTC)

        now = datetime.now(tz=UTC)
        delta = now - mtime_datetime
        age_limit = timedelta(days=age_limit_days)  # default is 3 days

        if delta > age_limit:
            print(f"TLDS file is older than {age_limit_days} days, updating...")
            self.download_tlds(filename)

    def download_tlds(self, filename: str) -> str | None:
        """Downloads TLDS file, saves it to a file, and returns the path to the file.

        Args:
            filename (str): The name of the file to be downloaded.

        Returns:
            The path to the downloaded file.
        """
        url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
        filepath = Path(filename)

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print(f"Error downloading file: {err}")
            return None

        with Path(filepath).open("wb") as fileobj:
            fileobj.write(response.content)
        return str(filepath.resolve())

    @property
    def valid_tlds(self) -> set[str]:
        """Getter method for the valid_tlds class property.

        Returns:
            set: A set of valid top-level domains (TLDs).
        """
        valid_tlds = set()
        with Path(self.tlds_filename, encoding="utf-8").open("r") as fileobj:
            for line in fileobj:
                tld = line.strip().lower()
                if tld and not tld.startswith("#"):
                    valid_tlds.add(tld)
        return valid_tlds

    def process_domains(self, sorted_patterns: set[str]) -> set[str]:
        """Filters a set of domain patterns based on their top-level domain.

        Args:
            sorted_patterns (Set[str]): Domain names, sorted in alphabetical order.

        Returns:
            A set of domain names that have valid top-level domains (TLDs) and are not
            in the excluded list of TLDs.
        """
        new_patterns = set()
        exclude = ("gov", "foo", "py", "zip")  # add excluded tlds here
        for domain in sorted_patterns:
            tld = domain.split(".")[-1].lower()
            if tld in self.valid_tlds and tld not in exclude:
                new_patterns.add(domain)
        return new_patterns

    def print_and_write_patterns(self, key: str, patterns: set[str], output: bool, title: str) -> None:
        """Prints and writes the patterns to a file if output is True.

        Args:
            key (str): The key or identifier for the patterns.
            patterns (Set[str]): A set of strings representing patterns that have been found.
            output (bool): Whether the results should be written to a file or not.
            title (str): The title of the report that will be written to a file.

        Returns:
            None
        """
        if pattern := "\n".join(patterns):
            print(f"\n{FOUND}{BOLD}{key}{RESET}\n{SEP}\n{pattern}")
            if output:
                self.write_file(report=title, results=f"\n{key}\n{'-' * 15}\n{pattern}\n", opt="a")


class FileMissingError(Exception):
    """Custom exception for missing file."""

    def __init__(self, pdf_doc: argparse.Namespace) -> None:
        """Initializes the FileMissingError class."""
        super().__init__(f"{RED}[ERROR]{RESET} No such file: {pdf_doc}")


def main() -> None:
    """Main function that takes in command line arguments for a PDF document and extracts IOCs.

    Raises:
        FileMissingError: If the file does not exist.
    """
    parser = argparse.ArgumentParser(description="PDF IOC Extractor")
    parser.add_argument(dest="pdf_doc", help="Path to single PDF document")
    parser.add_argument("-o", "--out", dest="output", action="store_true", help="Write output to file")
    args = parser.parse_args()

    # Check if pdf file exists
    if not Path(args.pdf_doc).exists():
        raise FileMissingError(args.pdf_doc)

    title = Path(args.pdf_doc).name  # get filename for report title
    worker = PDFWorker()  # instantiate PDFWorker class
    worker.processor(pdfdoc=args.pdf_doc, output=args.output, title=title)  # process PDF document


if __name__ == "__main__":
    BANNER = r"""
        ____     ____   ______
       / __ \   /  _/  / ____/
      / /_/ /   / /   / __/
     / ____/  _/ /   / /___
    /_/      /___/  /_____/

    PDF IOC Extractor
    """
    print(f"{CYAN}{BANNER}{RESET}")

    main()
