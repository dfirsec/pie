"""Worker module to process PDF files and extract text."""

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from pathlib import Path

import requests
from pdfminer.high_level import extract_text
from rich.console import Console
from rich.prompt import Prompt

from utils.helpers import Helpers

# Base directory
root = Path(__file__).resolve().parent

helper = Helpers()
console = Console(highlight=False)


class PDFWorker:
    """Processes PDF file."""

    def __init__(self) -> None:
        """Initialize match counter and TLDs filename."""
        self.counter: int = 0
        self.tlds_filename: str = "tlds-alpha-by-domain.txt"
        self._valid_tlds: set[str] | None = None

    def extractor(self, pdf: Path) -> list[str | None]:
        """Open the PDF file and extract the text.

        If the file size is greater than 10 MB, exit the program with an error message.

        Args:
            pdf: The PDF file to be read

        Returns:
            A list of text from each page of the PDF file.

        Raises:
            SystemExit: If the file size is greater than 30 MB.
        """
        file_size_limit = 30 * 1024 * 1024  # 30 MB in bytes
        size = pdf.stat().st_size
        if size > file_size_limit:
            large = round(size / (1024 * 1024))
            console.print(f"[red][ERROR][/red] Limit file size to 10 MB or less. Your file is {large:,} MB.")
            raise SystemExit(1)

        return extract_text(pdf)

    def write_file(self, results: str, mode: str, report: Path | None) -> None:
        """Write the results to the file.

        Args:
            results: The text that will be written to the file.
            mode: 'w' for write, 'a' for append.
            report: The path to the PDF file you want to extract text from.
        """
        if report:
            file_output = root / f"{report.stem.replace(' ', '_')}.txt"
            with file_output.open(mode, encoding="utf-8") as out:
                out.write(results)

    def processor(self, pdfdoc: str | Path, output: bool, title: str) -> None:
        """Extracts the text from PDF file, and writes it to a file.

        Args:
            pdfdoc: The PDF document to be processed
            output: Whether to write output to a file
            title: The title of the PDF document

        Raises:
            TypeError: If there's an issue with text extraction
        """
        pdf_path = Path(pdfdoc)
        try:
            with console.status("Gathering IOCs..."):
                pages = self.extractor(pdf=pdf_path)
                text = "".join(filter(None, pages))
        except KeyboardInterrupt as e:
            raise SystemExit() from e
        except TypeError as e:
            console.print(f"[red]Error processing PDF: {e}[/red]")
            raise
        else:
            self.get_patterns(output, title, pdf_path, text)

    def get_patterns(self, output: bool, title: str, pdfdoc: Path, text: str) -> None:
        """Searches for patterns in a given text and outputs the results to a file or console.

        Args:
            output: A boolean value indicating whether to output the results to a file or not
            title: A string representing the title of the PDF document being analyzed
            pdfdoc: The path or location of the PDF document being analyzed
            text: The text to be analyzed for patterns and IOCs (indicators of compromise)
        """
        if output:
            self.write_file(report=Path(title), results=f"\nTITLE: {title} \nPATH: {pdfdoc}\n", mode="w")

        self.detect_language(output, Path(title), text)

        for key, pvals in helper.patts(text).items():
            if pvals:
                sorted_patterns = sorted(set(pvals))
                if sorted_patterns:
                    self.counter += 1

                if key == "DOMAIN":
                    sorted_patterns = self.process_domains(set(sorted_patterns))
                    if not sorted_patterns:
                        self.counter -= 1

                self.print_and_write_patterns(key, set(sorted_patterns), output, Path(title))

        if self.counter <= 0:
            console.print("[yellow]= No IOCs found =[/yellow]")
            if output:
                self.write_file(report=Path(title), results="= No IOCs found =", mode="w")

    def detect_language(self, output: bool, title: Path, text: str) -> None:
        """Detects the language of the text.

        Args:
            output: boolean value indicating whether to output the results to a file or not.
            title: The title of the report.
            text: The text to be analyzed for languages.
        """
        detected_language = helper.detect_language(text)
        languages = {"ARABIC", "CYRILLIC", "KANJI", "CHINESE", "FARSI", "HEBREW"}
        results = ""
        sep = "-" * 14

        for language in languages:
            if detected_language.get(language) and (spec := "".join(detected_language[language])):
                self.counter += 1
                results += f"\n\n:pushpin: [bold]{language}[/bold]\n[grey50]{sep}[/grey50]\n{spec}"

        if output and results:
            self.write_file(report=title, results=results, mode="a")
        console.print(results)

    def tlds_file(self, age_limit_days: int = 3) -> Path | None:
        """Checks for TLDS file.

        Args:
            age_limit_days: The age limit in days. Defaults to 3.

        Returns:
            The path to the TLDS file if it exists or was downloaded, None otherwise.
        """
        filepath = Path(self.tlds_filename)
        if filepath.exists():
            self.check_tlds_file_age(filepath, age_limit_days)
            return filepath

        try:
            response = Prompt.ask(
                ":thinking_face: The TLDS file is missing, would you like to download the file?",
                choices=["yes", "no"],
                default="no",
            )
            if response.lower() == "yes":
                self.download_tlds_and_print_message(
                    ":stopwatch:  Downloading file... ",
                    ":thumbsup: The file '",
                    "' has been downloaded and saved.\n",
                )
                return filepath

            console.print(":disappointed: Skipped downloading TLDS file.\n")
        except KeyboardInterrupt:
            console.print("\n:disappointed: Skipped downloading TLDS file.\n")
            return None
        else:
            return None

    def check_tlds_file_age(self, filepath: Path, age_limit_days: int) -> None:
        """Checks the age of the TLDS file.

        Args:
            filepath: The path to the TLDS file.
            age_limit_days: The age limit in days.
        """
        mtime = filepath.stat().st_mtime
        mtime_datetime = datetime.fromtimestamp(mtime, tz=UTC)
        now = datetime.now(tz=UTC)
        delta = now - mtime_datetime
        age_limit = timedelta(days=age_limit_days)

        if delta > age_limit:
            try:
                response = Prompt.ask(
                    f":thinking_face: TLDS file is older than {age_limit_days} days, " "would you like to update it?",
                    choices=["yes", "no"],
                    default="no",
                )
                if response.lower() == "yes":
                    self.download_tlds_and_print_message(
                        ":stopwatch:  Updating file... ",
                        ":thumbsup: The file ",
                        " has been updated and saved.\n",
                    )
                else:
                    console.print(":disappointed: Skipped updating TLDS file.\n")
            except KeyboardInterrupt:
                console.print("\n:disappointed: Skipped updating TLDS file.\n")

    def download_tlds_and_print_message(self, arg0: str, arg1: str, arg2: str) -> None:
        """Downloads the TLDS file and prints a message."""
        console.print(arg0)
        self.download_tlds()
        console.print(f"{arg1}{self.tlds_filename}{arg2}")

    def download_tlds(self) -> None:
        """Downloads TLDS file and saves it."""
        url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
        filepath = Path(self.tlds_filename)

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            filepath.write_bytes(response.content)
            self._valid_tlds = None  # Reset cached valid_tlds
        except requests.exceptions.RequestException as err:
            console.print(f"[red]Error downloading file: {err}[/red]")

    @property
    def valid_tlds(self) -> set[str]:
        """Returns a set of valid top-level domains (TLDs)."""
        if self._valid_tlds is None:
            self._valid_tlds = set()
            tlds = Path(self.tlds_filename)
            if tlds.exists():
                with tlds.open(encoding="utf-8") as fileobj:
                    self._valid_tlds = {
                        line.strip().lower() for line in fileobj if line.strip() and not line.startswith("#")
                    }
        return self._valid_tlds

    def process_domains(self, sorted_patterns: set[str]) -> set[str]:
        """Filters a set of domain patterns based on their top-level domain.

        Args:
            sorted_patterns: Domain names, sorted in alphabetical order.

        Returns:
            A set of domain names that have valid top-level domains (TLDs) and are not
            in the excluded list of TLDs.
        """
        exclude = {"gov", "foo", "py", "zip"}  # add excluded tlds here
        return {domain for domain in sorted_patterns if domain.split(".")[-1].lower() in self.valid_tlds - exclude}

    def print_and_write_patterns(self, key: str, patterns: set[str], output: bool, title: Path) -> None:
        """Prints and writes the patterns to a file if output is True.

        Args:
            key: The key or identifier for the patterns.
            patterns: A set of strings representing patterns that have been found.
            output: Whether the results should be written to a file or not.
            title: The title of the report that will be written to a file.
        """
        if patterns:
            sep = "-" * 14
            pattern_str = "\n".join(patterns)
            console.print(f"\n:pushpin: {key}\n[grey50]{sep}[/grey50]\n{pattern_str}")
            if output:
                self.write_file(report=title, results=f"\n{key}\n{sep}\n{pattern_str}\n", mode="a")
