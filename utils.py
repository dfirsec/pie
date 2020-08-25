__author__ = "DFIRSec (@pulsecode)"
__description__ = "Extract Indicators of Compromise (IOCs) from PDF documents."


import re
import sys

from colorama import Fore, Style, init


class Processor():
    def regex(self, _type):
        pattern = dict(
            address=r"(^(\d+)\s?([A-Za-z](?=\s))?\s(.*?)\s([^ ]+?)\s?((?<=\s)APT)?\s?((?<=\s)\d*)?$)",
            arabic=r"[\u0600-\u06FF]",
            archive=r"(([^\s|\W])+[a-z-A-Z0-9\-\_]+((?:\.zip)|(?:\.7z)|(?:\.rar)|(?:\.xz)|(?:\.tar)|(?:\.tar.gz)))",
            base64=r"(^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$)",
            binary=r"(([^\s|\W])+([a-z-A-Z0-9\-\_]|[\u4E00-\u9FFF]|[\u0400-\u04FF])+((?:\.exe)|(?:\.msi)|(?:\.dll)|(?:\.bin)))",
            btc=r"(^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$)",
            cc=r"((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])",
            chinese=r"[\u4E00-\u9FFF]",
            cyrillic=r"[\u0400-\u04FF]",
            date=r"(?:(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}",
            domain=r"([A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?<!fireeye)(?:\[\.\]|\.)(?![a-z-]*.\.gov|gov|add|ako|asn|asp|bat|bak|bin|class|cpj|dat|db|dll|doc|drv|dx|exe|gif|gov|gz|hta|htm|img|inf|ini|jar|java|jsp|jpg|key|lnk|log|md|min|msi|mtx|nat|rar|rer|rpm|out|pdf|php|png|ps|py|src|sh|sys|tmp|txt|user|vbe|xls|xml|xpm|zip|[i\.e]$|[e\.g]$)(?:[a-z]{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)",
            office=r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+\.(doc|docx|xls|xlsx|pdf))",
            email=r"([a-zA-Z0-9_.+-]+(\[@\]|@)(?!fireeye)[a-zA-Z0-9-.]+(\.|\[\.\])(?![a-z-]+\.gov|gov)([a-zA-Z0-9-.]{2,6}\b))",
            env_var=r"(\%+[a-zA-Z0-9]+\%.*[^\"])",
            misc_file=r"([a-z-A-Z0-9\-\_ ]\.(txt|csv))",
            image=r"(([^\s|\W])+[a-z-A-Z0-9\-\_]+((?:\.jpg)|(?:\.gif)|(?:\.jpeg)|(?:\.jpg)|(?:\.png)|(?:\.svg)))",
            ipv4=r"(((?![0])(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\[\.\]|\.))){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
            md5=r"\b[A-Fa-f0-9]{32}\b",
            phone=r"(^(?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-]))\$)",
            po_box=r"P\.? ?O\.? Box \d+",
            script=r"(([^\s|(\"])+[a-z-A-Z0-9\-\_]+((?:\.vbs)|(?:\.sh)|(?:\.bat)|(?:\.ps1)|(?:\.py)))",
            sha1=r"\b[A-Fa-f0-9]{40}\b",
            sha256=r"\b[A-Fa-f0-9]{64}\b",
            sha512=r"\b[A-Fa-f0-9]{128}\b",
            ssn=r"(?!000|666|333)0*(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[- ](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}",
            url=r"((http|hxxp)[s]?:\/\/(?!.+\.gov|gov)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:[0-9a-fA-F][0-9a-fA-F]))+(?<![\s\W]))",
            webfile=r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+(\.|\[\.\])(hta|html|htm|htmls|java|jsp|js|php|asp|aspx))",
            windir=r"([a-zA-Z]{1}:(\\|\\\\|\/\/)(?<![a-zA-Z]:\/\/)[a-zA-Z0-9\-\_\\\/]([^\s|\"]+)[^\.\"\r\n])",
            zip_code=r"\b\d{5}(?:[-\s]\d{4})?\b"
        )

        return re.compile(pattern[_type])

    def reiter(self, regex, text):
        return [x.group() for x in re.finditer(regex, text)]

    def patts(self, text):
        patterns = {
            'ARABIC': self.reiter(self.regex(_type='arabic'), text),
            'ARCHIVE': self.reiter(self.regex(_type='archive'), text),
            'BINARY': self.reiter(self.regex(_type='binary'), text),
            'BTC': self.reiter(self.regex(_type='btc'), text),
            'CHINESE': self.reiter(self.regex(_type='chinese'), text),
            'CYRILLIC': self.reiter(self.regex(_type='cyrillic'), text),
            'DOMAIN': self.reiter(self.regex(_type='domain'), text),
            'EMAIL': self.reiter(self.regex(_type='email'), text),
            'ENVIRONMENT VARIABLE': self.reiter(self.regex(_type='env_var'), text),
            'MISC FILE': self.reiter(self.regex(_type='misc_file'), text),
            'IMAGE': self.reiter(self.regex(_type='image'), text),
            'IPV4': self.reiter(self.regex(_type='ipv4'), text),
            'MD5': self.reiter(self.regex(_type='md5'), text),
            'OFFICE/PDF': self.reiter(self.regex(_type='office'), text),
            'PHONE': self.reiter(self.regex(_type='phone'), text),
            'SCRIPT': self.reiter(self.regex(_type='script'), text),
            'SHA1': self.reiter(self.regex(_type='sha1'), text),
            'SHA256': self.reiter(self.regex(_type='sha256'), text),
            'URL': self.reiter(self.regex(_type='url'), text),
            'WEB FILE': self.reiter(self.regex(_type='webfile'), text),
            'WIN DIR': self.reiter(self.regex(_type='windir'), text)
        }

        return patterns


class Termcolor:
    # Initizlize colorama
    init()

    BOLD = Fore.LIGHTWHITE_EX
    CYAN = Fore.CYAN
    GRAY = Fore.LIGHTBLACK_EX
    GREEN = Fore.LIGHTGREEN_EX
    RED = Fore.RED
    YELLOW = Fore.LIGHTYELLOW_EX
    RESET = Style.RESET_ALL
    SEP = f"{GRAY}--------------{RESET}"
    DOTSEP = f"{GRAY}{'.' * 20}{RESET}"
    FOUND = CYAN + "\u2BA9 " + RESET
