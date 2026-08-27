#!/usr/bin/env python3

import argparse
import random
import socket
import string
import struct
import sys
import time
from datetime import (
    datetime,
    timedelta,
)
from random import (
    randint,
    sample,
)
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)


class Helper:
    """Helper functions"""

    space = " " * 20

    def _forwarded_for(self) -> str:
        """Generate a random X-My-X-Forwarded-For IP address

        Returns:
            randomized X-My-X-Forwarded-For
        """
        # Start range at 1.0.0.0
        i = struct.pack(">I", random.randint(0x1000000, 0xFFFFFFFF))
        return socket.inet_ntoa(i)

    def _amzn_trace_id(self) -> str:
        """Generate a random X-Amzn-Trace-Id
        https://aws.amazon.com/premiumsupport/knowledge-center/trace-elb-x-amzn-trace-id/
        e.g. X-Amzn-Trace-Id: Root=1-67891233-abcdef012345678912345678

        Returns:
            randomized X-Amzn-Trace-Id
        """
        b = "Root=1"
        f = "".join(random.choice("abcdef0123456789") for _ in range(8))
        s = "".join(random.choice("abcdef0123456789") for _ in range(24))
        return f"{b}-{f}-{s}"

    def _amzn_apigateway_api_id(self) -> str:
        """Generate a random X-Amzn-Apigateway-Api-Id
        e.g. x-amzn-apigateway-api-id=beags1mnid

        Returns:
            randomized X-Amzn-Apigateway-Api-Id
        """
        c = string.digits + string.ascii_lowercase
        return "".join(random.choice(c) for _ in range(10))

    @classmethod
    def fireprox_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Update the provided HTTP headers for FireProx masking
        https://github.com/ustayready/fireprox/issues/32

        Arguments:
            headers: dict of http headers

        Returns:
            updated http headers
        """
        headers["X-My-X-Forwarded-For"] = cls._forwarded_for(cls)
        headers["X-My-X-Amzn-Trace-Id"] = cls._amzn_trace_id(cls)
        headers["x-amzn-apigateway-api-id"] = cls._amzn_apigateway_api_id(cls)

        # I don't think we need to worry about these headers
        # headers["X-Forwarded-Port"] = 443
        # headers["X-Forwarded-Proto"] = "https"

        return headers

    @classmethod
    def write_data(
        cls,
        creds: Union[List[str], Dict[str, str]],
        file_: str,
        append: bool = True,
    ):
        """Write a given list of cred data to a specified file.

        Arguments:
            creds: data to write (if a dict, format key:value)
            file_: name of output file
            append: determine if we should write new file or append
        """
        mode = "a" if append else "w"
        if len(creds) > 0:
            if type(creds) == dict:
                creds = [f"{k}:{v}" for k, v in creds.items()]
            with open(file_, mode) as f:
                for account in creds:
                    f.write(f"{account}\n")

    @classmethod
    def get_random_element_from_list(cls, l: List[Any]) -> Any:
        """Select a random element from a given list

        Arguments:
            l: list of objects

        Returns:
            random element from list
        """
        return sample(l, 1)[0]

    @classmethod
    def get_random_sublist_from_list(cls, l: List[Any]) -> List[Any]:
        """Select a random set from a given list

        Arguments:
            l: list of objects

        Returns:
            random sublist of elements from list
        """
        return sample(l, randint(1, len(l)))

    @classmethod
    def get_chunks_from_list(
        cls,
        list_: List[Any],
        n: int,
    ) -> List[Any]:
        """Yield chunks of a given size, N, from a provided list.

        Arguments:
            list_: original list to chunk
            n: size of list segments

        Yields:
            list segment
        """
        for i in range(0, len(list_), n):
            yield list_[i : i + n]

    @classmethod
    def get_list_from_file(
        cls,
        file_: str,
    ) -> List[Any]:
        """Read a file's lines into a list.

        Arguments:
            file_: file to read into a list

        Returns:
            list of file lines
        """
        with open(file_, "r") as f:
            list_ = [line.strip() for line in f if line.strip() not in [None, ""]]
        return list_

    @classmethod
    def get_last_nonempty_line_from_file(
        cls,
        file_: str,
    ) -> Optional[str]:
        """Read and return the last non-empty line from a file.

        Arguments:
            file_: file to read from

        Returns:
            last non-empty line, otherwise None
        """
        last_line = None
        with open(file_, "r", encoding="utf-8") as f:
            for line in f:
                value = line.strip()
                if value:
                    last_line = value
        return last_line

    @classmethod
    def trim_list_to_resume_value(
        cls,
        list_: List[Any],
        value: Any,
    ) -> Tuple[List[Any], int, bool]:
        """Trim a list so execution starts at a given value.

        Arguments:
            list_: full list to trim
            value: value to find and trim from

        Returns:
            tuple: (trimmed list, skipped count, found flag)
        """
        for index, item in enumerate(list_):
            if item == value:
                return (list_[index:], index, True)
        return (list_, 0, False)

    @classmethod
    def get_max_dict_elem(
        cls,
        dict_: Dict[str, List[str]],
    ) -> int:
        """Identify the largest list of values in a given
        dictionary.

        Arguments:
            dict_: dictionary to iterate over

        Returns:
            length of largest list of values
        """
        # Account for an empty dict_
        if not dict_:
            return 0
        max_ = max(dict_, key=lambda k: len(dict_[k]))
        return len(dict_[max_])

    @classmethod
    def get_paired_dict_from_file(
        cls,
        file_: str,
    ) -> Dict[str, List[str]]:
        """Read paired email:password combinations from a
        file into an organized dict object.

        Arguments:
            file_: file to read into a list

        Returns:
            dict of {email: [passwords]}
        """
        with open(file_, "r", encoding="utf-8-sig") as f:
            list_ = [
                (line_number, line.strip())
                for line_number, line in enumerate(f, start=1)
                if line.strip()
            ]
        dict_ = {}
        for line_number, line in list_:
            if ":" not in line:
                raise ValueError(
                    f"Invalid paired credential on line {line_number}: "
                    "expected email:password."
                )
            username, password = line.split(":", 1)
            email = cls.normalize_email(username)
            if not password:
                raise ValueError(
                    f"Invalid paired credential on line {line_number}: "
                    "password is empty."
                )
            if email not in dict_:
                dict_[email] = []
            dict_[email].append(password)
        return dict_

    @classmethod
    def check_last_chunk(
        cls,
        sublist: List[Any],
        full_list: List[Any],
    ) -> bool:
        """Identify if the current list chunk is the last chunk.
        This assumes the full_list was uniqued prior to chunking.

        Arguments:
            sublist: sublist to compare to full_list
            full_list: complete list to check if sublist is in

        Returns:
            boolean if last chunk
        """
        if sublist[-1] == full_list[-1]:
            return True
        return False

    @classmethod
    def lockout_reset_wait(cls, lockout: Union[int, float]):
        """Print a lockout timer to the screen.
        Reference: https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/core/utils/time.py

        Arguments:
            lockout: lockout time in minutes
        """
        delay = timedelta(hours=0, minutes=lockout, seconds=0)
        sys.stdout.write("\n\n")
        for remaining in range(int(delay.total_seconds()), 0, -1):
            sys.stdout.write(f"\r[*] Next spray in: {timedelta(seconds=remaining - 1)}")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write("\n\n")

    @classmethod
    def normalize_email(cls, user: str) -> str:
        """Validate and normalize a complete email-style user principal name.

        Arguments:
            user: complete user principal name in ``local@domain`` format

        Returns:
            address with its domain normalized to lowercase IDNA form

        Raises:
            ValueError: if the value is not a complete, usable email address
        """
        if not isinstance(user, str):
            raise ValueError("Email address must be a string.")

        value = user.strip()
        if value.count("@") != 1:
            raise ValueError(
                f"Invalid email address '{user}': expected exactly one '@'."
            )

        local_part, raw_domain = value.rsplit("@", 1)
        if (
            not local_part
            or len(local_part) > 64
            or local_part.startswith(".")
            or local_part.endswith(".")
            or ".." in local_part
            or any(
                character.isspace() or ord(character) < 32
                for character in local_part
            )
        ):
            raise ValueError(f"Invalid email address '{user}': invalid local part.")

        try:
            domain = raw_domain.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(
                f"Invalid email address '{user}': invalid domain."
            ) from exc

        if not domain or len(domain) > 253 or "." not in domain:
            raise ValueError(f"Invalid email address '{user}': invalid domain.")

        labels = domain.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise ValueError(f"Invalid email address '{user}': invalid domain.")

        email = f"{local_part}@{domain}"
        if len(email) > 254:
            raise ValueError(f"Invalid email address '{user}': address is too long.")
        return email

    @classmethod
    def get_email_domain(cls, user: str) -> str:
        """Return the normalized domain associated with an email address."""
        return cls.normalize_email(user).rsplit("@", 1)[1]

    @classmethod
    def normalize_email_list(cls, users: List[str]) -> List[str]:
        """Validate a collection of addresses while preserving its order."""
        normalized = []
        for index, user in enumerate(users, start=1):
            try:
                normalized.append(cls.normalize_email(user))
            except ValueError as exc:
                raise ValueError(f"Invalid user entry #{index}: {exc}") from exc
        return normalized

    @classmethod
    def check_email(cls, user: str, domain: str = None) -> str:
        """Validate an email without ever replacing its supplied domain.

        ``domain`` remains as an internal consistency check for module code. It
        must be the domain derived from ``user`` by the execution layer.
        """
        email = cls.normalize_email(user)
        email_domain = email.rsplit("@", 1)[1]
        if domain and email_domain != domain.lower().rstrip("."):
            raise ValueError(
                f"Email domain mismatch for '{email}': expected '{domain}'."
            )
        return email

    @classmethod
    def prompt_question(cls, prompt: str) -> str:
        """Prompt a user with a given question.

        Arguments:
            prompt: question to display to the user

        Returns:
            user response
        """
        resp = str(input(prompt) or "Y").lower().strip()
        if resp[0] not in ["y", "n"]:
            return prompt_question(prompt)  # type: ignore
        return resp

    @classmethod
    def banner(cls, args: argparse.Namespace, version: str):
        """Build a tool banner based on provided command line args.

        Arguments:
            args: populated argparse namespace
            version: tool version
        """
        BANNER = "\n            *** O365 Spray ***            \n"
        BANNER += "\n>----------------------------------------<\n"

        # Add version
        space = " " * (15 - len("version"))
        BANNER += "\n   > version%s:  %s" % (space, version)

        _args = vars(args)
        for arg in _args:
            if arg.startswith("_") or arg == "adfs_urls":
                continue
            if _args[arg]:

                # Handle conditions to not show certain data
                # 1) Don't show `rate` if both enum and spray are disabled or
                #    the user specified validation only
                if arg == "rate" and (
                    (not args.enum and not args.spray) or args.validate
                ):
                    continue
                # 2) Don't show `enum_module` if enum is disabled
                if arg == "enum_module" and not args.enum:
                    continue
                # 3) Don't show the following if spray is disabled:
                #    spray_module, count, lockout, safe
                if (
                    arg == "spray_module"
                    or arg == "count"
                    or arg == "lockout"
                    or arg == "safe"
                ) and not args.spray:
                    continue
                # 4) Don't show notification settings if spray is disabled
                if arg in {"telegram_token", "telegram_chat_id"} and not args.spray:
                    continue

                value = _args[arg]
                space = " " * (15 - len(arg))

                # Handle conditions to show custom values
                # 1) If a user agents file is provided, show 'random' instead
                #    of full list of agents - include number of random agents
                if arg == "useragents" and args.useragents:
                    value = f"random ({len(_args[arg])})"
                # 2) Redact sensitive notification secrets in banner output.
                if arg in {"telegram_token", "telegram_chat_id"}:
                    value = "configured"

                BANNER += "\n   > %s%s:  %s" % (arg, space, str(value))

                # Add data meanings
                if arg == "count":
                    BANNER += " passwords/spray"

                if arg == "lockout":
                    BANNER += " minutes"

                if arg == "rate":
                    BANNER += " threads"

                if arg == "safe":
                    BANNER += " locked accounts"

                if arg == "timeout":
                    BANNER += " seconds"

        # Add timestamp for start of spray
        space = " " * (15 - len("start"))
        start_t = datetime.today().strftime("%Y-%m-%d %H:%M:%S")
        BANNER += "\n   > start%s:  %s" % (space, start_t)

        BANNER += "\n"
        BANNER += "\n>----------------------------------------<\n"

        print(BANNER)
