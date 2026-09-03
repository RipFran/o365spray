import asyncio
import io
import tempfile
import types
import unittest
from argparse import Namespace
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from o365spray.__main__ import parse_args
from o365spray.core.handlers.enumerator.modules.base import EnumeratorBase
from o365spray.core.handlers.sprayer.modules.base import SprayerBase
from o365spray.core.handlers.validator.validate import validate
from o365spray.core.utils import Helper


class RecordingEnumerator(EnumeratorBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = []

    def _enumerate(self, domain, user, password="Password1"):
        self.calls.append((domain, user, password))


class RecordingSprayer(SprayerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = []

    def _spray(self, domain, user, password):
        self.calls.append((domain, user, password))


class EmailValidationTests(unittest.TestCase):
    def test_normalizes_only_the_domain(self):
        self.assertEqual(
            Helper.normalize_email("Alice.Smith@EXAMPLE.COM"),
            "Alice.Smith@example.com",
        )

    def test_rejects_incomplete_or_malformed_addresses(self):
        for value in ("alice", "@example.com", "alice@", "a@@example.com", "a@localhost"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Helper.normalize_email(value)

    def test_check_email_never_rewrites_a_domain(self):
        with self.assertRaises(ValueError):
            Helper.check_email("alice@example.org", "example.com")

    def test_paired_file_is_strict_and_preserves_mixed_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paired.txt"
            path.write_text(
                "Alice@EXAMPLE.COM:FirstPassword\n"
                "bob@example.org:Second:Password\n",
                encoding="utf-8",
            )
            self.assertEqual(
                Helper.get_paired_dict_from_file(str(path)),
                {
                    "Alice@example.com": ["FirstPassword"],
                    "bob@example.org": ["Second:Password"],
                },
            )

    def test_paired_file_reports_bad_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paired.txt"
            path.write_text("not-an-email-or-pair\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1"):
                Helper.get_paired_dict_from_file(str(path))


class CommandLineContractTests(unittest.TestCase):
    def test_parser_derives_all_domains_from_complete_addresses(self):
        argv = [
            "o365spray",
            "--enum",
            "-u",
            "Alice@EXAMPLE.COM,bob@example.org",
        ]
        with patch("sys.argv", argv):
            args = parse_args()
        self.assertEqual(args.domains, ["example.com", "example.org"])

    def test_parser_rejects_a_bare_username(self):
        with patch("sys.argv", ["o365spray", "--enum", "-u", "alice"]):
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parse_args()

    def test_removed_domain_option_is_not_accepted(self):
        argv = [
            "o365spray",
            "--enum",
            "-u",
            "alice@example.com",
            "--domain",
            "example.com",
        ]
        with patch("sys.argv", argv):
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parse_args()


class ResumeTests(unittest.TestCase):
    def test_resolves_an_existing_checkpoint_file(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "resume.txt"
            checkpoint.write_text("first@example.com\nlast@example.com\n")

            self.assertEqual(
                Helper.resolve_resume(
                    str(checkpoint), str(checkpoint), "default-resume.txt"
                ),
                (str(checkpoint), "last@example.com"),
            )

    def test_resolves_a_literal_dictionary_entry(self):
        self.assertEqual(
            Helper.resolve_resume(
                "last@EXAMPLE.COM", "last@EXAMPLE.COM", "default-resume.txt"
            ),
            ("default-resume.txt", "last@example.com"),
        )

    def test_preserves_a_new_custom_checkpoint_path(self):
        self.assertEqual(
            Helper.resolve_resume(
                "custom-resume.txt", "custom-resume.txt", "default-resume.txt"
            ),
            ("custom-resume.txt", None),
        )


class PerAddressRoutingTests(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()

    def tearDown(self):
        self.loop.close()

    def test_enumerator_routes_each_address_to_its_own_domain(self):
        enumerator = RecordingEnumerator(loop=self.loop, writer=False, workers=2)
        try:
            self.loop.run_until_complete(
                enumerator.run(["Alice@EXAMPLE.COM", "bob@example.org"])
            )
            self.assertCountEqual(
                enumerator.calls,
                [
                    ("example.com", "Alice@example.com", "Password1"),
                    ("example.org", "bob@example.org", "Password1"),
                ],
            )
        finally:
            enumerator.executor.shutdown(wait=True)

    def test_sprayer_routes_paired_passwords_per_address(self):
        sprayer = RecordingSprayer(
            loop=self.loop,
            userlist=["Alice@EXAMPLE.COM", "bob@example.org"],
            writer=False,
            workers=2,
        )
        try:
            self.loop.run_until_complete(
                sprayer.run(["FirstPassword", "SecondPassword"])
            )
            self.assertCountEqual(
                sprayer.calls,
                [
                    ("example.com", "Alice@example.com", "FirstPassword"),
                    ("example.org", "bob@example.org", "SecondPassword"),
                ],
            )
        finally:
            sprayer.executor.shutdown(wait=True)


class DomainValidationTests(unittest.TestCase):
    def test_each_derived_domain_is_validated_once(self):
        class FakeValidator:
            calls = []

            def __init__(self, **kwargs):
                pass

            def validate(self, domain):
                self.calls.append(domain)
                if domain == "example.org":
                    return True, "https://adfs.example.org/adfs/ls/?username=x"
                return True, None

        fake_module = types.SimpleNamespace(
            ValidateModule_getuserrealm=FakeValidator
        )
        args = Namespace(
            domains=["example.com", "example.org"],
            validate=True,
            enum=False,
            spray=False,
            enum_module="oauth2",
            spray_module="oauth2",
            validate_module="getuserrealm",
            timeout=25,
            proxy=None,
            sleep=0,
            jitter=0,
            useragents=None,
            adfs_urls={},
        )

        with patch(
            "o365spray.core.handlers.validator.validate.importlib.import_module",
            return_value=fake_module,
        ):
            result = validate(args)

        self.assertEqual(FakeValidator.calls, ["example.com", "example.org"])
        self.assertEqual(
            result.adfs_urls,
            {"example.org": "https://adfs.example.org/adfs/ls/?username=x"},
        )


if __name__ == "__main__":
    unittest.main()
