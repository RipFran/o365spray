#!/usr/bin/env python3

import logging
import time

from o365spray.core.handlers.enumerator.modules.base import EnumeratorBase
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)


class EnumerateModule_office(EnumeratorBase):
    """Office Enumeration module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(EnumerateModule_office, self).__init__(*args, **kwargs)

    def _enumerate(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users on Microsoft using Office.com

        Note: It appears the pre-request is no longer required to retrieve
              the specific header data

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
            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{user} -> {email}" if user != email else email
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Build request data
            data = {
                "isOtherIdpSupported": True,
                "isRemoteNGCSupported": False,
                "checkPhones": True,
                "isCookieBannerShown": False,
                "isFidoSupported": False,
                "username": email,
            }

            # Grab default headers
            # Updated: copy headers to avoid cross-request mutation.
            headers = Defaults.HTTP_HEADERS.copy()

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/common/GetCredentialType?mkt=en-US"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"

            # Updated: include retry configuration for transient failures.
            response = self._send_request(
                "post",
                url,
                json=data,
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
            body = response.json()

            if status == 200:
                # This enumeration is only valid if the user has DesktopSSO
                # enabled
                # https://github.com/Gerenios/AADInternals/blob/master/KillChain_utils.ps1#L93
                if "DesktopSsoEnabled" in body["EstsProperties"]:
                    is_desktop_sso = body["EstsProperties"]["DesktopSsoEnabled"]
                    if not is_desktop_sso:
                        logging.info(f"Desktop SSO disabled. Shutting down...")
                        self.exit = True
                        return self.shutdown()

                if_exists_result = int(body["IfExistsResult"])
                is_request_throttled = int(body["ThrottleStatus"])

                # Check if the requests are being throttled and shutdown
                # if so
                if is_request_throttled != 0 or if_exists_result == 2:
                    # Updated: log throttling with context.
                    logging.info(
                        f"Requests are being throttled. Shutting down... (module={self.module_tag})"
                    )
                    self.exit = True
                    return self.shutdown()

                # It appears that both 0 and 6 response codes indicate a valid user
                # whereas 5 indicates the use of a different identity provider -- let's
                # account for that.
                # https://www.redsiege.com/blog/2020/03/user-enumeration-part-2-microsoft-office-365/
                # https://warroom.rsmus.com/enumerating-emails-via-office-com/
                if if_exists_result in [0, 6]:
                    if self.writer:
                        self.valid_writer.write(email)
                    self.VALID_ACCOUNTS.append(email)
                    # Updated: richer CLI output for valid responses.
                    self._log_enum_result(
                        "VALID",
                        email,
                        status=status,
                        reason=response.reason,
                        detail=f"IfExistsResult={if_exists_result}",
                    )

                # This will not be added to our list of valid users as we want to avoid
                # hitting personal accounts
                elif if_exists_result == 5:
                    if self.writer:
                        if not self.found_idp:
                            self.found_idp = True
                        self.idp_writer.write(email)
                    # Updated: richer CLI output for different IDP results.
                    self._log_enum_result(
                        "DIFFIDP",
                        email,
                        status=status,
                        reason=response.reason,
                        detail="Different identity provider",
                    )

                else:
                    # Updated: richer CLI output for invalid responses.
                    self._log_enum_result(
                        "INVALID",
                        email,
                        status=status,
                        reason=response.reason,
                        detail=f"IfExistsResult={if_exists_result}",
                    )

            else:
                # Updated: richer CLI output for invalid responses.
                self._log_enum_result(
                    "INVALID",
                    email,
                    status=status,
                    reason=response.reason,
                    detail="Office GetCredentialType rejected",
                )

        except Exception as e:
            # Updated: surface request failures with context.
            logging.warning(
                f"[{text_colors.WARNING}REQUEST_FAILED{text_colors.ENDC}] "
                f"{user} | module={self.module_tag} | error={type(e).__name__}: {e}"
            )
            pass
