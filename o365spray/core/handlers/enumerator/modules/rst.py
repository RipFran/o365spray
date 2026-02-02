#!/usr/bin/env python3

import logging
import time
from bs4 import BeautifulSoup  # type: ignore

from o365spray.core.handlers.enumerator.modules.base import EnumeratorBase
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)


class EnumerateModule_rst(EnumeratorBase):
    """OneDrive Enumeration module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(EnumerateModule_rst, self).__init__(*args, **kwargs)

    def _enumerate(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users via the Office 365 RST SOAP API

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

            # Update content type for SOAP XML
            # Updated: copy headers to avoid cross-request mutation.
            headers = Defaults.HTTP_HEADERS.copy()
            headers["Content-Type"] = "application/soap+xml"

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/rst2.srf"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = "https://login.microsoftonline.com/rst2.srf"

            data = f"""
<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <S:Header>
        <wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To>
        <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo">
            <ps:BinaryVersion>5</ps:BinaryVersion>
            <ps:HostingApp>Managed IDCRL</ps:HostingApp>
        </ps:AuthInfo>
        <wsse:Security>
            <wsse:UsernameToken wsu:Id="user">
                <wsse:Username>{user}</wsse:Username>
                <wsse:Password>{password}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </S:Header>
    <S:Body>
        <wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0">
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
            <wsp:AppliesTo>
                <wsa:EndpointReference>
                    <wsa:Address>online.lync.com</wsa:Address>
                </wsa:EndpointReference>
            </wsp:AppliesTo>
            <wsp:PolicyReference URI="MBI"></wsp:PolicyReference>
        </wst:RequestSecurityToken>
    </S:Body>
</S:Envelope>
"""

            # Updated: include retry configuration for transient failures.
            response = self._send_request(
                "post",
                url,
                data=data.strip(),
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
            xml = BeautifulSoup(response.content, "xml")

            # If a valid security token is returned, the credentials were
            # valid
            if xml.find("wsse:BinarySecurityToken"):
                if self.writer:
                    self.valid_writer.write(email)
                self.VALID_ACCOUNTS.append(email)
                # Updated: richer CLI output for valid responses.
                self._log_enum_result(
                    "VALID",
                    email,
                    status=status,
                    reason=response.reason,
                    detail="RST security token issued",
                )

            # Attempt to parse an AADSTS error
            elif xml.find("psf:text"):
                error = xml.find("psf:text").text
                # User not found error is an invalid user
                if "AADSTS50034" in error:
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
                        detail="RST indicates valid user",
                    )

            # Unknown response -> invalid user
            else:
                # Updated: richer CLI output for invalid responses.
                self._log_enum_result(
                    "INVALID",
                    email,
                    status=status,
                    reason=response.reason,
                    detail="RST rejected or unknown response",
                )

        except Exception as e:
            # Updated: surface request failures with context.
            logging.warning(
                f"[{text_colors.WARNING}REQUEST_FAILED{text_colors.ENDC}] "
                f"{user} | module={self.module_tag} | error={type(e).__name__}: {e}"
            )
            pass
