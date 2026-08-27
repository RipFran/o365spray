#!/usr/bin/env python3

import argparse
import importlib
import logging

from o365spray.core.utils import Helper, text_colors


def validate(args: argparse.Namespace) -> argparse.Namespace:
    """Validate every distinct domain derived from the supplied addresses.

    Validation is all-or-nothing for enum/spray actions: invalid domains are
    reported and no subset of the operator's input is silently discarded.
    """
    module = f"o365spray.core.handlers.validator.modules.{args.validate_module}"
    module_class = f"ValidateModule_{args.validate_module}"

    try:
        Validator = getattr(importlib.import_module(module), module_class)
    except Exception as exc:
        logging.error(f"ERROR: Invalid module\n{exc}")
        (args.enum, args.spray) = (False, False)
        return args

    validator = Validator(
        timeout=args.timeout,
        proxy=args.proxy,
        sleep=args.sleep,
        jitter=args.jitter,
        useragents=args.useragents,
    )

    invalid_domains = []
    args.adfs_urls = {}
    for domain in args.domains:
        logging.info(f"Validating: {domain}")
        valid, adfs_url = validator.validate(domain)

        if not valid:
            invalid_domains.append(domain)
            logging.info(
                f"[{text_colors.FAIL}FAILED{text_colors.ENDC}] "
                f"The following domain does not appear to be using O365: {domain}"
            )
        elif adfs_url:
            args.adfs_urls[domain] = adfs_url
            logging.info(
                f"[{text_colors.WARNING}WARNING{text_colors.ENDC}] "
                "The following domain appears to be using O365, but is "
                f"Federated: {domain}"
            )
            logging.info(f"ADFS AuthURL:\n{adfs_url}")
        else:
            logging.info(
                f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] "
                f"The following domain appears to be using O365: {domain}"
            )

    if invalid_domains:
        logging.error(
            "Domain validation failed for %d domain(s); enum/spray will not run: %s",
            len(invalid_domains),
            ", ".join(invalid_domains),
        )
        (args.enum, args.spray) = (False, False)
        return args

    if args.validate:
        (args.enum, args.spray) = (False, False)
        return args

    federated_domains = set(args.adfs_urls)
    all_domains = set(args.domains)

    # Preserve the existing prompt for a homogeneous federated scope. Mixed
    # scopes retain the explicit module because managed domains lack ADFS URLs.
    if federated_domains and federated_domains == all_domains:
        if args.enum and args.enum_module != "oauth2":
            logging.info("\n")
            prompt = (
                "[ ? ]\tSwitch to the oAuth2 module for user enumeration against "
                "Federated Realms [Y/n] "
            )
            if Helper.prompt_question(prompt)[0] == "y":
                args.enum_module = "oauth2"
            else:
                logging.info("Disabling user enumeration against Federated Realms.")
                args.enum = False

        if args.spray and args.spray_module != "adfs":
            logging.info("\n")
            prompt = "[ ? ]\tSwitch to the ADFS module for password spraying [Y/n] "
            if Helper.prompt_question(prompt)[0] == "y":
                args.spray_module = "adfs"
    elif federated_domains:
        logging.warning(
            "Mixed managed/federated domain scope detected. Keeping the selected "
            "modules; ADFS endpoints will only be used for matching domains."
        )

    if args.spray and args.spray_module == "adfs":
        missing = sorted(all_domains - federated_domains)
        if missing:
            logging.error(
                "The ADFS spray module has no discovered AuthURL for: %s",
                ", ".join(missing),
            )
            args.spray = False

    return args
