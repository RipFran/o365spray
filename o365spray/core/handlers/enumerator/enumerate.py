#!/usr/bin/env python3

import argparse
import asyncio
import importlib
import logging
import signal
import sys
from pathlib import Path

from o365spray.core.utils import (
    Defaults,
    DefaultFiles,
    Helper,
    add_file_logger,
    remove_file_logger,
)


def enumerate(args: argparse.Namespace, output_dir: str) -> object:
    """Run user enumeration against a given domain.

    Arguments:
        args: namespace containing command line arguments
        output_dir: name of output directory to write results to

    Returns:
        initialized Enumerator module instance

    Raises:
        KeyboardInterrupt: generic catch so that our signal handler
          can do its job
    """
    # Create enum directory
    output_directory = f"{output_dir}/enum/"
    Path(output_directory).mkdir(parents=True, exist_ok=True)

    # Updated: explicitly create/set event loop for Python 3.10+ compatibility.
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    # Updated: attach per-enumeration raw CLI log file handler.
    raw_log_handler = add_file_logger(
        f"{output_directory}{DefaultFiles.ENUM_LOG_FILE}",
        args.debug,
    )

    # Support both username(s) and a username file being provided
    password = "Password1" if not args.password else args.password.split(",")[0]
    userlist = []
    if args.username:
        userlist += args.username.split(",")
    if args.userfile:
        userlist += Helper.get_list_from_file(args.userfile)

    if args.resume and args.spray:
        resume_file = f"{args.resume}.enum"
    else:
        resume_file = args.resume or f"{output_directory}{DefaultFiles.ENUM_RESUME}"
    logging.info(f"Enumeration checkpoint file: '{resume_file}'")

    if args.resume and Path(resume_file).is_file():
        resume_user = Helper.get_last_nonempty_line_from_file(resume_file)
        if resume_user:
            original_count = len(userlist)
            userlist, skipped, found = Helper.trim_list_to_resume_value(
                userlist,
                resume_user,
            )
            if found:
                logging.info(
                    "Resuming enumeration from '%s' (skipped %d users).",
                    resume_user,
                    skipped,
                )
            else:
                logging.warning(
                    "Resume user '%s' was not found in the provided user list. "
                    "Starting from the beginning.",
                    resume_user,
                )
            logging.debug(
                "Enumeration resume scope: %d/%d users remaining.",
                len(userlist),
                original_count,
            )
    elif args.resume:
        logging.warning(
            "Resume checkpoint '%s' was not found. Starting from the beginning.",
            resume_file,
        )

    logging.info(f"Running user enumeration against {len(userlist)} potential users")

    # Attempt to import the defined module
    module = f"o365spray.core.handlers.enumerator.modules.{args.enum_module}"
    module_class = f"EnumerateModule_{args.enum_module}"

    try:
        Enumerator = getattr(importlib.import_module(module), module_class)
    except Exception as e:
        logging.error(f"ERROR: Invalid module\n{e}")
        return None

    enum = Enumerator(
        loop,
        output_dir=output_directory,
        timeout=args.timeout,
        proxy=args.proxy,
        workers=args.rate,
        poolsize=args.poolsize,
        writer=True,
        sleep=args.sleep,
        jitter=args.jitter,
        proxy_url=args.proxy_url,
        useragents=args.useragents,
        # Updated: pass retry configuration to enumeration modules.
        request_retries=args.retries,
        resume_file=resume_file,
    )

    def enum_signal_handler(signal, frame):
        """Signal handler for Enum routines.

        Arguments:
            signal: called signal
            frame: stack frame
        """
        enum.shutdown(key=True)
        print(Defaults.ERASE_LINE, end="\r")
        logging.info("\n")  # Blank line
        logging.info("Valid Accounts: %d" % len(enum.VALID_ACCOUNTS))
        sys.exit(0)

    # Add signal handler to handle ctrl-c interrupts
    signal.signal(signal.SIGINT, enum_signal_handler)
    signal.signal(signal.SIGTERM, enum_signal_handler)

    try:
        loop.run_until_complete(
            enum.run(
                userlist,
                password=password,
                domain=args.domain,
            )
        )

        # Gracefully shutdown if it triggered internally
        if not enum.exit:
            enum.shutdown()
        logging.info("Valid Accounts: %d" % len(enum.VALID_ACCOUNTS))

        loop.run_until_complete(asyncio.sleep(0.250))
        loop.close()

    except KeyboardInterrupt:
        pass
    finally:
        # Updated: remove file handler to keep logs scoped per action.
        remove_file_logger(raw_log_handler)

    return enum
