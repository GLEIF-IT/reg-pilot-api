# -*- encoding: utf-8 -*-
"""
Regulation portal service
regps.cli.regps.commands module

regulation portal servicecommand line interface
"""

import argparse

# from regps.app import service

d = "Runs regulation portal service\n"
d += "\tExample:\nregps\n"
parser = argparse.ArgumentParser(description=d)
# parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument(
    "-V",
    "--version",
    action="version",
    version="0.0.1",
    help="Prints out version of script runner.",
)
parser.add_argument(
    "-p",
    "--port",
    action="store",
    default=4902,
    help="Local port number the HTTP server listens on. Default is 4902.",
)
