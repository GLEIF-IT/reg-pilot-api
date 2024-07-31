# -*- encoding: utf-8 -*-
"""
Regulation portal service
regps.app.cli.commands module

"""
import logging
import multicommand
import regps.app.fastapi_app as fastapi_app
import commands


def main():
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    if not hasattr(args, 'handler'):
        parser.print_help()
        return

    try:
        logging.info("******* Starting regulation portal service for %s listening: http/%s "
                     ".******", args.http)

        fastapi_app.main()

        logging.info("******* Ended reg portal service %s listening: http/%s"
                     ".******", args.http)


    except Exception as ex:
        logging.error(f"ERR: {ex}")
        return -1


if __name__ == "__main__":
    main()
