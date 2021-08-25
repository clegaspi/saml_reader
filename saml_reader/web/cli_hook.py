import argparse
import sys
import webbrowser
from threading import Timer
from functools import partial

from saml_reader import __version__
from saml_reader.web.index import run_web_app


def web_cli(cl_args):
    """
    Entrypoint for the command line interface to start the web app. Handles parsing command line arguments.

    Args:
        cl_args (iterable): Command-line arguments. Possibilities:
            - `--host`: optional argument. Specifying will change hostname/IP address where web app is served.
            - `--port`: optional argument. Specifying will change the port where the web app is served.
            - `--no-open-browser`: optional argument. Specifying will suppress opening the web browser automatically.
            - `--version`: optional argument. Displays version information and exits.
            - `--help`: optional argument. Displays help information and exits.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(prog="SAML Reader Web App",
                                     description='Start the SAML Reader web app '
                                                 'to analyze and diagnose '
                                                 'federated authentication issues.')
    parser.add_argument('--host',
                        dest='host', action='store', required=False, default="localhost",
                        help='specify host/IP address where the web app is listening. Default: localhost')
    parser.add_argument('--port',
                        dest='port', action='store', required=False, default="8050",
                        help='specify port where the web app is listening. Default: 8050')
    parser.add_argument('--no-open-browser',
                        dest='no_open_browser', action='store_true', required=False,
                        help='suppress opening the web browser automatically. Otherwise, the default browser ' + \
                            'will open automatically to the webpage.')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')

    parsed_args = parser.parse_args(cl_args)

    # TODO: This is kind of crude, but it works. Any "better" way of opening the browser after
    #       the web app has started

    web_address = f"http://{parsed_args.host}:{parsed_args.port}/"

    if not parsed_args.no_open_browser:
        Timer(2, partial(webbrowser.open, web_address)).start()
        print("Browser should open shortly after server starts. If webpage does not load, refresh the page.")
    else:
        print(f"Open browser to {web_address} once the server starts.")
    print("NOTE: Use Ctrl+C to stop the web server when finished. Closing the webpage will not stop the server!\n")
    run_web_app(host=parsed_args.host, port=parsed_args.port)
    

def start_web_app_from_cli():
    web_cli(sys.argv[1:])