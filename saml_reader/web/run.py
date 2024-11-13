"""This is the main file for running the web app. Running this script directly is intended
to be used for running in debug mode. This script takes a couple of arguments:

- `--local` to run using localhost as the host/IP address to serve on. The default is `0.0.0.0/0`.
- `--using-debugger` disables Dash/Flask interactive debug mode. Use this when attaching a Python debugger.
"""

from functools import partial
import sys
from threading import Thread

# `server` must be imported for running this app with gunicorn
from saml_reader.web.app import app, server

# Loads all page payouts and callback functions
import saml_reader.web.layouts
import saml_reader.web.callbacks


# Set app settings
app.title = "SAML Reader"
app.config.suppress_callback_exceptions = True
# This sets the template for all pages
app.layout = saml_reader.web.layouts.index.layout


def run_web_app(host="localhost", port=8050, server_timeout=None, **options):
    """Hook to run web server.

    Args:
        host (str, optional): Hostname or IP address on which to server the web app.
            Defaults to "localhost".
        port (int, optional): Port on which to serve the web app. Defaults to 8050.
        server_timeout (int, optional): number of seconds to run the web server before automatically
            shutting it down as a security measure.
        **options (optional): Keyword arguments sent to underlying Dash/Flask launcher.
    """
    server_func = partial(app.run_server, host=host, port=port, **options)
    if server_timeout is not None:
        # Avoiding spawning extra thread in case bad clash with gunicorn
        thread = Thread(target=server_func)
        thread.daemon = True
        thread.start()
        try:
            thread.join(timeout=server_timeout)
            print("\nServer timeout reached. Stopping server.")
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received. Stopping server.")
    else:
        server_func()


if __name__ == "__main__":
    # Defaults
    host = "0.0.0.0"
    use_flask_debug_mode = True

    # Checking command line arguments
    # TODO: Maybe replace this with argparse
    if len(sys.argv) > 1:
        if "--local" in sys.argv:
            host = "localhost"
        if "--using-debugger" in sys.argv:
            use_flask_debug_mode = False

    options = {"debug": use_flask_debug_mode, "dev_tools_ui": use_flask_debug_mode}
    run_web_app(host, **options)
