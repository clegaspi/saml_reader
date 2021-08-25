import sys

from saml_reader.web.app import app
import saml_reader.web.layouts
import saml_reader.web.callbacks


app.title = "SAML Reader"
app.config.suppress_callback_exceptions = True
# This sets the template for all pages
app.layout = saml_reader.web.layouts.index.layout


def run_web_app(host="localhost", port=8050, **options):
    app.run_server(host=host, port=port, **options)

if __name__ == '__main__':
    host = "0.0.0.0"
    use_flask_debug_mode = True
    if len(sys.argv) > 1:
        if '--local' in sys.argv:
            host = "localhost"
        if '--using-debugger' in sys.argv:
            use_flask_debug_mode = False

    options = {"debug": use_flask_debug_mode, "dev_tools_ui": use_flask_debug_mode}
    run_web_app(host, **options)
