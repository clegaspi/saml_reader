import argparse
import sys

import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output

from saml_reader.web.app import app
from saml_reader.web.pages import home, analyze

# app.scripts.config.serve_locally = True
app.title = "SAML Reader"
route = dcc.Location(id='url', refresh=False)

layout_menu = html.Div(
    children=[dcc.Link('What is this?', href='/home'),
              html.Span(' • '),
              dcc.Link('Analyze SAML', href='/analyze')
              ])
# header
app.layout = html.Div(
    children=[route,
              html.Div([html.H3(app.title), layout_menu, html.Br()],
                       style={'textAlign': 'center'}),
              html.Div(id='page-content')],
    style={'marginLeft': 200, 'marginRight': 200, 'marginTop': 30})

# Initialize page layouts to register callbacks

# Uncomment this if you define callbacks for objects that don't exist yet
app.config.suppress_callback_exceptions = True


@app.callback(Output('page-content', 'children'),
              [Input('url', 'pathname'),
               Input('url', 'search')])
def display_page(pathname, parameters):
    """
    Args:
      pathname:
      parameters:
    Returns:
    """

    if pathname == '/analyze':
        return analyze.layout

    return home.layout


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
