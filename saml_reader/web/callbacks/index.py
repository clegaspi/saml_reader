
from dash.dependencies import Input, Output

from saml_reader.web.app import app
from saml_reader.web.layouts import home, analyze

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
