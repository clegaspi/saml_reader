"""Callbacks for page header"""

from dash.dependencies import Input, Output

from saml_reader.web.app import app
import saml_reader.web.layouts as pages


@app.callback(
    Output("page-content", "children"),
    [Input("url", "pathname"), Input("url", "search")],
)
def display_page(pathname, parameters):
    """
    Handles changing page contents when navigating to a new page.

    Args:
        pathname: the path portion of the URL where "/" is root
        parameters: query parameters passed to the URL

    Returns:
        html object
    """

    if pathname == "/analyze":
        return pages.analyze.layout

    return pages.home.layout
