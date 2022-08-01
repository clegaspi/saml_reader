"""Layout for Home page
"""

from dash import dcc, html


def build_layout():
    """
    Builds layout for page.

    Returns:
        an HTML component such as html.Div
    """
    layout = html.Div([
        dcc.Markdown("""
        Hi! Welcome to the SAML Reader web app. Please select one of the available tools
        from the list above.

        At present, it's just the analyzer, but more to come in the future!
        """)
    ])
    return layout

"""Page layout"""
layout = build_layout()
