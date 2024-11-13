"""Template for the web app. Subpages are loaded into the `page-content` Div."""

from dash import dcc, html


def build_layout():
    """
    Builds layout for page.

    Returns:
        an HTML component such as html.Div
    """
    route = dcc.Location(id="url", refresh=False)

    layout_menu = html.Div(
        children=[
            dcc.Link("What is this?", href="/home"),
            html.Span(" • "),
            dcc.Link("Analyze SAML", href="/analyze"),
        ]
    )
    # header
    page_template_layout = html.Div(
        children=[
            route,
            html.Div(
                [html.H3("SAML Reader"), layout_menu, html.Br()],
                style={"textAlign": "center"},
            ),
            html.Div(id="page-content"),
        ],
        style={"marginLeft": 200, "marginRight": 200, "marginTop": 30},
    )

    return page_template_layout


"""Page layout"""
layout = build_layout()
