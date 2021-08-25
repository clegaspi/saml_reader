import dash_core_components as dcc
import dash_html_components as html


def build_layout():
    route = dcc.Location(id='url', refresh=False)

    layout_menu = html.Div(
        children=[dcc.Link('What is this?', href='/home'),
                html.Span(' • '),
                dcc.Link('Analyze SAML', href='/analyze')
                ])
    # header
    page_template_layout = html.Div(
        children=[route,
                html.Div([html.H3("SAML Reader"), layout_menu, html.Br()],
                        style={'textAlign': 'center'}),
                html.Div(id='page-content')],
        style={'marginLeft': 200, 'marginRight': 200, 'marginTop': 30})

    return page_template_layout

layout = build_layout()
