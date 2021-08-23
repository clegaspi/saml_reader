import dash_core_components as dcc
import dash_html_components as html

from saml_reader.web.app import app

def build_layout():
    layout = html.Div([
        dcc.Markdown("""
        Hi! Welcome to the SAML Reader web app. Please select one of the available tools
        from the list above.
        """)
    ])
    return layout

layout = build_layout()
