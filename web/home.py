import dash_core_components as dcc
import dash_html_components as html


def home_layout(app):
    layout = html.Div([
        html.Label("Hi! Welcome to the SAML reader web app. Please select one of the available tools.")
    ])
    return layout
