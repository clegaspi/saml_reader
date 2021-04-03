import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
# from flask_caching import Cache
# import plotly.io as pio

from web.home import home_layout
from web.analyze import analyze_layout

app = dash.Dash(__name__)
server = app.server
# app.config.suppress_callback_exceptions = True  # TODO: remove this?
app.scripts.config.serve_locally = True
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

#CORRELATE_LAYOUT = correlate_layout(app)
#INTERACTIVE_LAYOUT = interactive_layout(app)
#EXPLORE_LAYOUT = explore_layout(app)
#REFS_LAYOUT = refs_layout(app)
#define_plot_callbacks(app)

# routing, current routes defined are:
# / for home page
# /model for model summary
# /model/model_name for information on that model
# /property for property summary
# /property/property_name for information on that property

HOME_LAYOUT = home_layout(app)
ANALYZE_LAYOUT = analyze_layout(app)


@app.callback(Output('page-content', 'children'),
              [Input('url', 'pathname'),
               Input('url', 'search')])
def display_page(pathname, search):
    """
    Args:
      pathname:
      search:
    Returns:
    """

    if pathname == '/analyze':
        return ANALYZE_LAYOUT

    return HOME_LAYOUT


if __name__ == '__main__':
    # app.run_server(debug=False, dev_tools_ui=True)
    app.run_server(debug=False, dev_tools_ui=True)
