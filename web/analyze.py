import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from saml_reader.text_reader import DataTypeInvalid
from saml_reader.cli import run_analysis, OutputStream


def analyze_layout(app):
    data_info_layout = html.Div([
        html.Label(
            children="Select Data Type:",
            style={
                'display': 'inline-block',
                'margin-right': '10px',
                'vertical-align': 'middle'
            }
        ),
        dcc.Dropdown(
            id='saml_data_type',
            options=[
                {'label': 'xml', 'value': 'xml'},
                {'label': 'base64', 'value': 'base64'},
                {'label': 'har', 'value': 'har'}
            ],
            value='xml',
            placeholder="Select data type",
            style={
                'width': '100px',
                'display': 'inline-block',
                'margin-right': '10px',
                'vertical-align': 'middle'
            }
        ),
        html.Button(
            id="submit_saml_data",
            children="Analyze",
            style={
                'display': 'inline-block',
                'vertical-align': 'middle'
            }
        )
    ])

    input_box = dcc.Textarea(
        id='saml_input',
        value="Paste SAML data here",
        style={
            'width': '50%',
            'height': 300
        }
    )

    output_box = dcc.Textarea(
        id='analysis_output',
        value="Your analysis will appear here",
        contentEditable=False,
        style={
            'width': '50%',
            'height': 300
        }
    )

    @app.callback(
        Output('analysis_output', 'value'),
        [Input('submit_saml_data', 'n_clicks'),
         Input('saml_input', 'n_submit')],
        [State('saml_data_type', 'value'),
         State('saml_input', 'value')]
    )
    def submit_analysis(n_clicks, n_submit, data_type, saml_data):
        if (n_clicks is None) and (n_submit is None) or saml_data == "":
            raise PreventUpdate

        return submit_analysis_to_backend(data_type, saml_data)

    layout = html.Div([
        data_info_layout,
        html.Br(),
        input_box,
        html.Br(),
        output_box
    ])
    return layout


def submit_analysis_to_backend(data_type, saml_data):
    report = OutputStream()

    run_analysis(
        input_type=data_type,
        source='raw',
        raw_data=saml_data,
        print_analysis=True,
        print_summary=True,
        output_stream=report.print
    )

    return report.getvalue()
