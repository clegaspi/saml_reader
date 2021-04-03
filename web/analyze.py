from contextlib import redirect_stdout
from io import StringIO

import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from saml_reader.text_reader import TextReader, DataTypeInvalid
from saml_reader.validation.mongo import MongoVerifier
from saml_reader.cli import display_validation_results, display_summary


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

        return run_analysis(data_type, saml_data)

    layout = html.Div([
        data_info_layout,
        html.Br(),
        input_box,
        html.Br(),
        output_box
    ])
    return layout


def run_analysis(data_type, saml_data):
    report = [
        f"SAML READER",
        f"----------------------",
        f"Parsing SAML data..."
    ]

    try:
        saml_parser = TextReader(data_type, saml_data)
    except DataTypeInvalid:
        if data_type == 'har':
            report.append("We could not find the correct data in the HAR data specified.\n"
                          "Check to make sure that the input data is of the correct type.")
        else:
            report.append(f"The input data does not appear to be the specified input type '{data_type}'.\n"
                          f"Check to make sure that the input data is of the correct type.")
        return "\n".join(report)

    for msg in saml_parser.get_errors():
        report.append(msg)

    if not saml_parser.saml_is_valid():
        return "\n".join(report)

    report.append("------------")

    verifier = MongoVerifier(
        saml_parser.get_saml(),
        saml_parser.get_certificate()
    )

    verifier.validate_configuration()

    output = StringIO()
    with redirect_stdout(output):
        display_validation_results(verifier)
        display_summary(verifier)

    report.append(output.getvalue())

    return "\n".join(report)
