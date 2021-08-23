from logging import disable
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
from dash_html_components.Label import Label

from saml_reader.web.app import app
from saml_reader.cli import run_analysis, OutputStream


def build_layout():
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

    warning_text = dcc.Markdown(
        """
        ### SAML Data
        
        *Please note:* It is not recommended to paste HAR data here, because HAR files are usually quite large 
        in size and you can crash your browser. Use the CLI instead.
        """
    )

    input_box = dcc.Textarea(
        id='saml_input',
        placeholder="Paste SAML data here",
        style={
            'width': "100%",
            'height': 300
        }
    )

    output_box_label = html.Label("Analysis output:")

    output_box = dcc.Textarea(
        id='analysis_output',
        value="Your analysis will appear here",
        contentEditable=False,
        style={
            'width': "100%",
            'height': 300
        }
    )

    left_side = html.Div(
        children=[
            warning_text,
            html.Br(),
            data_info_layout,
            html.Br(),
            input_box,
            html.Br(),
            output_box_label,
            html.Br(),
            output_box
        ],
        style={
            "width": "50%",
            "float": "left",
            "margin-right": "4%"
        })

    rs_top_text = dcc.Markdown(
        """
        ### Comparison values
        
        If you would like to enter comparison values, please do so below.
        """
    )

    comparison_fields = html.Div([
        html.Label(
            "User's First Name",
            style={"width": "20%"}),
        dcc.Input(
            placeholder="Sam",
            type='text',
            value='',
            id='compare-first-name',
            style={"width": "300px"}
        ),
        html.Br(),
        html.Label(
            "User's Last Name",
            style={"width": "20%"}),
        dcc.Input(
            placeholder="Ell",
            type='text',
            value='',
            id='compare-last-name',
            style={"width": "300px"}
        ),
        html.Br(),
        html.Label(
            "User's E-mail Address",
            style={"width": "20%"}),
        dcc.Input(
            placeholder="sam.ell@mydomain.com",
            type='text',
            value='',
            id='compare-email',
            style={"width": "300px"}
        ),
        html.Br(),
        html.Label(
            "Audience URI",
            style={"width": "20%"}),
        dcc.Input(
            placeholder="https://www.okta.com/saml2/service-provider/...",
            type='text',
            value='',
            id='compare-audience',
            style={"width": "300px"}
        ),
        html.Br(),
        html.Label(
            "Assertion Consumer Service URL",
            style={"width": "20%"}),
        dcc.Input(
            placeholder="https://auth.mongodb.com/sso/saml2/...",
            type='text',
            value='',
            id='compare-acs',
            style={"width": "300px"}
        ),
        html.Br(),
        html.Label(
            "Issuer URI",
            style={"width": "20%"}),
        dcc.Input(
            placeholder="idp-entity-id",
            type='text',
            value='',
            id='compare-issuer',
            style={"width": "300px"}
        ),
        html.Br(),
        html.Label(
            "Encryption Type"
        ),
        html.Br(),
        dcc.Dropdown(
            placeholder="SHA-?",
            options=[{"label": x, "value": x} for x in ['SHA-256', 'SHA-1']],
            value='',
            id='compare-encryption',
            style={
                "width": "300px",
                "display": "inline-block"}
        ),
        html.Br(),
        html.Label(
            "SAML Certificate Expiration Date (MM/DD/YYYY)"
        ),
        html.Br(),
        dcc.DatePickerSingle(
            placeholder='Select Date',
            id='compare-cert-expiration',
            clearable=True,
            display_format="MM/DD/YYYY",
            style={
                "width": "500px"
            }
        ),
        html.Br(),
        html.Label(
            "Associated Domains"
        ),
        html.Br(),
        dcc.Input(
            placeholder="mydomain.com",
            type='text',
            value='',
            id='domain-name-text',
            style={"width": "300px"}
        ),
        html.Button(
            "Add",
            id='submit_add_domain',
            style={"display": "inline-block", "vertical-align": "middle"}
        ),
        html.Br(),
        html.Div(
            id='compare-domain-list',
            children=[],
            style={"width": "300px"}
        ),
        html.Br(),
        dcc.Checklist(
            id='compare-role-mapping-expected',
            options=[
                {"label": "Role mapping expected?", "value": "Yes"}
            ],
            inputStyle={
                "margin-right": "1em"
            }
        ),
        html.Div(
            id='div-role-mapping-groups',
            hidden=True,
            children=[
                html.Label(
                    "Expected Group Names"
                ),
                html.Br(),
                dcc.Input(
                    placeholder="Group Name",
                    type='text',
                    value='',
                    id='group-name-text',
                    style={"width": "300px"}
                ),
                html.Button(
                    "Add",
                    id='submit_add_group',
                    style={"display": "inline-block", "vertical-align": "middle"}
                ),
                html.Br(),
                html.Div(
                    id='compare-domain-list',
                    children=[],
                    style={"width": "300px"}
                )
            ]
        )
    ])

    right_side = html.Div(
        children=[
            rs_top_text,
            html.Br(),
            comparison_fields
        ],
        style={
            "flex-grow": 1
        }
    )

    layout = html.Div([
        left_side, right_side
    ], className="row")
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


layout = build_layout()


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

@app.callback(
    Output('div-role-mapping-groups', 'hidden'),
    [Input('compare-role-mapping-expected', 'value')]
)
def toggle_role_mapping_entry(role_mapping_expected):
    if "Yes" in role_mapping_expected or []:
        return False
    return True