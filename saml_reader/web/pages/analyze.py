from datetime import datetime

from saml_reader import cert
from saml_reader.validation.input_validation import MongoFederationConfig
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

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
            'height': 300,
            'resize': 'none'
        }
    )

    output_box_label = html.Label("Analysis output:")

    output_box = dcc.Textarea(
        id='analysis_output',
        placeholder="Your analysis will appear here",
        contentEditable=False,
        style={
            'width': "100%",
            'height': 300,
            'resize': 'none'
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
        
        If you would like to enter comparison values, please do so below."""
    )

    comparison_fields = html.Div([
        dcc.ConfirmDialogProvider(
            children=html.Button(
                "Reset All Values",
                style={"margin-bottom": "1em"}
            ),
            id='submit_reset_values',
            message='Are you sure you want to clear all values including SAML data?',
        ),
        html.Br(),
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
            id='submit-add-domain',
            style={"display": "inline-block", "vertical-align": "middle"}
        ),
        html.Br(),
        html.Div(
            id='div-domain-list',
            children=[
                dcc.Markdown(
                    "List of domains:",
                    style={"font-weight": "bold"}
                ),
                dcc.Checklist(
                    id="compare-domain-list",
                    options=[],
                    value=[],
                    inputStyle={
                        "margin-right": "1em"
                    },
                    labelStyle={
                        "font-weight": "normal",
                        "display": "block"
                    }
                )],
            style={
                "width": "400px", 
                "border": "1px solid black", 
                "display": "inline-block",
                "margin-bottom": "1em",
                "margin-top": "1em",
                "padding": "0.5em"
            }
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
                    id='submit-add-group',
                    style={"display": "inline-block", "vertical-align": "middle"}
                ),
                html.Br(),
                html.Div(
                    id='div-group-list',
                    children=[
                        dcc.Markdown(
                            "List of expected group names:",
                            style={"font-weight": "bold"}
                        ),
                        dcc.Checklist(
                            id="compare-group-list",
                            options=[],
                            value=[],
                            inputStyle={
                                "margin-right": "1em"
                            },
                            labelStyle={
                                "font-weight": "normal",
                                "display": "block"
                            }
                        )],
                    style={
                        "width": "400px", 
                        "border": "1px solid black", 
                        "display": "inline-block",
                        "margin-bottom": "1em",
                        "margin-top": "1em",
                        "padding": "0.5em"
                    }
                ),
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
    ], className="row", style={"margin-bottom": "3em"})
    return layout


def submit_analysis_to_backend(data_type, saml_data, comparison_data):
    report = OutputStream()

    run_analysis(
        input_type=data_type,
        source='raw',
        compare=True,
        compare_object=comparison_data,
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
     State('saml_input', 'value'),
     State('compare-first-name', 'value'),
     State('compare-last-name', 'value'),
     State('compare-email', 'value'),
     State('compare-audience', 'value'),
     State('compare-acs', 'value'),
     State('compare-issuer', 'value'),
     State('compare-encryption', 'value'),
     State('compare-cert-expiration', 'date'),
     State('compare-domain-list', 'value'),
     State('compare-role-mapping-expected', 'value'),
     State('compare-group-list', 'value')]
)
def submit_analysis(
        n_clicks, n_submit,
        data_type, saml_data,
        first_name, last_name, email, audience, acs, issuer, encryption,
        cert_expiration, domain_list, role_mapping_expected, group_list):
    if (n_clicks is None) and (n_submit is None) or saml_data == "":
        raise PreventUpdate

    comparison_data = {
        "firstName": first_name or None,
        "lastName": last_name or None,
        "email": email or None,
        "issuer": issuer or None,
        "acs": acs or None,
        "audience": audience or None,
        "encryption": encryption or None,
        "role_mapping_expected": "N"
    }
    if domain_list:
        comparison_data["domains"] = domain_list
    if role_mapping_expected:
        comparison_data["role_mapping_expected"] = "Y"
        if group_list:
            comparison_data["memberOf"] = group_list
    if cert_expiration:
        comparison_data["cert_expiration"] = datetime.strptime(cert_expiration, "%Y-%m-%d").strftime("%m/%d/%Y")
    try:
        comparison_object = MongoFederationConfig(**{k:v for k,v in comparison_data.items() if v is not None})
    except ValueError as e:
        return e.args[0]

    return submit_analysis_to_backend(data_type, saml_data, comparison_object)

@app.callback(
    Output('div-role-mapping-groups', 'hidden'),
    [Input('compare-role-mapping-expected', 'value')]
)
def toggle_role_mapping_entry(role_mapping_expected):
    if "Yes" in role_mapping_expected or []:
        return False
    return True

@app.callback(
    [Output('compare-first-name', 'value'),
    Output('compare-last-name', 'value'),
    Output('compare-email', 'value'),
    Output('compare-audience', 'value'),
    Output('compare-acs', 'value'),
    Output('compare-issuer', 'value'),
    Output('compare-encryption', 'value'),
    Output('domain-name-text', 'value'),
    Output('group-name-text', 'value'),
    Output('saml_input', 'value'),
    Output('analysis_output', 'value'),
    Output('compare-cert-expiration', 'date'),
    Output('compare-domain-list', 'options'),
    Output('compare-domain-list', 'value'),
    Output('compare-role-mapping-expected', 'value'),
    Output('compare-group-list', 'options'),
    Output('compare-group-list', 'value')],
    [Input('submit_reset_values', 'submit_n_clicks')]
)
def prompt_reset_values(n_clicks):
    if n_clicks is None:
        raise PreventUpdate

    return [""]*11 + [None] + [[]]*5

@app.callback(
    [Output('compare-domain-list', 'options'),
     Output('compare-domain-list', 'value'),
     Output('domain-name-text', 'value')],
    [Input('submit-add-domain', 'n_clicks'),
     Input('domain-name-text', 'n_submit')],
    [State('domain-name-text', 'value'),
     State('compare-domain-list', 'options'),
     State('compare-domain-list', 'value')]
)
def add_domain_to_list(n_clicks, n_submit, value, current_items, checked_items):
    if (n_clicks is None) and (n_submit is None) or value == "":
        raise PreventUpdate

    if value not in [x["value"] for x in current_items]:
        current_items.append({"label": value, "value": value})
        checked_items.append(value)

    return current_items, checked_items, ""

@app.callback(
    Output('compare-domain-list', 'options'),
    [Input('compare-domain-list', 'value')]
)
def remove_domain_from_list(checked_items):
    return [{"label": x, "value": x} for x in checked_items]

@app.callback(
    [Output('compare-group-list', 'options'),
     Output('compare-group-list', 'value'),
     Output('group-name-text', 'value')],
    [Input('submit-add-group', 'n_clicks'),
     Input('group-name-text', 'n_submit')],
    [State('group-name-text', 'value'),
     State('compare-group-list', 'options'),
     State('compare-group-list', 'value')]
)
def add_group_to_list(n_clicks, n_submit, value, current_items, checked_items):
    if (n_clicks is None) and (n_submit is None) or value == "":
        raise PreventUpdate

    if value not in [x["value"] for x in current_items]:
        current_items.append({"label": value, "value": value})
        checked_items.append(value)

    return current_items, checked_items, ""

@app.callback(
    Output('compare-group-list', 'options'),
    [Input('compare-group-list', 'value')]
)
def remove_group_from_list(checked_items):
    return [{"label": x, "value": x} for x in checked_items]

