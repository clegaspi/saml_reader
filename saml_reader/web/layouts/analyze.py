"""Layout for SAML analysis page
"""

import dash_core_components as dcc
import dash_html_components as html


def build_layout():
    """
    Builds layout for page.

    Returns:
        an HTML component such as html.Div
    """
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
            "User's Email Address/Username",
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

"""Page layout"""
layout = build_layout()
