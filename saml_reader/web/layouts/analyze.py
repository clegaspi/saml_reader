"""Layout for SAML analysis page
"""

from dash import dcc, html


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
            'display': 'inline-block',
            'vertical-align': 'top',
        })

    rs_top_text = html.Div([
        dcc.Markdown(
            """
            ### Comparison values

            If you would like to enter comparison values, please do so below."""
        ),
        html.Details([
            html.Summary(
                dcc.Markdown(
                    "Need help finding this info? Click here.",
                    style={
                        'vertical-align': 'top',
                        'display': 'inline-block'
                    }
                )
            ),
            dcc.Markdown(
                """
                #### Finding comparison values

                First name, last name, and username information can be found in the
                Support Portal or admin panel.
                
                The Audience URI, Assertion Consumer Service URL, and associated domains
                can be found in the customer's federation settings on the identity provider
                information card.
                
                The Issuer URI, encryption type, and SAML certificate expiration date
                can be found by clicking "Modify" on the identity provider information
                card in the customer's federation settings.
                
                To determine if role mapping is expected, first look to see if any
                organizations are associated with the active identity provider configuration.
                For each organization that is associated, find the associated organization in
                the Organizations section and click into the settings. From the organization settings,
                click into Role Mappings. If there are any role mappings defined in any organization,
                then the customer is expecting role mapping to be configured.
                
                For expected group names, if a customer has specified which group name(s) their
                user is supposed to have, then you can add that to this list."""
            )]
        )]
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
        html.Div([
            html.Label(
                "User's First Name",
                style={
                    "width": "30%",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            ),
            dcc.Input(
                placeholder="Sam",
                type='text',
                value='',
                id='compare-first-name',
                style={
                    "width": "300px",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            )
        ]),
        html.Div([
            html.Label(
                "User's Last Name",
                style={
                    "width": "30%",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            ),
            dcc.Input(
                placeholder="Ell",
                type='text',
                value='',
                id='compare-last-name',
                style={
                    "width": "300px",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            )
        ]),
        html.Div([
            html.Label(
                "User's Email Address/Username",
                style={
                    "width": "30%",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            ),
            dcc.Input(
                placeholder="sam.ell@mydomain.com",
                type='text',
                value='',
                id='compare-email',
                style={
                    "width": "300px",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            )
        ]),
        html.Div([
            html.Label(
                "Audience URI",
                style={
                    "width": "30%",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            ),
            dcc.Input(
                placeholder="https://www.okta.com/saml2/service-provider/...",
                type='text',
                value='',
                id='compare-audience',
                style={
                    "width": "300px",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            ),
        ]),
        html.Div([
            html.Label(
                "Assertion Consumer Service URL",
                style={
                    "width": "30%",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            ),
            dcc.Input(
                placeholder="https://auth.mongodb.com/sso/saml2/...",
                type='text',
                value='',
                id='compare-acs',
                style={
                    "width": "300px",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            )
        ]),
        html.Div([
            html.Label(
                "Issuer URI",
                style={
                    "width": "30%",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            ),
            dcc.Input(
                placeholder="idp-entity-id",
                type='text',
                value='',
                id='compare-issuer',
                style={
                    "width": "300px",
                    'display': 'inline-block',
                    'vertical-align': 'middle'
                }
            )
        ]),
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
                    style={"display": "inline-block",
                           "vertical-align": "middle"}
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
    ], style={'display': 'inline-block',
              'vertical-align': 'middle'})

    right_side = html.Div(
        children=[
            rs_top_text,
            html.Br(),
            comparison_fields
        ],
        style={
            'display': 'inline-block',
            'vertical-align': 'top',
            'width': '50%'
        }
    )

    layout = html.Div([
        left_side, right_side
    ], className="row", style={"margin-bottom": "3em"})
    return layout


"""Page layout"""
layout = build_layout()
