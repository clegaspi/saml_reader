from datetime import datetime

from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from saml_reader.validation.input_validation import MongoFederationConfig
from saml_reader.cli import run_analysis, OutputStream
from saml_reader.web.app import app


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
