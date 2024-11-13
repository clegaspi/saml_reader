"""Callbacks for the SAML analyzer page"""

from datetime import datetime

from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from saml_reader.validation.input_validation import MongoFederationConfig
from saml_reader.cli import run_analysis, OutputStream
from saml_reader.web.app import app


def submit_analysis_to_backend(data_type, saml_data, comparison_data):
    """Sends data to the SAML reader backend after compilation from the
    web frontend.

    Args:
        data_type (basestring): Type of data being passed in. Must be
            `xml`, `base64`, or `har`.
        saml_data (basestring): raw SAML data
        comparison_data (MongoFederationConfig): federation data for comparison

    Returns:
        basestring: report generated after running tests
    """
    report = OutputStream()

    run_analysis(
        input_type=data_type,
        source="raw",
        compare=True,
        compare_object=comparison_data,
        raw_data=saml_data,
        print_analysis=True,
        print_summary=True,
        output_stream=report.print,
    )
    # TODO: In the future, generate a nicer looking report on the webpage, so
    #       this function should just return the status of tests and another
    #       function will handle building the web report.
    return report.getvalue()


@app.callback(
    Output("analysis_output", "value"),
    [Input("submit_saml_data", "n_clicks")],
    [
        State("saml_data_type", "value"),
        State("saml_input", "value"),
        State("compare-first-name", "value"),
        State("compare-last-name", "value"),
        State("compare-email", "value"),
        State("compare-audience", "value"),
        State("compare-acs", "value"),
        State("compare-issuer", "value"),
        State("compare-encryption", "value"),
        State("compare-cert-expiration", "date"),
        State("compare-domain-list", "value"),
        State("compare-role-mapping-expected", "value"),
        State("compare-group-list", "value"),
    ],
)
def submit_analysis(
    n_clicks,
    data_type,
    saml_data,
    first_name,
    last_name,
    email,
    audience,
    acs,
    issuer,
    encryption,
    cert_expiration,
    domain_list,
    role_mapping_expected,
    group_list,
):
    """Validates comparison input data and, if passes, send it to the analyzer.
    If an entry fails, an error is output to the results section. If all entries
    are acceptable, the output of the analyzer is output to the results section.

    Args:
        n_clicks (int): how many times was the submission button clicked
        data_type (basestring): format of data entered
        saml_data (basestring): SAML data
        first_name (basestring): first name for comparison
        last_name (basestring): last name for comparison
        email (basestring): email for comparison
        audience (basestring): audience URI for comparison
        acs (basestring): assertion consumer service URL for comparison
        issuer (basestring): issuer URI for comparison
        encryption (basestring): encryption algorithm for comparison
        cert_expiration (basestring): signing certificate expiration date for comparison
        domain_list (`list` of `basestring`): list of federated domains for comparison
        role_mapping_expected (`list` of `basestring`): contains "Yes" if role mapping is expected,
            `None` otherwise.
        group_list (`list` of `basestring`): list of expected role mapping groups for the user

    Raises:
        PreventUpdate: if the callback was canceled or there is no SAML data to send

    Returns:
        basestring: output for the results box
    """
    if n_clicks is None or not saml_data:
        raise PreventUpdate

    comparison_data = {
        "firstName": first_name or None,
        "lastName": last_name or None,
        "email": email or None,
        "issuer": issuer or None,
        "acs": acs or None,
        "audience": audience or None,
        "encryption": encryption or None,
        "role_mapping_expected": "N",
    }
    if domain_list:
        comparison_data["domains"] = domain_list
    if role_mapping_expected:
        comparison_data["role_mapping_expected"] = "Y"
        if group_list:
            comparison_data["memberOf"] = group_list
    if cert_expiration:
        comparison_data["cert_expiration"] = datetime.strptime(
            cert_expiration, "%Y-%m-%d"
        ).strftime("%m/%d/%Y")
    try:
        comparison_object = MongoFederationConfig(
            **{k: v for k, v in comparison_data.items() if v is not None}
        )
    except ValueError as e:
        return e.args[0]

    return submit_analysis_to_backend(data_type, saml_data, comparison_object)


@app.callback(
    Output("div-role-mapping-groups", "hidden"),
    [Input("compare-role-mapping-expected", "value")],
)
def toggle_role_mapping_entry(role_mapping_expected):
    """Toggles role mapping section on or off

    Args:
        role_mapping_expected (`list` of `basestring`): contains "Yes" if enabled,
            `None` otherwise.

    Returns:
        bool: True if should be hidden, False otherwise
    """
    if "Yes" in role_mapping_expected or []:
        return False
    return True


@app.callback(
    [
        Output("compare-first-name", "value"),
        Output("compare-last-name", "value"),
        Output("compare-email", "value"),
        Output("compare-audience", "value"),
        Output("compare-acs", "value"),
        Output("compare-issuer", "value"),
        Output("compare-encryption", "value"),
        Output("domain-name-text", "value"),
        Output("group-name-text", "value"),
        Output("saml_input", "value"),
        Output("analysis_output", "value"),
        Output("compare-cert-expiration", "date"),
        Output("compare-domain-list", "options"),
        Output("compare-domain-list", "value"),
        Output("compare-role-mapping-expected", "value"),
        Output("compare-group-list", "options"),
        Output("compare-group-list", "value"),
    ],
    [Input("submit_reset_values", "submit_n_clicks")],
)
def prompt_reset_values(n_clicks):
    """Clears entered data if user confirms ok.

    Args:
        n_clicks (int): non-zero if the user confirmed to clear the data

    Raises:
        PreventUpdate: if the callback was canceled (user said No)

    Returns:
        appropriate values to clear all data on the page
    """
    if n_clicks is None:
        raise PreventUpdate

    return [""] * 11 + [None] + [[]] * 5


@app.callback(
    [
        Output("compare-domain-list", "options"),
        Output("compare-domain-list", "value"),
        Output("domain-name-text", "value"),
    ],
    [Input("submit-add-domain", "n_clicks"), Input("domain-name-text", "n_submit")],
    [
        State("domain-name-text", "value"),
        State("compare-domain-list", "options"),
        State("compare-domain-list", "value"),
    ],
)
def add_domain_to_list(n_clicks, n_submit, value, current_items, checked_items):
    """Adds a domain to the list of federated domains, checks its box, and clears entry field.
    If value is already in list, just clears the entry field.

    Args:
        n_clicks (int): is not None if the button was pressed
        n_submit (int): is not None if Enter was pressed in the domain text box
        value (basestring): value of the domain
        current_items (`list` of `dict`): checkbox options representing domains currently in list
        checked_items (`list` of `basestring`): checked options (should be all domains)

    Raises:
        PreventUpdate: if button not clicked or Enter not pressed in the entry field
            or no value in the entry field

    Returns:
        tuple: `list` of `dict` of items in the domain checklist,
            `list` of `basestring` representing items checked,
            `basestring` for value of entry field
    """
    if (n_clicks is None) and (n_submit is None) or value == "":
        raise PreventUpdate

    if value not in [x["value"] for x in current_items]:
        current_items.append({"label": value, "value": value})
        checked_items.append(value)

    return current_items, checked_items, ""


@app.callback(
    Output("compare-domain-list", "options"), [Input("compare-domain-list", "value")]
)
def remove_domain_from_list(checked_items):
    """Remove domain from the list when it is unchecked.

    Args:
        checked_items (`list` of `basestring`): list of domains currently checked

    Returns:
        `list` of `dict`: updated list of domains in checklist
    """
    return [{"label": x, "value": x} for x in checked_items]


@app.callback(
    [
        Output("compare-group-list", "options"),
        Output("compare-group-list", "value"),
        Output("group-name-text", "value"),
    ],
    [Input("submit-add-group", "n_clicks"), Input("group-name-text", "n_submit")],
    [
        State("group-name-text", "value"),
        State("compare-group-list", "options"),
        State("compare-group-list", "value"),
    ],
)
def add_group_to_list(n_clicks, n_submit, value, current_items, checked_items):
    """Adds a AD to the list of mapped groups, checks its box, and clears entry field.
    If value is already in list, just clears the entry field.

    Args:
        n_clicks (int): is not None if the button was pressed
        n_submit (int): is not None if Enter was pressed in the group text box
        value (basestring): value of the group
        current_items (`list` of `dict`): checkbox options representing groups currently in list
        checked_items (`list` of `basestring`): checked options (should be all groups)

    Raises:
        PreventUpdate: if button not clicked or Enter not pressed in the entry field
            or no value in the entry field

    Returns:
        tuple: `list` of `dict` of items in the group checklist,
            `list` of `basestring` representing items checked,
            `basestring` for value of entry field
    """
    # TODO: This should probably be consolidated with the domain list
    if (n_clicks is None) and (n_submit is None) or value == "":
        raise PreventUpdate

    if value not in [x["value"] for x in current_items]:
        current_items.append({"label": value, "value": value})
        checked_items.append(value)

    return current_items, checked_items, ""


@app.callback(
    Output("compare-group-list", "options"), [Input("compare-group-list", "value")]
)
def remove_group_from_list(checked_items):
    """Remove group from the list when it is unchecked.

    Args:
        checked_items (`list` of `basestring`): list of groups currently checked

    Returns:
        `list` of `dict`: updated list of groups in checklist
    """
    # TODO: This could be consolidated with the domain list
    return [{"label": x, "value": x} for x in checked_items]
