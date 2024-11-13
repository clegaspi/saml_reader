"""Callbacks for the SAML analyzer page"""

from datetime import datetime
import re
from typing import TYPE_CHECKING
from dataclasses import asdict
from requests import HTTPError
import json

import flask
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
from dash import ctx, dcc, html

from saml_reader import __version__
from saml_reader.validation.input_validation import MongoFederationConfig
from saml_reader.cli import run_analysis, OutputStream
from saml_reader.web.app import app
from saml_reader.web.callbacks.crypto import (
    encrypt_string,
    decrypt_string,
    CRYPTO_STATE,
)
from cryptography.fernet import InvalidToken

try:
    from atlas_sdk.client.api import PublicV2ApiClient
    from atlas_sdk.auth.profile import Profile
    from atlas_sdk.auth.oauth import Token, DeviceCode

    ATLAS_SDK_AVAILABLE = True
except ImportError:
    ATLAS_SDK_AVAILABLE = False
USER_AGENT = f"saml-reader/{__version__}"


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


@app.callback(
    [
        Output("div-lookup-status-text", "children"),
        Output("div-lookup-status-text", "hidden"),
        Output("div-auth-required-text", "children"),
        Output("div-auth-required-text", "hidden"),
    ],
    [Input("submit-lookup-idp", "n_clicks")],
    [State("federation-url", "value")],
)
def validate_url_and_authenticate_sdk(n_clicks, url_value):
    """Remove group from the list when it is unchecked.

    Args:
        checked_items (`list` of `basestring`): list of groups currently checked

    Returns:
        `list` of `dict`: updated list of groups in checklist
    """
    if not ATLAS_SDK_AVAILABLE:
        return (
            html.P(
                "Atlas SDK not available. Cannot use this feature",
                style={"color": "red"},
            ),
            False,
        )
    if n_clicks is None or not url_value:
        raise PreventUpdate

    rx = re.search(
        r"^\s*https://cloud.mongodb(gov)?.com/v2#/federation/(?P<id>[a-z0-9]{24})",
        url_value,
    )
    if not rx or not rx.group("id"):
        return "Invalid URL", {"color": "red"}, False

    federation_id = rx.group("id")

    set_cookie(
        "saml-reader-cs",
        CRYPTO_STATE,
        max_age=0,
        secure=False,
        httponly=True,
    )
    set_cookie(
        "saml-reader-federation-id",
        federation_id,
        secure=False,
        httponly=True,
    )

    client = get_atlas_client()
    if client:
        return (
            html.P(f"Looking up federation {federation_id}", style={"color": "black"}),
            False,
            None,
            True,
        )

    client = PublicV2ApiClient(
        auth_type="oauth", open_browser=False, user_agent=USER_AGENT
    )
    dc: DeviceCode = client._auth_config.request_code()
    write_device_code_to_cookie(dc)
    return (
        None,
        True,
        [
            html.P(
                [
                    "Go to ",
                    html.A(
                        "this link",
                        href=dc.verification_uri,
                        target="_blank",
                        rel="noopener noreferrer",
                    ),
                    " to authenticate.",
                    html.Br(),
                    "Enter code ",
                    html.B(dc.user_code),
                    " to authorize this client.",
                ]
            ),
            dcc.Interval(
                id="check-auth-periodically",
                interval=dc.interval * 1000,
                max_intervals=(dc.expires_in // dc.interval) + 1,
                disabled=False,
            ),
        ],
        False,
    )


@app.callback(
    [
        Output("div-lookup-status-text", "children"),
        Output("div-lookup-status-text", "hidden"),
        Output("div-auth-required-text", "children"),
        Output("div-auth-required-text", "hidden"),
    ],
    [Input("check-auth-periodically", "n_intervals")],
    prevent_initial_call=True,
)
def check_sdk_authentication(n_intervals):
    if n_intervals is None:
        raise PreventUpdate

    dc = read_device_code_from_cookie()
    client = PublicV2ApiClient(
        auth_type="oauth", open_browser=False, user_agent=USER_AGENT
    )
    try:
        token = client._auth_config.get_token(dc)
    except HTTPError:
        return (
            None,
            True,
            html.P(
                "Authentication timed out. Please try again.", style={"color": "red"}
            ),
            False,
        )
    if token is None:
        raise PreventUpdate

    write_token_to_cookie(token)
    federation_id = get_cookie("saml-reader-federation-id", decrypt=False)
    return (
        html.P(f"Looking up federation {federation_id}", style={"color": "black"}),
        False,
        html.P("Authentication succeeded.", style={"color": "green"}),
        False,
    )


@app.callback(
    [
        Output("div-lookup-status-text", "children"),
        Output("div-lookup-status-text", "hidden"),
    ],
    [Input("div-lookup-status-text", "children")],
    prevent_initial_call=True,
)
def do_idp_lookup(children):
    if children is None:
        raise PreventUpdate

    client = get_atlas_client()

    federation_id = get_cookie("saml-reader-federation-id", decrypt=False)

    result = client.get(
        client.api_base_url + f"federationSettings/{federation_id}/identityProviders"
    )

    if not result.ok:
        return (
            html.P(
                f"Looking up federation {federation_id}...not found",
                style={"color": "red"},
            ),
            False,
        )

    idps = [
        {"label": f'{x["displayName"]} ({x["oktaIdpId"]})', "value": json.dumps(x)}
        for x in result.json()["results"]
        if x["protocol"] == "SAML"
    ]

    if not idps:
        return (
            html.P(
                f"Looking up federation {federation_id}...no SAML IdPs found!",
                {"color": "orange"},
            ),
            False,
        )

    return (
        [
            html.P(
                f"Looking up federation {federation_id}...found!",
                style={"color": "green"},
            ),
            html.Label(
                "Configured IdPs",
                style={
                    "width": "30%",
                    "display": "inline-block",
                    "vertical-align": "middle",
                },
            ),
            dcc.Dropdown(
                id="idp-selection-dropdown",
                options=idps,
                placeholder="Select IdP",
                style={
                    "width": "300px",
                    "display": "inline-block",
                    "vertical-align": "middle",
                },
            ),
        ],
        False,
    )


@app.callback(
    [
        Output("compare-audience", "value"),
        Output("compare-acs", "value"),
        Output("compare-issuer", "value"),
        Output("compare-encryption", "value"),
        Output("compare-cert-expiration", "date"),
        Output("compare-domain-list", "value"),
    ],
    [Input("idp-selection-dropdown", "value")],
    prevent_initial_call=True,
)
def set_comparison_values_for_selection_idp(value):
    if value is None:
        raise PreventUpdate

    idp = json.loads(value)

    cert_info = idp.get("pemFileInfo", {}).get("certificates", [])
    if not cert_info:
        cert_expiration = ""
    else:
        cert_expiration = datetime.strptime(
            cert_info[0]["notAfter"], "%Y-%m-%dT%H:%M:%SZ"
        ).strftime("%Y-%m-%d")
    return (
        idp.get("audienceUri", ""),
        idp.get("acsUrl", ""),
        idp.get("issuerUri", ""),
        idp.get("responseSignatureAlgorithm", ""),
        cert_expiration,
        idp.get("associatedDomains", []),
    )


def get_atlas_client() -> PublicV2ApiClient | None:
    token = read_token_from_cookie()
    if not token:
        return None

    client = PublicV2ApiClient(
        profile=Profile("saml-reader", token=token),
        auth_type="oauth",
        open_browser=False,
        user_agent=USER_AGENT,
    )

    if not client.test_auth():
        return None

    write_token_to_cookie(client.profile.token)
    return client


def get_cookie(name: str, decrypt: bool = True) -> str | None:
    data = flask.request.cookies.get(name, None)
    if not data:
        return None
    if decrypt:
        try:
            return decrypt_string(data)
        except InvalidToken:
            return None
    return data


if TYPE_CHECKING:
    set_cookie = flask.Response().set_cookie
else:

    def set_cookie(name: str, value: str, /, secure: bool = False, **kwargs):
        if secure:
            value = encrypt_string(value)
        ctx.response.set_cookie(name, value, secure=secure, **kwargs)


def write_token_to_cookie(token: Token):
    token_dict = asdict(token)
    token_dict["issue_time"] = token_dict["issue_time"].timestamp()
    set_cookie(
        "saml-reader-atlas-token",
        json.dumps(token_dict),
        secure=True,
        httponly=True,
    )


def read_token_from_cookie() -> Token | None:
    token_json = get_cookie("saml-reader-atlas-token")
    if not token_json:
        return None
    token_dict = json.loads(token_json)
    token_dict["issue_time"] = datetime.fromtimestamp(token_dict["issue_time"])
    return Token(**token_dict)


def write_device_code_to_cookie(dc: DeviceCode):
    dc_dict = asdict(dc)
    dc_dict["issue_time"] = dc_dict["issue_time"].timestamp()
    set_cookie(
        "saml-reader-device-code",
        json.dumps(dc_dict),
        secure=True,
        httponly=True,
    )


def read_device_code_from_cookie() -> DeviceCode | None:
    dc_json = get_cookie("saml-reader-device-code")
    if not dc_json:
        return None
    dc_dict = json.loads(dc_json)
    dc_dict["issue_time"] = datetime.fromtimestamp(dc_dict["issue_time"])
    return DeviceCode(**dc_dict)
