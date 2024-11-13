from dash_extensions.enrich import DashProxy, MultiplexerTransform

# DashProxy allows the use MultiplexerTransform which automatically handles multiple callbacks
# to the same object which is not natively supported by Dash.
app = DashProxy(
    __name__,
    external_stylesheets=[
        "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
    ],
    transforms=[MultiplexerTransform()],
)
server = app.server
