from dash_extensions.enrich import DashProxy, MultiplexerTransform


app = DashProxy(__name__,
    external_stylesheets=[
        "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"
    ],
    transforms=[MultiplexerTransform()]
)
server = app.server
