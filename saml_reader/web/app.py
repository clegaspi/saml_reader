import dash

app = dash.Dash(__name__,
    external_stylesheets=[
        "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"
    ]
)
server = app.server
