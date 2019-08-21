import json
import time

from authlib.client import OAuth2Session
from flask import Flask, request, render_template, redirect, url_for, session, flash
import requests

SINGLETOUCH_API = "https://sandbox-api.singletouch.com.au/api"
SINGLETOUCH_TENANT = "singletouchsandbox.onmicrosoft.com"
SINGLETOUCH_POLICY = "B2C_1_singletouch"
SINGLETOUCH_AUTH_CALLBACK = "http://localhost:44396/B2C_1_singletouch-callback"

AZURE_AUTHORIZE_URL = "https://login.microsoftonline.com/tfp/{tenant}/{policy}/oauth2/v2.0/authorize"
AZURE_AUTHORIZE_URL = AZURE_AUTHORIZE_URL.format(tenant=SINGLETOUCH_TENANT, policy=SINGLETOUCH_POLICY)

AZURE_TOKEN_URL = "https://login.microsoftonline.com/tfp/{tenant}/{policy}/oauth2/v2.0/token?p={policy}"
AZURE_TOKEN_URL = AZURE_TOKEN_URL.format(tenant=SINGLETOUCH_TENANT, policy=SINGLETOUCH_POLICY)

app = Flask(__name__)
app.config["SECRET_KEY"] = "This should be secret"


@app.route("/")
def home():
    if not is_token_valid():
        return render_template("authorize.html")
    else:
        return render_template("upload.html")


def is_token_valid():
    """ Determine if the current token is still valid"""
    if "token" not in session:
        return False

    token = session.get("token")

    return token["expires_on"] > time.time()


@app.route("/authorize", methods=["POST"])
def authorize():
    client_id = request.form["client-id"]
    client_secret = request.form["client-secret"]

    scope = client_id + " openid"

    oauth_session = OAuth2Session(client_id, scope=scope, redirect_uri=SINGLETOUCH_AUTH_CALLBACK)

    url, oauth_state = oauth_session.create_authorization_url(AZURE_AUTHORIZE_URL)

    session["client_id"] = client_id
    session["client_secret"] = client_secret

    session.modified = True

    return redirect(url)


@app.route("/B2C_1_singletouch-callback")
def auth_callback():
    code = request.values["code"]

    client_id = session.pop("client_id")
    client_secret = session.pop("client_secret")

    scope = client_id + " openid"

    oauth_session = OAuth2Session(client_id, scope=scope, redirect_uri=SINGLETOUCH_AUTH_CALLBACK)

    token = oauth_session.fetch_access_token(AZURE_TOKEN_URL, code=code, client_secret=client_secret)

    session["token"] = token

    return redirect(url_for("home"))


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]

    json_data = json.load(file.stream)
    token = session.get("token")

    headers = {"Authorization": "Bearer " + token["id_token"], "Content-Type": "application/json"}

    # Note that the JSON request must be wrapped in a list
    r = requests.post(SINGLETOUCH_API + "/STPEvent2018", json=[json_data], headers=headers)

    if r.status_code == 200:
        flash("Uploaded file")
    else:
        flash("There was a problem uploading the file, got code {}".format(r.status_code), category="error")

    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, port=44396)
