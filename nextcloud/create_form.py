"""Create the New User Onboarding form in Nextcloud from form-spec.json.

Usage:
  NC_USER=tloubani NC_TOKEN=<app password> python3 create_form.py form-spec.json

The token is an app password created with:
  occ user:auth-tokens:add tloubani --name onboarding-form --no-interaction

Not idempotent: running it again creates another form. Existing deployments
should use the IDs already recorded in form-spec.json / the Windmill script.
"""
import json
import os
import sys
import urllib.request

BASE = "https://cloud.glia.org/ocs/v2.php/apps/forms/api/v3"
USER = os.environ["NC_USER"]
TOKEN = os.environ["NC_TOKEN"]


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Authorization", "Basic " + __import__("base64").b64encode((USER + ":" + TOKEN).encode()).decode())
    req.add_header("OCS-APIRequest", "true")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)["ocs"]["data"]


def main(spec_path):
    spec = json.load(open(spec_path))
    form = call("POST", "/forms", {})
    form_id = form["id"]
    call("PATCH", "/forms/%d" % form_id, {"keyValuePairs": {
        "title": spec["title"], "description": spec["description"]}})
    for question in spec["questions"]:
        body = {"type": question["type"], "text": question["text"]}
        if question.get("extraSettings"):
            body["extraSettings"] = question["extraSettings"]
        q = call("POST", "/forms/%d/questions" % form_id, body)
        if question.get("required"):
            call("PATCH", "/forms/%d/questions/%d" % (form_id, q["id"]),
                 {"keyValuePairs": {"isRequired": True}})
        if question.get("options"):
            call("POST", "/forms/%d/questions/%d/options" % (form_id, q["id"]),
                 {"optionTexts": [o["text"] for o in question["options"]]})
    for share in spec["shares"]:
        call("POST", "/forms/%d/shares" % form_id, share)
    print(json.dumps({"id": form_id, "hash": form["hash"]}))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "nextcloud/form-spec.json")
