"""Onboarding: create an LDAP user from a Nextcloud Forms submission.

Polls form 46 (New User Onboarding) via the Forms API, creates the account
under ou=users if it does not already exist.

Self-contained: speaks LDAP directly over TLS (bind/search/add/modify) so the
Windmill worker needs no third-party Python packages.
"""
import base64
import hashlib
import json
import os
import random
import re
import smtplib
import socket
import ssl
import time
import unicodedata
import urllib.request
from email.message import EmailMessage

import wmill

FORM_ID = 46
NC_BASE = "https://cloud.glia.org"
NC_API = NC_BASE + "/ocs/v2.php/apps/forms/api/v3"
NC_USER = "tloubani"
LDAP_HOST = "auth.glia.org"
LDAP_BASE = "dc=emlondon,dc=ca"
LDAP_ADMIN = "cn=admin," + LDAP_BASE
USER_BASE = "ou=users," + LDAP_BASE
GROUP_DN = "cn=emlondon,ou=groups," + LDAP_BASE

# question ids in the onboarding form
Q_FIRST, Q_LAST, Q_EMAIL = 391, 392, 394
Q_TITLE, Q_TEAM, Q_VPN, Q_INBOX = 395, 396, 397, 398

# --- minimal BER/LDAP -------------------------------------------------------


def _len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, value):
    return bytes([tag]) + _len(len(value)) + value


def _int(n):
    if n == 0:
        b = b"\x00"
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
    return _tlv(0x02, b)


def _str(value):
    if isinstance(value, str):
        value = value.encode()
    return _tlv(0x04, value)


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _set(*parts):
    return _tlv(0x31, b"".join(parts))


def _enum(n):
    return _tlv(0x0a, bytes([n]))


def _read_tlv(sock):
    tag = sock.recv(1)
    if not tag:
        raise EOFError("LDAP connection closed")
    first = sock.recv(1)
    if not first:
        raise EOFError("LDAP connection closed")
    length = first[0]
    if length & 0x80:
        n = length & 0x7F
        raw = b""
        while len(raw) < n:
            raw += sock.recv(n - len(raw))
        length = int.from_bytes(raw, "big")
    value = b""
    while len(value) < length:
        chunk = sock.recv(length - len(value))
        if not chunk:
            raise EOFError("LDAP connection closed")
        value += chunk
    return tag[0], value


def _parse_tlv(buf, pos):
    tag = buf[pos]
    pos += 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, buf[pos:pos + length], pos + length


def _result_code(value):
    tag, content, _ = _parse_tlv(value, 0)
    if tag != 0x0A:
        return -1
    return int.from_bytes(content, "big")


class LDAP:
    def __init__(self, host, port=636, timeout=25):
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=host)
        self.mid = 0

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def _send(self, op):
        self.mid += 1
        self.sock.sendall(_seq(_int(self.mid), op))
        return self.mid

    def _read(self):
        tag, value = _read_tlv(self.sock)
        while tag != 0x30:
            tag, value = _read_tlv(self.sock)
        _, _, pos = _parse_tlv(value, 0)          # message id
        op_tag, op_value, _ = _parse_tlv(value, pos)
        return op_tag, op_value

    def bind(self, dn, password):
        op = _tlv(0x60, _int(3) + _str(dn) + _tlv(0x80, password.encode()))
        self._send(op)
        tag, value = self._read()
        return _result_code(value) == 0

    def exists(self, base, attr, value):
        # equalityMatch (uid=<value>)
        match = _tlv(0xA3, _str(attr) + _str(value))
        op = _tlv(0x63, _str(base) + _enum(2) + _enum(0) + _int(0) + _int(0) +
                              _tlv(0x01, b"\x00") + match + _seq())
        self._send(op)
        found = False
        while True:
            tag, value = self._read()
            if tag == 0x64:
                found = True
            elif tag == 0x65:
                return found

    def entry(self, uid):
        """Return attributes of uid=<uid> as {lowercase attr: [values]}."""
        match = _tlv(0xA3, _str("uid") + _str(uid))
        op = _tlv(0x63, _str(LDAP_BASE) + _enum(2) + _enum(0) + _int(0) + _int(0) +
                  _tlv(0x01, b"\x00") + match + _seq())
        self._send(op)
        attrs = {}
        while True:
            tag, value = self._read()
            if tag == 0x65:
                return attrs
            if tag != 0x64:
                continue
            _, _, pos = _parse_tlv(value, 0)          # objectName
            if pos >= len(value):
                continue
            atag, aval, _ = _parse_tlv(value, pos)    # attributes
            if atag != 0x30:
                continue
            q = 0
            while q < len(aval):
                _, attrseq, q = _parse_tlv(aval, q)
                _, name, r = _parse_tlv(attrseq, 0)
                _, valset, _ = _parse_tlv(attrseq, r)
                vals = []
                z = 0
                while z < len(valset):
                    _, v, z = _parse_tlv(valset, z)
                    vals.append(v.decode(errors="ignore"))
                attrs[name.decode(errors="ignore").lower()] = vals

    def add(self, dn, attributes):
        attrs = []
        for key, values in attributes.items():
            if isinstance(values, (str, int)):
                values = [values]
            attrs.append(_seq(_str(key), _set(*[_str(str(v)) for v in values])))
        op = _tlv(0x68, _str(dn) + _seq(*attrs))
        self._send(op)
        tag, value = self._read()
        return _result_code(value)

    def modify(self, dn, attr, value, operation=0):
        change = _seq(_enum(operation), _seq(_str(attr), _set(_str(str(value)))))
        op = _tlv(0x66, _str(dn) + _seq(change))
        self._send(op)
        tag, value = self._read()
        return _result_code(value)


# --- helpers ---------------------------------------------------------------


def nc_get(path):
    token = wmill.get_variable("u/admin/nextcloud_form_token")
    auth = base64.b64encode((NC_USER + ":" + token).encode()).decode()
    req = urllib.request.Request(NC_API + path)
    req.add_header("Authorization", "Basic " + auth)
    req.add_header("OCS-APIRequest", "true")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as resp:
        return json.load(resp)


def ssha(password):
    salt = os.urandom(4)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()


def answers_by_question(submission):
    out = {}
    for answer in submission.get("answers") or []:
        out.setdefault(answer["questionId"], []).append(answer.get("text") or "")
    return out


def text(ans, qid):
    vals = [v.strip() for v in ans.get(qid, []) if v and v.strip()]
    return vals[0] if vals else ""


def checked(ans, qid):
    vals = [v.strip().lower() for v in ans.get(qid, []) if v and v.strip()]
    return any(v in ("yes", "true", "1", "on") for v in vals)


def slug(value):
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", value.lower())


def surname_key(last):
    # Hyphenated surnames use the first part: Smith-Jones -> smith.
    return slug(last.split("-")[0])


def allocate_uid(conn, first, last):
    """Initial+surname, then full first.surname, then numbered full name."""
    base = slug(first)[:1] + surname_key(last)
    if not base:
        return ""
    if not conn.exists(LDAP_BASE, "uid", base):
        return base
    full = slug(first) + "." + surname_key(last)
    if not conn.exists(LDAP_BASE, "uid", full):
        return full
    n = 2
    while conn.exists(LDAP_BASE, "uid", "%s%d" % (full, n)):
        n += 1
    return "%s%d" % (full, n)


def send_email(recipients, subject, body):
    recipients = [r for r in dict.fromkeys(recipients) if r]
    if not recipients:
        return {"ok": False, "reason": "no recipients"}
    smtp_password = wmill.get_variable("u/admin/smtp_password")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = "Glia <cloud@emlondon.ca>"
    message["To"] = ", ".join(recipients)
    message.set_content(body)
    with smtplib.SMTP_SSL("mail.tarek.org", 465, timeout=30) as smtp:
        smtp.login("cloud@emlondon.ca", smtp_password)
        smtp.send_message(message)
    return {"ok": True, "to": recipients}


def welcome_body(first, uid, password, mail, vpn, inbox):
    return (
        "Hello %s,\n\n"
        "Welcome to Glia! An account has been created for you.\n\n"
        "Username: %s\n"
        "Temporary password: %s\n"
        "Sign in: https://user.glia.org\n"
        "Glia email: %s\n"
        "VPN access requested: %s\n"
        "Email inbox requested: %s\n\n"
        "Please sign in and change your password immediately: open the menu and choose "
        "\"Change password\". Then complete \"My profile\" with your phone, title, photo "
        "and other details.\n\n"
        "Your one-page account guide is in Nextcloud under Glia > Website & IT "
        "(\"Glia Account Guide - Passwords and Personal Information.pdf\").\n\n"
        "If you need help, contact the person who onboarded you or the Website & IT team.\n\n"
        "Welcome aboard!\nGlia\n"
    ) % (first, uid, password, mail, "yes" if vpn else "no", "yes" if inbox else "no")


def submitter_body(first, last, uid, mail, vpn, inbox, personal, submitter):
    return (
        "Hello,\n\n"
        "The onboarding form for %s %s has been processed by %s.\n\n"
        "Username: %s\n"
        "Account email: %s\n"
        "Personal email: %s\n"
        "VPN access requested: %s\n"
        "Email inbox requested: %s\n\n"
        "A welcome email with the username and temporary password was sent to %s.\n"
        "VPN and mailbox provisioning are not automatic yet; please follow up separately.\n\n"
        "The new member should sign in at https://user.glia.org and change the temporary password.\n"
        "Guides: Nextcloud > Glia > Website & IT.\n\n"
        "Glia onboarding automation\n"
    ) % (first, last, submitter, uid, mail, personal or "-",
         "yes" if vpn else "no", "yes" if inbox else "no", personal or "the new member")


def processed_submissions():
    try:
        raw = wmill.get_variable("u/admin/onboarding_processed")
        return set(json.loads(raw)) if raw else set()
    except Exception:
        return set()


def main():
    ldap_pw = wmill.get_variable("u/admin/ldap_admin_password")
    data = nc_get("/forms/%d/submissions" % FORM_ID)
    submissions = (data.get("ocs", {}).get("data", {}) or {}).get("submissions", [])

    conn = LDAP(LDAP_HOST)
    if not conn.bind(LDAP_ADMIN, ldap_pw):
        conn.close()
        raise RuntimeError("LDAP admin bind failed")

    created, skipped, errors = [], [], []
    processed = processed_submissions()
    newly_processed = set()
    already_processed = []
    for submission in submissions:
        submission_id = submission.get("id")
        if submission_id in processed:
            already_processed.append(submission_id)
            continue
        ans = answers_by_question(submission)
        first = text(ans, Q_FIRST)
        last = text(ans, Q_LAST)
        if not first or not last:
            errors.append({"submission": submission.get("id"), "reason": "missing first/last name"})
            continue
        uid = allocate_uid(conn, first, last)
        if not uid:
            errors.append({"submission": submission.get("id"), "reason": "could not derive username"})
            continue

        if conn.exists(LDAP_BASE, "uid", uid):
            skipped.append(uid)
            continue

        vpn = checked(ans, Q_VPN)
        inbox = checked(ans, Q_INBOX)
        uid_number = 20000 + int(time.time()) % 40000 + random.randint(0, 500)
        password = "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")
                           for _ in range(14))
        dn = "uid=%s,%s" % (uid, USER_BASE)
        mail = "%s@glia.org" % uid
        classes = ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"]
        if inbox:
            classes.append("gosaMailAccount")
        attributes = {
            "objectClass": classes,
            "uid": uid,
            "cn": "%s %s" % (first, last),
            "sn": last,
            "givenName": first,
            "displayName": "%s %s" % (first, last),
            "uidNumber": str(uid_number),
            "gidNumber": "512",
            "homeDirectory": "/home/%s" % uid,
            "loginShell": "/bin/bash",
            "mail": mail,
            "userPassword": ssha(password),
            "description": "Onboarding form by %s: VPN=%s Email=%s Team=%s Personal=%s" % (
                submission.get("userId", "unknown"),
                "yes" if vpn else "no",
                "yes" if inbox else "no",
                text(ans, Q_TEAM) or "-",
                text(ans, Q_EMAIL) or "-"),
        }
        title = text(ans, Q_TITLE)
        if title:
            attributes["title"] = title

        rc = conn.add(dn, attributes)
        if rc == 0:
            try:
                conn.modify(GROUP_DN, "memberUid", uid)
            except Exception:
                pass
            personal = text(ans, Q_EMAIL)
            submitter = submission.get("userId", "unknown")
            submitter_mail = ""
            try:
                info = conn.entry(submitter)
                submitter_mail = (info.get("mail") or [""])[0]
            except Exception:
                submitter_mail = ""
            email_status = []
            try:
                email_status.append({"kind": "new_user", "result": send_email(
                    [personal], "Welcome to Glia! Your Glia account is ready",
                    welcome_body(first, uid, password, mail, vpn, inbox))})
            except Exception as exc:
                errors.append({"submission": submission.get("id"), "uid": uid, "email": str(exc)})
            try:
                email_status.append({"kind": "submitter", "result": send_email(
                    [submitter_mail], "Onboarding complete: %s %s (%s)" % (first, last, uid),
                    submitter_body(first, last, uid, mail, vpn, inbox, personal, submitter))})
            except Exception as exc:
                errors.append({"submission": submission.get("id"), "uid": uid, "email": str(exc)})
            created.append({"uid": uid, "dn": dn, "mail": mail, "vpn": vpn, "inbox": inbox,
                            "emails": email_status})
            newly_processed.add(submission_id)
        else:
            errors.append({"submission": submission.get("id"), "uid": uid, "ldap_result": rc})

    if newly_processed:
        wmill.set_variable("u/admin/onboarding_processed",
                           json.dumps(sorted(processed | newly_processed)))
    conn.close()
    return {"created": created, "skipped": skipped, "already_processed": already_processed,
            "errors": errors, "submissions": len(submissions)}
