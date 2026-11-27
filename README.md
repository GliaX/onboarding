# Glia onboarding form → LDAP user

Nextcloud **Forms** onboarding form, shared with Meriam Waqas (`mwaqas`),
Jen Wilson (`jwilson`), Tarek Loubani (`tloubani`) and Adam Popanda
(`apopanda`), plus a Windmill automation that creates the LDAP user when a
submission arrives.

- Form: **New User Onboarding**, id 46, hash `nTp2QmoAbCDQajer`
  (`https://cloud.glia.org/apps/forms/nTp2QmoAbCDQajer`)
- Automation: Windmill workspace `nextcloud`, script
  `f/onboarding/form_to_user`, schedule `0 */2 * * * *` (America/Toronto,
  every 2 minutes, enabled)
- LDAP: `ldaps://auth.glia.org:636`, accounts under `ou=users,dc=emlondon,dc=ca`

## Form fields

| id | field | notes |
|----|-------|-------|
| 391 | First name | required |
| 392 | Last name | required |
| 393 | Username | required, used as uid |
| 394 | Personal email | required, email validation; recorded, not the account address |
| 395 | Job title | optional, becomes `title` |
| 396 | Team / organisation | optional, recorded in description |
| 397 | Create VPN access? | checkbox "Yes"; recorded in description, **no provisioning yet** |
| 398 | Create email inbox? | checkbox "Yes"; adds `gosaMailAccount` + `<uid>@glia.org` |

Shares are submit-only (`permissions: ["submit"]`); shares are to users, not
public links. The form owner is `tloubani`.

## What the automation does

Every 2 minutes the script:

1. Fetches submissions from the Forms API as `tloubani` (app password).
2. Skips submissions with an invalid/missing first name, last name or username.
3. Skips accounts whose `uid` already exists (idempotent, so repeated polls do
   not duplicate users or email).
4. Adds `uid=<username>,ou=users,dc=emlondon,dc=ca` with
   `inetOrgPerson` + `posixAccount` (gid 512, `/home/<uid>`, `/bin/bash`),
   a random 14-char password (SSHA-hashed), `mail=<uid>@glia.org`, title if
   given, and a description recording the VPN/email checkbox answers.
5. Adds `memberUid` to the `emlondon` group.

It speaks LDAP directly over TLS with the Python standard library, so the
Windmill worker does not need `ldap3` or any other package.

## Windmill setup

Workspace: `nextcloud` (embedded Windmill in the Nextcloud Flow ExApp).

Secrets are workspace variables:

- `u/admin/nextcloud_form_token` — Nextcloud app password for `tloubani`
- `u/admin/ldap_admin_password` — LDAP `cn=admin` password

The app password was created with:

```bash
docker exec -u www-data nextcloud php occ user:auth-tokens:add tloubani \
  --name onboarding-form --no-interaction
```

Script and schedule were created through the Windmill API at
`http://127.0.0.1:8000` inside the `nc_app_flow` container. The script content
is `windmill/onboarding_form_to_user.py`.

## Recreating the form

`nextcloud/form-spec.json` records the live form (ids, shares, options).
`nextcloud/create_form.py` creates a fresh form from it:

```bash
NC_USER=tloubani NC_TOKEN=<app password> \
  python3 nextcloud/create_form.py nextcloud/form-spec.json
```

This is not idempotent; it creates a new form. Update the question ids in the
Windmill script if the form is rebuilt.

## Verified

- Test submissions created `uid=ontest`, `ontest2` and `ontest3` via the flow;
  all were deleted afterwards, along with their submissions and `memberUid`
  entries. The form currently has zero submissions.
- Second run skipped existing accounts with no errors (idempotent).
- Created user attributes checked: `inetOrgPerson`, `posixAccount`,
  `gosaMailAccount`, `mail`, `gidNumber`, description flags, group membership.

## Limits / next steps

- VPN and email checkboxes are **recorded only**, as requested; provisioning
  is not wired.
- The generated password is not delivered anywhere. Onboarding managers must
  set/reset it later (Luminary / Nextcloud admin).
- Polling means up to ~2 minutes latency; a webhook trigger would be tighter.
- The uid allocation in the script is time/random based rather than using
  `cn=lastUID`; acceptable while accounts are mostly non-POSIX, but worth
  aligning before wider POSIX use.
- The form is internal to Nextcloud (no public link); the four sharees submit
  while logged in.
