# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue, and do not include real mail
content, passwords, tokens or keys in the report; a description and steps to
reproduce with test data are enough.

You can expect an acknowledgement within a week. This is a single-maintainer
project, so fixes may take longer; you will be kept informed and credited in
the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Scope

Of particular interest: anything that lets an MCP client or a mail message
cause a provider write without a human approval, approve something itself,
read data outside its scopes, or obtain credentials; bypasses of the
administrator login, CSRF protection or writer fence; and leaks of mail
content or secrets into logs, reports or the repository.

The documented trade-offs in [docs/security.md](docs/security.md) (for example
the optional MFA auto-login and auto-approval) are known and not
vulnerabilities by themselves.
