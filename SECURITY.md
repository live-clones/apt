# Responsible disclosure policy
APT follows a responsible disclosure policy.
Please report any potential security issues
privately via e-mail or Launchpad.

## Reporting via e-mail
Send an e-mail to the following recipients:

    To: security@ubuntu.com
    Cc: security@debian.org, jak@debian.org

We encourage encrypting reports using OpenPGP if
they involve critical issues such as bypassing
signatures and hashes of the repository.

The SECURITY-keyring.pgp file contains all
relevant keys.

Please do not CC public mailing lists such as
apt@packages.debian.org, deity@lists.debian.org.

## Reporting on Launchpad
Alternatively, you may use launchpad.net to report
a bug against the apt package in Ubuntu:

https://bugs.launchpad.net/ubuntu/+source/apt/+filebug

On the final page, change the information type from
"Public" to "Private Security".

Please be aware that Launchpad will send unencrypted
emails.

## The apt-pkg library security stance
Please make sure to responsibly disclose any crash or
memory unsafety inside of apt-pkg. While the library is
generally not meant to be used on untrusted inputs, and
we do not commit to security updates for such cases, we
want to evaluate them on a case-by-case basis.

## Writing a report
In order to allow timely processing of your report:

- Use brief bullet points rather than prose to document
  the issue, particularly when describing a list of steps
- If you are able to, construct a failing unit or
  integration test that demonstrates the issue.

## Large Language Model policy
If a Large Language Model (LLM) is being used as part
of your security research or report, please ensure that:

- you fully understand the report
- you have manually reproduced the reported issue
- it is not needlessly verbose

Please do not include complex code changes unless requested.
A minimal reproducer or failing test is usually more helpful
at the reporting stage.

Consider writing the report in your own words rather
than copying the output from the LLM.
