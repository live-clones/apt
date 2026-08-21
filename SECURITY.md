# Responsible disclosure policy
APT uses responsible disclosure, please report any
potential security issues privately to security@debian.org
and/or security@ubuntu.com.

Please do not CC public mailing lists such as
apt@packages.debian.org, deity@lists.debian.org.

## The apt-pkg library security stance
Please make sure to responsibly disclose any crash or
memory unsafety inside of apt-pkg. While the library is
generally not meant to be used on untrusted inputs, and
we do not commit to security updates for such cases, we
want to evaluate them on a case-by-case basis.

## Large Language Model policy
If a Large Language Model (LLM) is being used as part
of your security research or report, please ensure that:

- you fully understand the report
- you have manually reproduced the reported issue
- it is not needlessly verbose
- it does not include LLM-generated patches

Consider writing the report in your own words rather
than copying the output from the LLM.
