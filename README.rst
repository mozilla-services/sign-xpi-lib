============
sign-xpi-lib
============


.. image:: https://img.shields.io/pypi/v/sign_xpi_lib.svg
        :target: https://pypi.python.org/pypi/sign_xpi_lib

.. image:: https://img.shields.io/travis/glasserc/sign_xpi_lib.svg
        :target: https://travis-ci.org/glasserc/sign_xpi_lib

.. image:: https://readthedocs.org/projects/sign-xpi-lib/badge/?version=latest
        :target: https://sign-xpi-lib.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

.. image:: https://pyup.io/repos/github/glasserc/sign_xpi_lib/shield.svg
     :target: https://pyup.io/repos/github/glasserc/sign_xpi_lib/
     :alt: Updates


A library to handle the manipulations of signing XPIs at Mozilla.


* Free software: MIT license
* Documentation: https://sign-xpi-lib.readthedocs.io.


Overview
--------

Information about how XPI signing works in Firefox can be found at
`the Mozilla wiki
<https://wiki.mozilla.org/Add-ons/Extension_Signing>`_.

A tool that generates PKCS7 signatures in the correct format is
`autograph <https://github.com/mozilla-services/autograph/>`_, which
see for more information.

This library is used by `the sign-xpi lambda
<https://github.com/mozilla-services/sign-xpi/>`_, but can be used by
other clients too.

Usage::

  from sign_xpi_lib import XPIFile

  x = XPIFile('hypothetical-addon-unsigned.xpi')

  # this is the mozilla.sf file computed by hashing mozilla.rsa
  signed_manifest = x.signed_manifest
  print(signed_manifest)

  # This probably talks to Autograph or an HSM or whatever
  signature = 'generate-a-signature somehow'

  x.make_signed('hypothetical-addon-signed.xpi', 'mozilla.rsa',
                signed_manifest, signature)


See the `tests
<https://github.com/mozilla-services/sign-xpi-lib/blob/master/tests/test_sign_xpi_lib.py>`_
for more details.

Credits
---------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
