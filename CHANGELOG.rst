=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog`_, and this project adheres to `Semantic Versioning`_.

`Unreleased`_
-------------

* Add support for cryptography v38

`0.3.0`_ - 2022-08-01
---------------------

Changed
^^^^^^^
* By default, symmetric encryption is unsalted

`0.2.0`_ - 2022-06-06
---------------------

Added
^^^^^
* Exposed the methods that encrypt/decrypt bytes

Changed
^^^^^^^
* encrypt/decrypt are expecting a binary IO instead of a path

`0.1.0`_ - 2022-05-30
---------------------

Added
^^^^^
* Added a class for symmetric encryption/decryption

.. _`unreleased`: https://github.com/piper-hq/cryptonium/compare/v0.3.0...main
.. _`0.3.0`: https://github.com/piper-hq/cryptonium/compare/v0.2.0...v0.3.0
.. _`0.2.0`: https://github.com/piper-hq/cryptonium/compare/v0.1.0...v0.2.0
.. _`0.1.0`: https://github.com/piper-hq/cryptonium/releases/tag/v0.1.0

.. _`Keep a Changelog`: https://keepachangelog.com/en/1.0.0/
.. _`Semantic Versioning`: https://semver.org/spec/v2.0.0.html
