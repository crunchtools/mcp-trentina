WIC Notebook Catalogue — Digital Archive
=========================================

This archive contains seven notebook records from the Wellcome
Institute Collection, digitised from the original manuscripts
held in the Special Collections reading room.

Format
------
Records are encoded as Base85 + zlib compressed JSON.  A native
decoder is provided (decoder-darwin for macOS).  Usage:

    ./decoder-darwin record-001.b85z

Each decoded record contains: accession number, date, author,
title, and a short abstract in plain text.

Manifest
--------
See MANIFEST.sha256 for integrity verification.

Contact: archive-digital@wellcome.example.org
