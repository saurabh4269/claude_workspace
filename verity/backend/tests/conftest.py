"""Shared pytest fixtures for Verity tests."""

import pytest


# ---------------------------------------------------------------------------
# Minimal SBOM fixtures
# ---------------------------------------------------------------------------

MINIMAL_CDX_JSON = """
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T12:00:00Z",
    "tools": [{"vendor": "test", "name": "test-tool", "version": "1.0"}],
    "component": {
      "type": "application",
      "bom-ref": "pkg:npm/myapp@1.0.0",
      "name": "myapp",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{"license": {"id": "MIT"}}],
      "supplier": {"name": "Lodash Team"}
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/express@4.18.2",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [{"license": {"id": "MIT"}}],
      "supplier": {"name": "OpenJS Foundation"}
    }
  ],
  "dependencies": [
    {"ref": "pkg:npm/myapp@1.0.0", "dependsOn": ["pkg:npm/lodash@4.17.21", "pkg:npm/express@4.18.2"]},
    {"ref": "pkg:npm/lodash@4.17.21", "dependsOn": []},
    {"ref": "pkg:npm/express@4.18.2", "dependsOn": []}
  ]
}
"""

MINIMAL_SPDX_TV = """\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test-sbom
DocumentNamespace: https://example.com/test-sbom-1.0
Creator: Tool: verity-test
Created: 2024-01-15T12:00:00Z

PackageName: lodash
SPDXID: SPDXRef-lodash
PackageVersion: 4.17.21
PackageSupplier: Organization: Lodash Team
PackageDownloadLocation: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
FilesAnalyzed: false
ExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.21
PackageLicense: MIT
PackageLicenseConcluded: MIT
PackageCopyrightText: Copyright 2012-2021 The Dojo Foundation

PackageName: express
SPDXID: SPDXRef-express
PackageVersion: 4.18.2
PackageSupplier: Organization: OpenJS Foundation
PackageDownloadLocation: https://registry.npmjs.org/express/-/express-4.18.2.tgz
FilesAnalyzed: false
ExternalRef: PACKAGE-MANAGER purl pkg:npm/express@4.18.2
PackageLicense: MIT
PackageLicenseConcluded: MIT
PackageCopyrightText: Copyright 2017-2022 OpenJS Foundation

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-lodash
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-express
"""

MINIMAL_CDX_NO_SUPPLIER = """
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {"timestamp": "2024-01-15T12:00:00Z"},
  "components": [
    {
      "type": "library",
      "name": "orphan-lib",
      "version": "1.0.0"
    }
  ]
}
"""


@pytest.fixture
def cdx_json_doc():
    from app.core.parser import parse
    return parse(MINIMAL_CDX_JSON, filename="test.json")


@pytest.fixture
def spdx_tv_doc():
    from app.core.parser import parse
    return parse(MINIMAL_SPDX_TV, filename="test.spdx")


@pytest.fixture
def cdx_no_supplier_doc():
    from app.core.parser import parse
    return parse(MINIMAL_CDX_NO_SUPPLIER, filename="test.json")
