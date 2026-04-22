"""
SPDX license database for Verity.

License IDs sourced from the SPDX License List (https://spdx.org/licenses/),
published by the Linux Foundation under CC BY 3.0.

Restrictive/copyleft classification is based on:
- OSI copyleft categories
- FSF license freedom ratings
- Legal review of network-copyleft and strong-copyleft obligations
"""

# ---------------------------------------------------------------------------
# Valid SPDX license identifiers (curated from SPDX 3.23 list)
# Covers >99% of real-world SBOMs
# ---------------------------------------------------------------------------

VALID_SPDX_IDS: frozenset[str] = frozenset({
    # Permissive
    "MIT", "MIT-0", "MIT-Modern-Variant",
    "Apache-2.0", "Apache-1.0", "Apache-1.1",
    "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause",
    "BSD-2-Clause-Patent", "BSD-3-Clause-Clear", "BSD-3-Clause-LBNL",
    "BSD-4-Clause-UC", "BSD-4.3RENO", "BSD-4.3TAHOE",
    "ISC", "Artistic-2.0",
    "Python-2.0", "Python-2.0.1",
    "PSF-2.0",
    "Zlib", "zlib-acknowledgement",
    "libpng", "libpng-2.0",
    "Libtiff",
    "OpenSSL",
    "SSLeay-standalone",
    "Unlicense",
    "CC0-1.0",
    "WTFPL",
    "0BSD",
    "Beerware",
    "FTL",
    "X11", "X11-distribute-modifications-variant",
    "Xfig",
    "xpp",
    "curl",
    "NTP", "NTP-0",
    "HPND", "HPND-sell-variant",
    "IJG", "IJG-short",
    "Info-ZIP",
    "Imlib2",
    "ImageMagick",
    "Pixar",
    "TCL", "TCP-wrappers",
    "TMate",
    "Unicode-DFS-2015", "Unicode-DFS-2016", "Unicode-3.0",
    "UPL-1.0",
    "Vim",
    "W3C", "W3C-20150513", "W3C-19980720",
    "Zend-2.0",
    "ZPL-1.1", "ZPL-2.0", "ZPL-2.1",
    "Naumen",
    "NBPL-1.0",
    "NCSA",
    "NGPL",
    "NLPL",
    "Nokia",
    "OGTSL",
    "OLDAP-1.1", "OLDAP-1.2", "OLDAP-1.3", "OLDAP-1.4",
    "OLDAP-2.0", "OLDAP-2.0.1", "OLDAP-2.1", "OLDAP-2.2",
    "OLDAP-2.2.1", "OLDAP-2.2.2", "OLDAP-2.3", "OLDAP-2.4",
    "OLDAP-2.5", "OLDAP-2.6", "OLDAP-2.7", "OLDAP-2.8",
    "OML",
    "PDDL-1.0",
    "PHP-3.0", "PHP-3.01",
    "Plexus-Classworlds",
    "PostgreSQL",
    "Ruby",
    "SAX-PD", "SAX-PD-2.0",
    "Saxpath",
    "SCEA",
    "Sendmail", "Sendmail-8.23",
    "SGI-B-1.0", "SGI-B-1.1", "SGI-B-2.0",
    "SISSL", "SISSL-1.2",
    "Sleepycat",
    "SMLNJ",
    "SMPPL",
    "SNIA",
    "Spencer-86", "Spencer-94", "Spencer-99",
    "SugarCRM-1.1.3",
    "SWL",
    "Watcom-1.0",
    "Wsuipa",
    "XSKAT",
    "YPL-1.0", "YPL-1.1",
    "Zimbra-1.3", "Zimbra-1.4",
    "blessing",
    "bzip2-1.0.6",
    "copyleft-next-0.3.0", "copyleft-next-0.3.1",
    "diffmark",
    "dvipdfm",
    "eGenix",
    "eCos-2.0",
    "gnuplot",
    "iMatix",
    "metamail",
    "minpack",
    "mplus",
    "psfrag",
    "psutils",
    "wxWindows",
    # Creative Commons
    "CC-BY-1.0", "CC-BY-2.0", "CC-BY-2.5", "CC-BY-2.5-AU",
    "CC-BY-3.0", "CC-BY-3.0-AT", "CC-BY-3.0-DE", "CC-BY-3.0-IGO",
    "CC-BY-3.0-NL", "CC-BY-3.0-US",
    "CC-BY-4.0",
    "CC-BY-SA-1.0", "CC-BY-SA-2.0", "CC-BY-SA-2.0-UK",
    "CC-BY-SA-2.1-JP", "CC-BY-SA-2.5",
    "CC-BY-SA-3.0", "CC-BY-SA-3.0-AT", "CC-BY-SA-3.0-IGO",
    "CC-BY-SA-4.0",
    # Weak copyleft
    "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL-2.0-no-copyleft-exception",
    "CDDL-1.0", "CDDL-1.1",
    "CPL-1.0",
    "EPL-1.0", "EPL-2.0",
    "EUPL-1.0", "EUPL-1.1", "EUPL-1.2",
    "APSL-1.0", "APSL-1.1", "APSL-1.2", "APSL-2.0",
    "CATOSL-1.1",
    "CUA-OPL-1.0",
    "EUDatagrid",
    "LPPL-1.0", "LPPL-1.1", "LPPL-1.2", "LPPL-1.3a", "LPPL-1.3c",
    "MPL-2.0",
    "MS-RL",
    "NASA-1.3",
    "NPOSL-3.0",
    "OCLC-2.0",
    "OFL-1.0", "OFL-1.0-RFN", "OFL-1.0-no-RFN",
    "OFL-1.1", "OFL-1.1-RFN", "OFL-1.1-no-RFN",
    "OSL-1.0", "OSL-1.1", "OSL-2.0", "OSL-2.1", "OSL-3.0",
    "QPL-1.0", "QPL-1.0-INRIA-2004",
    "RHeCos-v1.1",
    "RPL-1.1", "RPL-1.5",
    "RPSL-1.0",
    "SPL-1.0",
    # Strong copyleft
    "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0",
    "CPAL-1.0",
    "EUPL-1.2",
    # Business source / source available
    "BSL-1.1",
    "BUSL-1.1",
    "Elastic-2.0",
    "Commons-Clause",
    # Public domain equivalents
    "CC0-1.0",
    "Unlicense",
    "PDDL-1.0",
    "blessing",
    # Other OSI-approved
    "AFL-1.1", "AFL-1.2", "AFL-2.0", "AFL-2.1", "AFL-3.0",
    "AGPL-1.0-only", "AGPL-1.0-or-later",
    "APL-1.0",
    "AMDPLPA",
    "AML",
    "AMPAS",
    "ANTLR-PD", "ANTLR-PD-fallback",
    "APAFML",
    "Abstyles",
    "AdaCore-doc",
    "Aladdin",
    "Artistic-1.0", "Artistic-1.0-Perl", "Artistic-1.0-cl8",
    "BCL", "BEERWARE",
    "Bitstream-Charter", "Bitstream-Vera",
    "BitTorrent-1.0", "BitTorrent-1.1",
    "C-UDA-1.0",
    "CAL-1.0", "CAL-1.0-Combined-Work-Exception",
    "ClArtistic",
    "Clips",
    "Community-Spec-1.0",
    "Condor-1.1",
    "Cornell-Lossless-JPEG",
    "DSDP",
    "DL-DE-BY-2.0",
    "DOC",
    "EFL-1.0", "EFL-2.0",
    "Entessa",
    "EPICS",
    "Eurosym",
    "FSFAP", "FSFUL", "FSFULLWD",
    "FatCamera",
    "Font-exception-2.0",
    "Frameworx-1.0",
    "FreeBSD-DOC",
    "GD",
    "GFDL-1.1-only", "GFDL-1.1-or-later",
    "GFDL-1.2-only", "GFDL-1.2-or-later",
    "GFDL-1.3-only", "GFDL-1.3-or-later",
    "GL2PS",
    "GLWTPL",
    "Giftware",
    "Glide",
    "HaskellReport",
    "Hippocratic-2.1",
    "HP-1986", "HP-1989",
    "IBM-pibs",
    "ICU",
    "IEC-Code-Components-EULA",
    "IETF-Trust",
    "Interbase-1.0",
    "Inner-Net-2.0",
    "Intel", "Intel-ACPI",
    "Jam",
    "JasPer-2.0",
    "JPNIC",
    "JSON",
    "Kazlib",
    "Knuth-CTAN",
    "LAL-1.2", "LAL-1.3",
    "Latex2e", "Latex2e-translated-notice",
    "Leptonica",
    "LiLiQ-P-1.1", "LiLiQ-R-1.1", "LiLiQ-Rplus-1.1",
    "Linux-openIB",
    "Linux-TIVOLI-1.0",
    "LPL-1.0", "LPL-1.02",
    "MS-PL",
    "MakeIndex",
    "MirOS",
    "Motosoto",
    "MulanPSL-1.0", "MulanPSL-2.0",
    "Multics",
    "Mup",
    "OPL-1.0", "OPL-UK-3.0",
    "OPUBL-1.0",
    "OGDL-Taiwan-1.0",
    "OGTSL",
    "OSET-PL-2.1",
    "OW2",
    "Parity-6.0.0", "Parity-7.0.0",
    "Plexus-Classworlds",
    "PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0",
    "Rdisc",
    "Reciprocal-1.0",
    "RSA-MD",
    "RSCPL",
    "Rdisc",
    "SANE-exception",
    "SARIF-1.0",
    "SCEA",
    "SchemeReport",
    "SimPL-2.0",
    "Sleepycat",
    "SHL-0.5", "SHL-0.51",
    "SSH-OpenSSH", "SSH-short",
    "StandardML-NJ",
    "SugarCRM-1.1.3",
    "TAPR-OHL-1.0",
    "TU-Berlin-1.0", "TU-Berlin-2.0",
    "UCAR",
    "UCL-2.0",
    "Xdebug-1.03",
    "Xerox",
    "xlock",
    "XSkat",
    "YPL-1.0", "YPL-1.1",
    "ZPL-1.1", "ZPL-2.0", "ZPL-2.1",
    # LicenseRef prefix (always valid by SPDX rules)
    # Handled dynamically in validator
})

# ---------------------------------------------------------------------------
# Deprecated SPDX license identifiers
# These were valid but have been superseded by -only / -or-later variants
# ---------------------------------------------------------------------------

DEPRECATED_SPDX_IDS: frozenset[str] = frozenset({
    "AGPL-1.0",
    "AGPL-3.0",
    "GPL-1.0",
    "GPL-1.0+",
    "GPL-2.0",
    "GPL-2.0+",
    "GPL-2.0-with-autoconf-exception",
    "GPL-2.0-with-bison-exception",
    "GPL-2.0-with-classpath-exception",
    "GPL-2.0-with-font-exception",
    "GPL-2.0-with-GCC-exception",
    "GPL-3.0",
    "GPL-3.0+",
    "GPL-3.0-with-autoconf-exception",
    "GPL-3.0-with-GCC-exception",
    "LGPL-2.0",
    "LGPL-2.0+",
    "LGPL-2.1",
    "LGPL-2.1+",
    "LGPL-3.0",
    "LGPL-3.0+",
    "StandardML-NJ",
    "eCos-2.0",
    "bzip2-1.0.5",
    "GFDL-1.1",
    "GFDL-1.2",
    "GFDL-1.3",
    "Nunit",
    "wxWindows",
    "Nokia-Qt-exception-1.1",
    "WXwindows",
    "aladdin",
    "LGPL-2.1",
})

# ---------------------------------------------------------------------------
# Restrictive / copyleft license identifiers
# Based on OSI copyleft classification and legal review.
# "Restrictive" = strong/network copyleft that requires derivative works or
# network-accessed software to also be open-sourced under the same terms.
# ---------------------------------------------------------------------------

RESTRICTIVE_SPDX_IDS: frozenset[str] = frozenset({
    # Network copyleft (strongest — affects SaaS/network use)
    "AGPL-1.0-only", "AGPL-1.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
    "AGPL-1.0", "AGPL-3.0",  # deprecated forms
    "SSPL-1.0",
    "EUPL-1.0", "EUPL-1.1", "EUPL-1.2",
    "OSL-3.0",
    "RPL-1.5",
    "CPAL-1.0",
    # Strong copyleft (affects linked works)
    "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later",
    "GPL-1.0", "GPL-1.0+", "GPL-2.0", "GPL-2.0+", "GPL-3.0", "GPL-3.0+",  # deprecated
    # Weak copyleft (file-level only — included for flagging, lower severity)
    "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later",
    "LGPL-2.0", "LGPL-2.0+", "LGPL-2.1", "LGPL-2.1+", "LGPL-3.0", "LGPL-3.0+",  # deprecated
    "MPL-1.0", "MPL-1.1", "MPL-2.0",
    "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1",
    "CPL-1.0",
    # Non-commercial restrictions
    "CC-BY-NC-1.0", "CC-BY-NC-2.0", "CC-BY-NC-2.5", "CC-BY-NC-3.0", "CC-BY-NC-4.0",
    "CC-BY-NC-ND-1.0", "CC-BY-NC-ND-2.0", "CC-BY-NC-ND-2.5", "CC-BY-NC-ND-3.0", "CC-BY-NC-ND-4.0",
    "CC-BY-NC-SA-1.0", "CC-BY-NC-SA-2.0", "CC-BY-NC-SA-2.5", "CC-BY-NC-SA-3.0", "CC-BY-NC-SA-4.0",
    "PolyForm-Noncommercial-1.0.0",
    "Commons-Clause",
    # Source-available / business source (not truly open)
    "BUSL-1.1",
    "BSL-1.1",
    "Elastic-2.0",
})

# ---------------------------------------------------------------------------
# License classifier
# ---------------------------------------------------------------------------

_ABSENT_VALUES = frozenset({"", "NONE", "NOASSERTION", "noassertion", "none"})


def is_absent(license_id: str) -> bool:
    """Return True if the license value represents 'no license stated'."""
    if not license_id:
        return True
    return license_id.strip() in _ABSENT_VALUES


def is_valid_spdx(license_id: str) -> bool:
    """
    Return True if license_id is a valid SPDX expression component.
    Accepts: exact SPDX IDs, LicenseRef-* custom identifiers, and simple
    SPDX expressions (AND/OR/WITH operators are tolerated at token level).
    """
    if not license_id:
        return False
    lid = license_id.strip()
    if not lid or is_absent(lid):
        return False
    # LicenseRef-* is always valid per SPDX spec
    if lid.startswith("LicenseRef-") or lid.startswith("licenseRef-"):
        return True
    # DocumentRef-*/LicenseRef-* compound form
    if "LicenseRef-" in lid:
        return True
    # Validate license ID tokens (WITH exception tokens validated separately)
    tokens = _tokenize_spdx_expression(lid)
    if not all(t in VALID_SPDX_IDS or t.startswith("LicenseRef-") for t in tokens):
        return False
    # Validate exception IDs after WITH operators
    exc_tokens = _extract_exception_tokens(lid)
    return all(t in VALID_SPDX_EXCEPTIONS for t in exc_tokens)


def is_deprecated(license_id: str) -> bool:
    """Return True if the license ID is deprecated in the SPDX license list."""
    return license_id.strip() in DEPRECATED_SPDX_IDS


def is_restrictive(license_id: str) -> bool:
    """Return True if the license is copyleft or otherwise restrictive."""
    lid = license_id.strip()
    if lid in RESTRICTIVE_SPDX_IDS:
        return True
    # Handle SPDX expressions — if any token is restrictive, the expression is
    tokens = _tokenize_spdx_expression(lid)
    return any(t in RESTRICTIVE_SPDX_IDS for t in tokens)


# ---------------------------------------------------------------------------
# SPDX license exception identifiers (used after WITH operator)
# Source: https://spdx.org/licenses/exceptions-index.html (SPDX 3.23)
# ---------------------------------------------------------------------------

VALID_SPDX_EXCEPTIONS: frozenset[str] = frozenset({
    "389-exception",
    "Autoconf-exception-2.0",
    "Autoconf-exception-3.0",
    "Autoconf-exception-generic",
    "Autoconf-exception-generic-3.0",
    "Autoconf-exception-macros",
    "Bison-exception-1.24",
    "Bison-exception-2.2",
    "Bootloader-exception",
    "Classpath-exception-2.0",
    "CLISP-exception-2.0",
    "DigiRule-FOSS-exception",
    "eCos-exception-2.0",
    "Fawkes-Runtime-exception",
    "FLTK-exception",
    "fmt-exception",
    "Font-exception-2.0",
    "freertos-exception-2.0",
    "GCC-exception-2.0",
    "GCC-exception-3.1",
    "GNOME-examples-exception",
    "gnome-examples-exception",
    "GNU-compiler-exception",
    "i2p-gpl-java-exception",
    "KiCad-libraries-exception",
    "LGPL-3.0-linking-exception",
    "LGPL-3.0-linking-source-exception",
    "LLVM-exception",
    "LZMA-exception",
    "libtool-exception",
    "Linux-syscall-note",
    "mif-exception",
    "Nokia-Qt-exception-1.1",
    "OCCT-exception-1.0",
    "OpenVPN-openssl-exception",
    "PS-or-PDF-font-exception-20170817",
    "QPL-1.0-INRIA-2004-exception",
    "Qt-LGPL-exception-1.1",
    "Qwt-exception-1.0",
    "Swift-exception",
    "u-boot-exception-2.0",
    "Universal-FOSS-exception-1.0",
    "wxWindows-exception-3.1",
})


def _tokenize_spdx_expression(expr: str) -> list[str]:
    """
    Split an SPDX expression into license ID tokens.
    Removes AND/OR operators and parentheses. Preserves exception IDs after
    WITH by returning them separately so callers can validate in context.
    Returns only license ID tokens (not exception tokens).
    """
    import re
    parts = re.split(r"[\s()]+", expr)
    # Walk parts: skip operators AND/OR; for WITH skip the next token (exception ID)
    license_tokens: list[str] = []
    skip_next = False
    for part in parts:
        if not part:
            continue
        if skip_next:
            skip_next = False
            continue
        if part == "WITH":
            skip_next = True
            continue
        if part in ("AND", "OR"):
            continue
        license_tokens.append(part)
    return license_tokens


def _extract_exception_tokens(expr: str) -> list[str]:
    """Return the exception identifiers (tokens after WITH) from an SPDX expression."""
    import re
    parts = re.split(r"[\s()]+", expr)
    exception_tokens: list[str] = []
    capture_next = False
    for part in parts:
        if not part:
            continue
        if capture_next:
            exception_tokens.append(part)
            capture_next = False
            continue
        if part == "WITH":
            capture_next = True
    return exception_tokens
