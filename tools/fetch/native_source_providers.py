import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable


def _semver(text):
    match = re.search(r"(\d+\.\d+\.\d+)", str(text or ""))
    return match.group(1) if match else ""


def _branch_from_version(version):
    version_text = _semver(version)
    if not version_text:
        return ""
    parts = version_text.split(".")
    return ".".join(parts[:2])


def _underscored(version):
    version_text = _semver(version)
    return version_text.replace(".", "_") if version_text else ""


def _github_tag_candidates(repo, tags):
    out = []
    seen = set()
    for tag in tags:
        tag_text = str(tag or "").strip()
        if not tag_text or tag_text in seen:
            continue
        seen.add(tag_text)
        out.append(
            {
                "url": f"https://github.com/{repo}/archive/refs/tags/{tag_text}.tar.gz",
                "archive_name": f"{repo.split('/')[-1]}-{tag_text}.tar.gz",
            }
        )
    return out


def _libxml2_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    branch = _branch_from_version(version_text)
    return [
        {
            "url": f"https://download.gnome.org/sources/libxml2/{branch}/libxml2-{version_text}.tar.xz",
            "archive_name": f"libxml2-{version_text}.tar.xz",
        },
        {
            "url": f"https://download.gnome.org/sources/libxml2/{branch}/libxml2-{version_text}.tar.gz",
            "archive_name": f"libxml2-{version_text}.tar.gz",
        },
    ]


def _zlib_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    return [
        {
            "url": f"https://zlib.net/fossils/zlib-{version_text}.tar.gz",
            "archive_name": f"zlib-{version_text}.tar.gz",
        },
        {
            "url": f"https://www.zlib.net/zlib-{version_text}.tar.gz",
            "archive_name": f"zlib-{version_text}.tar.gz",
        },
    ]


def _expat_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    return _github_tag_candidates(
        "libexpat/libexpat",
        [
            f"R_{_underscored(version_text)}",
            f"expat-{version_text}",
        ],
    )


def _openssl_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    branch = _branch_from_version(version_text)
    return [
        {
            "url": f"https://www.openssl.org/source/openssl-{version_text}.tar.gz",
            "archive_name": f"openssl-{version_text}.tar.gz",
        },
        {
            "url": f"https://www.openssl.org/source/old/{branch}/openssl-{version_text}.tar.gz",
            "archive_name": f"openssl-{version_text}.tar.gz",
        },
        {
            "url": f"https://github.com/openssl/openssl/archive/refs/tags/openssl-{version_text}.tar.gz",
            "archive_name": f"openssl-openssl-{version_text}.tar.gz",
        },
    ]


def _libwebp_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    return [
        {
            "url": f"https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-{version_text}.tar.gz",
            "archive_name": f"libwebp-{version_text}.tar.gz",
        },
        *_github_tag_candidates("webmproject/libwebp", [f"v{version_text}", version_text]),
    ]


def _libheif_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    return _github_tag_candidates("strukturag/libheif", [f"v{version_text}", version_text])


def _freetype_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    return [
        {
            "url": f"https://download.savannah.gnu.org/releases/freetype/freetype-{version_text}.tar.xz",
            "archive_name": f"freetype-{version_text}.tar.xz",
        },
        {
            "url": f"https://download.savannah.gnu.org/releases/freetype/freetype-{version_text}.tar.gz",
            "archive_name": f"freetype-{version_text}.tar.gz",
        },
    ]


def _gdal_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    return _github_tag_candidates("OSGeo/gdal", [f"v{version_text}", version_text])


def _openh264_candidates(version):
    version_text = _semver(version)
    if not version_text:
        return []
    return _github_tag_candidates("cisco/openh264", [f"v{version_text}", version_text])


@dataclass(frozen=True)
class ComponentProvider:
    name: str
    aliases: tuple[str, ...]
    local_dirs: tuple[str, ...] = ()
    official_candidates_fn: Callable[[str], list[dict]] | None = None
    validation_markers: tuple[str, ...] = ()
    dependency_tokens: tuple[str, ...] = ()
    pkg_config_names: tuple[str, ...] = ()
    header_markers: tuple[str, ...] = ()
    binary_names: tuple[str, ...] = ()

    def matches(self, component):
        normalized = str(component or "").strip().lower()
        aliases = {alias.strip().lower() for alias in self.aliases}
        return normalized in aliases

    def official_candidates(self, version):
        if not self.official_candidates_fn:
            return []
        return list(self.official_candidates_fn(version))

    def validate_source_tree(self, source_root):
        if not source_root or not os.path.isdir(source_root):
            return {"status": "missing", "reason": "source_root_missing"}
        if not self.validation_markers:
            return {"status": "ok", "matched": []}
        matched = []
        lowered_markers = [m.lower() for m in self.validation_markers]
        for base, _, files in os.walk(source_root):
            for name in files:
                rel = os.path.relpath(os.path.join(base, name), source_root).replace("\\", "/")
                rel_lower = rel.lower()
                for marker, marker_lower in zip(self.validation_markers, lowered_markers):
                    if marker_lower in rel_lower:
                        matched.append(marker)
        if matched:
            return {"status": "ok", "matched": sorted(set(matched))}
        return {"status": "warning", "reason": "validation_markers_not_found", "matched": []}

    def markers(self):
        out = set()
        out.update(self.aliases)
        out.update(self.pkg_config_names)
        out.update(self.header_markers)
        out.update(self.dependency_tokens)
        return tuple(sorted(token for token in out if token))


PROVIDERS = [
    ComponentProvider(
        name="openh264-sys2",
        aliases=("openh264-sys2", "openh264"),
        local_dirs=("upstream",),
        official_candidates_fn=_openh264_candidates,
        validation_markers=("codec/decoder", "welsDecoderExt.cpp"),
        dependency_tokens=("openh264", "welsdecodebs", "welsdecoderext"),
        header_markers=("wels/codec_api.h",),
        binary_names=("openh264",),
    ),
    ComponentProvider(
        name="libwebp",
        aliases=("libwebp", "libwebp-sys", "webp"),
        local_dirs=("vendor",),
        official_candidates_fn=_libwebp_candidates,
        validation_markers=("src/dec/webp_dec.c", "src/webp/decode.h"),
        dependency_tokens=("libwebp", "webpdemux", "webpmux"),
        pkg_config_names=("libwebp", "libwebpdemux", "libwebpmux"),
        header_markers=("webp/decode.h", "webp/demux.h"),
        binary_names=("webp", "webpdemux", "webpmux"),
    ),
    ComponentProvider(
        name="libxml2",
        aliases=("libxml2", "libxml"),
        official_candidates_fn=_libxml2_candidates,
        validation_markers=("parser.c", "include/libxml/parser.h"),
        dependency_tokens=("libxml2", "xmlparse", "xmlreader", "xml2-config"),
        pkg_config_names=("libxml-2.0",),
        header_markers=("libxml/parser.h", "libxml/xmlreader.h"),
        binary_names=("xml2", "libxml2"),
    ),
    ComponentProvider(
        name="zlib",
        aliases=("zlib", "libz", "libz-sys"),
        official_candidates_fn=_zlib_candidates,
        validation_markers=("inflate.c", "zlib.h"),
        dependency_tokens=("zlib", "inflate", "deflate", "-lz"),
        pkg_config_names=("zlib",),
        header_markers=("zlib.h",),
        binary_names=("z", "zlib"),
    ),
    ComponentProvider(
        name="expat",
        aliases=("expat", "libexpat", "expat-sys"),
        official_candidates_fn=_expat_candidates,
        validation_markers=("expat/lib/xmlparse.c", "expat/lib/expat.h"),
        dependency_tokens=("expat", "xmlparse", "xmltok"),
        pkg_config_names=("expat",),
        header_markers=("expat.h",),
        binary_names=("expat",),
    ),
    ComponentProvider(
        name="openssl",
        aliases=("openssl", "openssl-sys", "libssl", "libcrypto"),
        official_candidates_fn=_openssl_candidates,
        validation_markers=("crypto/", "ssl/ssl_lib.c", "include/openssl/ssl.h"),
        dependency_tokens=("openssl", "libssl", "libcrypto"),
        pkg_config_names=("openssl", "libssl", "libcrypto"),
        header_markers=("openssl/ssl.h", "openssl/x509.h"),
        binary_names=("ssl", "crypto"),
    ),
    ComponentProvider(
        name="libheif",
        aliases=("libheif", "heif", "libheif-sys"),
        official_candidates_fn=_libheif_candidates,
        validation_markers=("libheif/api/libheif/heif.h", "libheif/context.cc"),
        dependency_tokens=("libheif", "heif", "x265", "de265", "aom"),
        pkg_config_names=("libheif", "libde265", "aom"),
        header_markers=("libheif/heif.h",),
        binary_names=("heif", "de265", "aom"),
    ),
    ComponentProvider(
        name="freetype",
        aliases=("freetype", "freetype-sys", "freetype2"),
        official_candidates_fn=_freetype_candidates,
        validation_markers=("include/freetype/freetype.h", "src/base/ftinit.c"),
        dependency_tokens=("freetype", "freetype2", "harfbuzz", "brotli", "png"),
        pkg_config_names=("freetype2",),
        header_markers=("freetype/freetype.h",),
        binary_names=("freetype", "freetype2"),
    ),
    ComponentProvider(
        name="gdal",
        aliases=("gdal", "gdal-sys", "libgdal"),
        official_candidates_fn=_gdal_candidates,
        validation_markers=("gcore/gdal.h", "gcore/gdaldataset.cpp"),
        dependency_tokens=("gdal", "ogr", "proj", "geotiff", "sqlite3"),
        pkg_config_names=("gdal",),
        header_markers=("gdal.h", "ogr_api.h"),
        binary_names=("gdal",),
    ),
]


def iter_providers():
    return list(PROVIDERS)


def get_provider(component):
    for provider in PROVIDERS:
        if provider.matches(component):
            return provider
    return None


def canonical_component_name(component):
    provider = get_provider(component)
    return provider.name if provider else str(component or "").strip()


def _iter_source_scan_files(source_root, max_files=600, max_size=1_500_000):
    allowed_suffixes = {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".txt",
        ".pc",
        ".cmake",
        ".in",
        ".ac",
        ".am",
        ".mk",
        ".sh",
    }
    allowed_names = {
        "cmakelists.txt",
        "configure.ac",
        "configure.in",
        "meson.build",
        "meson_options.txt",
        "makefile.am",
        "makefile.in",
        "makefile",
    }
    count = 0
    for base, _, files in os.walk(source_root):
        for name in sorted(files):
            lower = name.lower()
            _, ext = os.path.splitext(lower)
            if lower not in allowed_names and ext not in allowed_suffixes:
                continue
            path = os.path.join(base, name)
            try:
                if os.path.getsize(path) > max_size:
                    continue
            except OSError:
                continue
            yield path
            count += 1
            if count >= max_files:
                return


def infer_source_dependencies(source_root, component):
    provider = get_provider(component)
    if not provider or not source_root or not os.path.isdir(source_root):
        return []
    self_name = provider.name
    evidence = {}
    provider_by_name = {item.name: item for item in PROVIDERS}
    for path in _iter_source_scan_files(source_root):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                text = handle.read().lower()
        except Exception:
            continue
        rel = os.path.relpath(path, source_root).replace("\\", "/")
        for candidate_name, candidate in provider_by_name.items():
            if candidate_name == self_name:
                continue
            matched_tokens = []
            for token in candidate.markers():
                token_text = str(token or "").strip().lower()
                if not token_text:
                    continue
                if "/" in token_text or "." in token_text:
                    if token_text in text:
                        matched_tokens.append(token)
                else:
                    if re.search(rf"(?<![a-z0-9_]){re.escape(token_text)}(?![a-z0-9_])", text):
                        matched_tokens.append(token)
            if matched_tokens:
                row = evidence.setdefault(candidate_name, {"component": candidate_name, "files": []})
                row["files"].append({"path": rel, "tokens": sorted(set(matched_tokens))[:6]})
    out = []
    for candidate_name, row in evidence.items():
        files = row["files"]
        confidence = "medium"
        if len(files) >= 2:
            confidence = "high"
        out.append(
            {
                "component": candidate_name,
                "confidence": confidence,
                "evidence": files[:8],
            }
        )
    return sorted(out, key=lambda item: (item["component"]))
