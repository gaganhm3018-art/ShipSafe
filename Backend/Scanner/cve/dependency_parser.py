"""
ShipSafe - Dependency Parser Module
Extracts direct and transitive dependencies from Python and JavaScript manifests and lockfiles.
Prioritizes exact resolved versions from lockfiles whenever available.
"""

import os
import re
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Set

try:
    import tomllib  # Python 3.11+ standard library
except ImportError:
    try:
        import tomli as tomllib  # Fallback if Python < 3.11
    except ImportError:
        tomllib = None

logger = logging.getLogger("ShipSafe.CVE.DependencyParser")

EXCLUDED_DIR_NAMES = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".turbo",
    ".pytest_cache",
    ".mypy_cache"
}

@dataclass
class ParsedDependency:
    name: str
    version: str
    ecosystem: str  # "PyPI" or "npm"
    manifest_file: str
    is_direct: bool = True
    is_exact_version: bool = True
    raw_specifier: Optional[str] = None
    extra_metadata: Dict[str, str] = field(default_factory=dict)

class DependencyParser:
    """
    Parses dependencies safely without executing code or running package managers.
    """

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()

    def _sanitize_path(self, target_path: str) -> Path:
        """Prevent path traversal and return resolved path inside permitted workspace."""
        p = (self.workspace_root / target_path).resolve()
        # Ensure target_path is within workspace or is an absolute existing path
        if not str(p).startswith(str(self.workspace_root)):
            # Check if target_path is an absolute valid path
            cand = Path(target_path).resolve()
            if cand.exists():
                return cand
            raise ValueError(f"Directory traversal detected or invalid path: {target_path}")
        return p

    def discover_manifest_files(self, target_dir: Optional[str] = None) -> Dict[str, List[Path]]:
        """
        Locates supported manifest and lock files in the workspace.
        """
        root = self._sanitize_path(target_dir) if target_dir else self.workspace_root
        if not root.exists():
            return {}

        found_files: Dict[str, List[Path]] = {
            "requirements.txt": [],
            "poetry.lock": [],
            "Pipfile.lock": [],
            "package.json": [],
            "package-lock.json": [],
            "yarn.lock": [],
            "pnpm-lock.yaml": []
        }

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune excluded directories in-place
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")]

            for fname in filenames:
                fl = fname.lower()
                if fl in found_files or fl.endswith("requirements.txt"):
                    key = "requirements.txt" if fl.endswith("requirements.txt") else fl
                    if key in found_files:
                        found_files[key].append(Path(dirpath) / fname)

        return found_files

    def parse_all(self, target_dir: Optional[str] = None) -> List[ParsedDependency]:
        """
        Discovers all dependency files and returns normalized deduplicated dependencies.
        Prioritizes lockfile resolved versions over package.json/unpinned ranges.
        """
        root = self._sanitize_path(target_dir) if target_dir else self.workspace_root
        files_by_type = self.discover_manifest_files(str(root))
        
        all_deps: List[ParsedDependency] = []
        lockfile_packages: Set[tuple[str, str]] = set() # (name.lower(), ecosystem)

        # 1. Parse Python lockfiles first
        for pfile in files_by_type.get("poetry.lock", []):
            deps = self.parse_poetry_lock(pfile)
            for d in deps:
                lockfile_packages.add((d.name.lower(), d.ecosystem))
            all_deps.extend(deps)

        for pfile in files_by_type.get("Pipfile.lock", []):
            deps = self.parse_pipfile_lock(pfile)
            for d in deps:
                lockfile_packages.add((d.name.lower(), d.ecosystem))
            all_deps.extend(deps)

        # 2. Parse JavaScript lockfiles first
        for pfile in files_by_type.get("package-lock.json", []):
            deps = self.parse_package_lock_json(pfile)
            for d in deps:
                lockfile_packages.add((d.name.lower(), d.ecosystem))
            all_deps.extend(deps)

        for pfile in files_by_type.get("yarn.lock", []):
            deps = self.parse_yarn_lock(pfile)
            for d in deps:
                lockfile_packages.add((d.name.lower(), d.ecosystem))
            all_deps.extend(deps)

        for pfile in files_by_type.get("pnpm-lock.yaml", []):
            deps = self.parse_pnpm_lock_yaml(pfile)
            for d in deps:
                lockfile_packages.add((d.name.lower(), d.ecosystem))
            all_deps.extend(deps)

        # 3. Parse requirements.txt (Python direct manifests)
        for pfile in files_by_type.get("requirements.txt", []):
            req_deps = self.parse_requirements_txt(pfile)
            for d in req_deps:
                # If already resolved with exact version in lockfile, skip or keep as direct
                key = (d.name.lower(), d.ecosystem)
                if key not in lockfile_packages:
                    all_deps.append(d)

        # 4. Parse package.json (JavaScript direct manifests)
        for pfile in files_by_type.get("package.json", []):
            pkg_deps = self.parse_package_json(pfile)
            for d in pkg_deps:
                key = (d.name.lower(), d.ecosystem)
                # If exact lockfile already captured resolved version, don't duplicate with range
                if key not in lockfile_packages:
                    all_deps.append(d)

        # Deduplicate identical (name, version, ecosystem)
        seen = set()
        deduped = []
        for d in all_deps:
            ident = (d.name.lower(), d.version, d.ecosystem)
            if ident not in seen:
                seen.add(ident)
                deduped.append(d)

        return deduped

    # --------------------------------------------------------------------------
    # Python Parsers
    # --------------------------------------------------------------------------

    def parse_requirements_txt(self, file_path: Path) -> List[ParsedDependency]:
        """
        Parses requirements.txt for pinned dependencies (e.g. package==1.2.3).
        """
        results = []
        rel_path = self._rel_path(file_path)

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"Could not read requirements file {file_path}: {e}")
            return results

        # Regex for requirements lines: name followed by version specifiers
        # e.g., requests==2.31.0, urllib3>=1.21.1,<1.27
        req_pattern = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(?:(==|>=|<=|~=|>|<|!=)\s*([A-Za-z0-9_.\-]+))?", re.MULTILINE)

        for line in content.splitlines():
            line = line.strip()
            # Skip comments, empty lines, options (-r, -i, -f, --extra-index-url)
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Strip inline comments
            line = line.split("#")[0].strip()

            # Handle environment markers like ; python_version < '3.8'
            if ";" in line:
                line = line.split(";")[0].strip()

            match = req_pattern.match(line)
            if match:
                pkg_name = match.group(1).strip()
                op = match.group(2)
                ver = match.group(3)

                is_exact = (op == "==") and (ver is not None)
                final_version = ver if ver else "unknown"

                results.append(ParsedDependency(
                    name=pkg_name,
                    version=final_version,
                    ecosystem="PyPI",
                    manifest_file=rel_path,
                    is_direct=True,
                    is_exact_version=is_exact,
                    raw_specifier=line
                ))

        return results

    def parse_poetry_lock(self, file_path: Path) -> List[ParsedDependency]:
        """
        Parses poetry.lock containing exact resolved versions.
        """
        results = []
        rel_path = self._rel_path(file_path)

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            if tomllib:
                data = tomllib.loads(content)
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    category = pkg.get("category", "main")
                    if name and ver:
                        results.append(ParsedDependency(
                            name=name,
                            version=ver,
                            ecosystem="PyPI",
                            manifest_file=rel_path,
                            is_direct=(category == "main"),
                            is_exact_version=True,
                            raw_specifier=f"{name}=={ver}"
                        ))
            else:
                # Basic line-by-line fallback if TOML library unavailable
                name, ver = None, None
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("[[package]]"):
                        if name and ver:
                            results.append(ParsedDependency(
                                name=name, version=ver, ecosystem="PyPI",
                                manifest_file=rel_path, is_direct=True, is_exact_version=True
                            ))
                        name, ver = None, None
                    elif line.startswith("name = "):
                        name = line.split("=", 1)[1].strip().strip('"\'')
                    elif line.startswith("version = "):
                        ver = line.split("=", 1)[1].strip().strip('"\'')
                if name and ver:
                    results.append(ParsedDependency(
                        name=name, version=ver, ecosystem="PyPI",
                        manifest_file=rel_path, is_direct=True, is_exact_version=True
                    ))
        except Exception as e:
            logger.warning(f"Error parsing poetry.lock at {file_path}: {e}")

        return results

    def parse_pipfile_lock(self, file_path: Path) -> List[ParsedDependency]:
        """
        Parses Pipfile.lock containing resolved dependencies.
        """
        results = []
        rel_path = self._rel_path(file_path)

        try:
            data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
            for section, is_direct in [("default", True), ("develop", False)]:
                for pkg_name, pkg_info in data.get(section, {}).items():
                    ver_raw = pkg_info.get("version", "")
                    ver_clean = ver_raw.lstrip("=").strip() if ver_raw else "unknown"
                    results.append(ParsedDependency(
                        name=pkg_name,
                        version=ver_clean,
                        ecosystem="PyPI",
                        manifest_file=rel_path,
                        is_direct=is_direct,
                        is_exact_version=ver_raw.startswith("=="),
                        raw_specifier=ver_raw
                    ))
        except Exception as e:
            logger.warning(f"Error parsing Pipfile.lock at {file_path}: {e}")

        return results

    # --------------------------------------------------------------------------
    # JavaScript Parsers
    # --------------------------------------------------------------------------

    def parse_package_lock_json(self, file_path: Path) -> List[ParsedDependency]:
        """
        Parses package-lock.json (handles v1, v2, and v3 schema).
        Extracts exact resolved versions for both direct and transitive packages.
        """
        results = []
        rel_path = self._rel_path(file_path)

        try:
            data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
            
            # lockfileVersion 2 or 3: uses "packages" map
            packages = data.get("packages")
            if isinstance(packages, dict):
                for pkg_path, meta in packages.items():
                    if not pkg_path: # root project
                        continue
                    if not isinstance(meta, dict):
                        continue
                    
                    # Extract package name: either meta["name"] or from path "node_modules/..."
                    pkg_name = meta.get("name")
                    if not pkg_name:
                        parts = pkg_path.split("node_modules/")
                        pkg_name = parts[-1] if len(parts) > 1 else pkg_path
                    
                    ver = meta.get("version")
                    if pkg_name and ver:
                        # Direct dependency if it's directly under node_modules/<name> without nesting
                        is_direct = pkg_path.count("node_modules/") == 1 and not meta.get("dev", False)
                        results.append(ParsedDependency(
                            name=pkg_name,
                            version=str(ver),
                            ecosystem="npm",
                            manifest_file=rel_path,
                            is_direct=is_direct,
                            is_exact_version=True,
                            raw_specifier=f"{pkg_name}@{ver}"
                        ))

            # lockfileVersion 1: uses recursive "dependencies"
            dependencies = data.get("dependencies")
            if isinstance(dependencies, dict) and not results:
                self._parse_v1_npm_dependencies(dependencies, rel_path, results, is_direct=True)

        except Exception as e:
            logger.warning(f"Error parsing package-lock.json at {file_path}: {e}")

        return results

    def _parse_v1_npm_dependencies(self, deps_dict: Dict, rel_path: str, out: List[ParsedDependency], is_direct: bool):
        for pkg_name, meta in deps_dict.items():
            if isinstance(meta, dict):
                ver = meta.get("version")
                if ver:
                    out.append(ParsedDependency(
                        name=pkg_name,
                        version=str(ver),
                        ecosystem="npm",
                        manifest_file=rel_path,
                        is_direct=is_direct,
                        is_exact_version=True,
                        raw_specifier=f"{pkg_name}@{ver}"
                    ))
                # Recursive transitive dependencies
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    self._parse_v1_npm_dependencies(nested, rel_path, out, is_direct=False)

    def parse_package_json(self, file_path: Path) -> List[ParsedDependency]:
        """
        Parses direct dependencies from package.json.
        """
        results = []
        rel_path = self._rel_path(file_path)

        try:
            data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})

            for name, spec in {**deps, **dev_deps}.items():
                if isinstance(spec, str):
                    # Clean range symbols (^, ~, >=) for heuristic version fallback
                    clean_ver = re.sub(r"^[~^><= ]+", "", spec).strip()
                    is_exact = not any(spec.startswith(c) for c in ["^", "~", ">", "<", "*"])
                    results.append(ParsedDependency(
                        name=name,
                        version=clean_ver if clean_ver else "unknown",
                        ecosystem="npm",
                        manifest_file=rel_path,
                        is_direct=True,
                        is_exact_version=is_exact,
                        raw_specifier=spec
                    ))
        except Exception as e:
            logger.warning(f"Error parsing package.json at {file_path}: {e}")

        return results

    def parse_yarn_lock(self, file_path: Path) -> List[ParsedDependency]:
        """
        Parses yarn.lock for resolved package versions.
        """
        results = []
        rel_path = self._rel_path(file_path)

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            current_names = []
            
            for line in content.splitlines():
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue

                if line.endswith(":") and not line.startswith(" "):
                    # Header line: "package@^1.0.0", "package@^1.2.0":
                    entries = [e.strip(' ":') for e in line_str.split(",")]
                    current_names = []
                    for entry in entries:
                        # Extract name before @ (handling scoped packages like @scope/pkg@1.0.0)
                        if entry.startswith("@"):
                            parts = entry[1:].split("@")
                            pkg_name = f"@{parts[0]}"
                        else:
                            pkg_name = entry.split("@")[0]
                        if pkg_name:
                            current_names.append(pkg_name)
                elif line_str.startswith("version ") and current_names:
                    ver = line_str.split("version", 1)[1].strip().strip('"\'')
                    for name in set(current_names):
                        results.append(ParsedDependency(
                            name=name,
                            version=ver,
                            ecosystem="npm",
                            manifest_file=rel_path,
                            is_direct=True,
                            is_exact_version=True,
                            raw_specifier=f"{name}@{ver}"
                        ))
                    current_names = []
        except Exception as e:
            logger.warning(f"Error parsing yarn.lock at {file_path}: {e}")

        return results

    def parse_pnpm_lock_yaml(self, file_path: Path) -> List[ParsedDependency]:
        """
        Parses pnpm-lock.yaml for resolved dependencies.
        """
        results = []
        rel_path = self._rel_path(file_path)

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            # In pnpm-lock.yaml, packages are defined like:
            # /package@1.2.3: or '/@scope/pkg@1.2.3':
            pkg_pattern = re.compile(r"^['\"]?/?(@?[a-zA-Z0-9_\-./]+)@([0-9a-zA-Z_\-+.]+)['\"]?:\s*$", re.MULTILINE)
            for match in pkg_pattern.finditer(content):
                name = match.group(1).lstrip("/")
                ver = match.group(2)
                results.append(ParsedDependency(
                    name=name,
                    version=ver,
                    ecosystem="npm",
                    manifest_file=rel_path,
                    is_direct=True,
                    is_exact_version=True,
                    raw_specifier=f"{name}@{ver}"
                ))
        except Exception as e:
            logger.warning(f"Error parsing pnpm-lock.yaml at {file_path}: {e}")

        return results

    def _rel_path(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.workspace_root)).replace("\\", "/")
        except ValueError:
            return p.name
