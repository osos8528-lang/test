#!/usr/bin/env python3
"""Workshop quality gate, deliberately scoped rather than a security certificate.

Stage 1: Python AST patterns (JS/TS use limited text patterns).
Stage 2: pytest with a main.py line-coverage threshold.
Stage 3: a set microbenchmark and a static WAL execute-call check.
No stage claims to measure real HTTP p99 or production availability.
"""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "tests", "test", "templates", "harness", ".pytest_cache"}
SQL_WORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\s", re.IGNORECASE)
SECRET_NAMES = re.compile(r"password|secret|token|api_?key", re.IGNORECASE)


def print_header(title):
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def finding(rule, path, line, message, stage="Security"):
    # Do not copy source lines or secret values into logs/reports.
    return {"stage": stage, "rule": rule, "file": str(path), "line": line, "message": message}


def audit_python(source, path):
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [finding("Source Parse Error", path, exc.lineno or 1, "Python 구문 분석 실패")]
    results = []
    for node in ast.walk(tree):
        dynamic = isinstance(node, ast.JoinedStr) or (
            isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
        ) or (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
        )
        if dynamic:
            fragments = " ".join(
                child.value for child in ast.walk(node)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            )
            if SQL_WORDS.search(fragments):
                results.append(finding("CWE-89 (Dynamic SQL)", path, node.lineno, "SQL 문자열 조합 발견. 매개변수 바인딩 여부를 검토하세요."))

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [child.id for target in targets for child in ast.walk(target) if isinstance(child, ast.Name)]
            if any(SECRET_NAMES.search(name) for name in names):
                value = node.value
                literal = isinstance(value, ast.Constant) and isinstance(value.value, str) and bool(value.value)
                fallback = (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and value.func.attr in {"getenv", "get"}
                    and (
                        (len(value.args) >= 2 and isinstance(value.args[1], ast.Constant) and isinstance(value.args[1].value, str) and bool(value.args[1].value))
                        or any(kw.arg == "default" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str) and bool(kw.value.value) for kw in value.keywords)
                    )
                )
                if literal or fallback:
                    results.append(finding("CWE-798 (Hardcoded Secret)", path, node.lineno, "비밀값 또는 비밀값의 기본값을 코드에 저장하지 마세요."))

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"md5", "sha1"}:
            results.append(finding("CWE-327 (Weak Hash)", path, node.lineno, "MD5/SHA-1 사용 목적을 검토하세요. 비밀번호에는 적절한 비밀번호 해시를 사용하세요."))

        if isinstance(node, ast.ExceptHandler):
            broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"})
            empty = all(isinstance(child, ast.Pass) or (
                isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant) and child.value.value is Ellipsis
            ) for child in node.body)
            if broad and empty:
                results.append(finding("Silent Failure (Empty Except)", path, node.lineno, "광범위한 예외를 아무 처리 없이 무시하는 구문입니다."))
    # Nested string expressions can point to the same issue.
    return list({(item["rule"], item["line"]): item for item in results}.values())


def stage1_security_audit():
    print("[Stage 1] Python AST / limited JS-TS pattern scan")
    results = []
    scanned = 0
    for root, dirs, files in os.walk("."):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in sorted(files):
            path = Path(root) / name
            if path.suffix not in {".py", ".js", ".ts"}:
                continue
            scanned += 1
            try:
                source = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeError):
                results.append(finding("Source Read Error", path, 1, "소스 파일을 읽지 못했습니다. 검사를 통과로 처리하지 않습니다."))
                continue
            if path.suffix == ".py":
                results.extend(audit_python(source, path))
            else:
                for line, text in enumerate(source.splitlines(), 1):
                    if re.search(r"createHash\(['\"](?:md5|sha1)['\"]\)", text):
                        results.append(finding("CWE-327 (Weak Hash)", path, line, "약한 해시 패턴 발견"))
                    if re.search(r"(?i)(password|secret|token|api_?key)\s*=\s*['\"][^'\"]+['\"]", text):
                        results.append(finding("CWE-798 (Hardcoded Secret)", path, line, "비밀값 문자열 대입 패턴 발견"))
                    if SQL_WORDS.search(text) and (("$" + "{") in text or " + " in text):
                        results.append(finding("CWE-89 (Dynamic SQL)", path, line, "동적 SQL 의심 패턴 발견"))
    if not scanned:
        results.append(finding("No Source Files", ".", 0, "검사할 소스 파일이 없습니다."))
    print(f"  scanned={scanned}, findings={len(results)}")
    for item in results:
        print(f"  FAIL [{item['rule']}] {item['file']}:{item['line']} {item['message']}")
    return results


def stage2_unit_tests():
    print("\n[Stage 2] Automated tests and main.py coverage >= 85%")
    test_dirs = [name for name in ("tests", "test") if Path(name).is_dir()]
    if not any(
        path.name.startswith("test_") or path.name.endswith("_test.py")
        for folder in test_dirs for path in Path(folder).rglob("*.py")
    ):
        print("  FAIL: 테스트 파일이 없습니다.")
        return [finding("Missing Tests", ".", 0, "테스트가 없으므로 검증을 통과할 수 없습니다.", "Tests")]
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", *test_dirs, "-q", "--tb=short",
             "--cov=main", "--cov-report=term-missing", "--cov-fail-under=85"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return [finding("Test Timeout", ".", 0, "테스트가 180초 제한을 넘었습니다.", "Tests")]
    print(result.stdout)
    if result.returncode:
        return [finding("Unit Test / Coverage Failure", ".", 0, (result.stdout + result.stderr)[-2000:], "Tests")]
    print("  PASS: 작성된 테스트와 커버리지 기준 통과")
    return []


def stage3_performance_benchmark():
    print("\n[Stage 3] Set microbenchmark and static WAL call check")
    results = []
    start = time.perf_counter()
    sample = set(range(50000))
    for _ in range(1000):
        _ = 49999 in sample
    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f"  Set construction + 1000 lookups: {elapsed_ms:.2f}ms (not HTTP p99)")
    if elapsed_ms > 100:
        results.append(finding("Microbenchmark Threshold", ".", 0, f"집합 예제 계산 {elapsed_ms:.2f}ms > 100ms", "Performance"))
    has_wal = False
    for filename in ("main.py", "app.py"):
        path = Path(filename)
        if not path.exists():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, SyntaxError):
            continue  # Stage 1 reports source errors separately.
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"execute", "executescript"} and node.args):
                continue
            value = node.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if re.search(r"\bPRAGMA\s+journal_mode\s*=\s*WAL\b", value.value, re.IGNORECASE):
                    has_wal = True
    if not has_wal:
        results.append(finding("Missing SQLite WAL Call", ".", 0, "SQLite 실행 구문에서 WAL 설정을 확인하지 못했습니다.", "Performance"))
    print("  WAL execute-call present" if has_wal else "  FAIL: WAL execute-call missing")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--security-only", action="store_true", help="Run the source scan only (used by the PR review job).")
    args = parser.parse_args()
    print_header("Campus Harness Verification Engine")
    issues = stage1_security_audit()
    if not args.security_only:
        issues += stage2_unit_tests()
        issues += stage3_performance_benchmark()
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "REJECTED" if issues else "APPROVED",
        "scope": "security-patterns" if args.security_only else "workshop-checks",
        "total_failures": len(issues), "failures": issues,
        "limitations": "Limited static checks and written tests; not a complete security audit or HTTP SLA certification.",
    }
    Path("harness_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print_header("Harness Evaluation Summary")
    print(f"[RED GATE] {len(issues)} finding(s)" if issues else "[GREEN] Specified checks passed; production safety is not guaranteed.")
    print("Report: harness_report.json")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
