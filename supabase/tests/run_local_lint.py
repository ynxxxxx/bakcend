import os
import re
import sys

def lint_sql_file(filepath):
    print(f"Linting SQL file: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    errors = []
    # Check for unclosed single quotes (excluding escaped ones)
    # Check basic CREATE TABLE vs RLS ENABLE
    table_matches = re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?([a-zA-Z0-9_]+)", content, re.IGNORECASE)
    rls_matches = re.findall(r"ALTER\s+TABLE\s+(?:public\.)?([a-zA-Z0-9_]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", content, re.IGNORECASE)

    missing_rls = set(table_matches) - set(rls_matches)
    if missing_rls:
        errors.append(f"Tables missing ENABLE ROW LEVEL SECURITY: {missing_rls}")

    # Check SECURITY DEFINER functions have fixed search_path
    sec_definers = re.findall(r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.([a-zA-Z0-9_]+).*?SECURITY\s+DEFINER", content, re.DOTALL | re.IGNORECASE)
    for fn in sec_definers:
        fn_pattern = rf"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.{fn}.*?SET\s+search_path"
        if not re.search(fn_pattern, content, re.DOTALL | re.IGNORECASE):
            errors.append(f"Function public.{fn} has SECURITY DEFINER without fixed search_path!")

    if errors:
        for err in errors:
            print(f"  ERROR: {err}")
        return False

    print(f"  OK: {len(table_matches)} tables validated with active RLS.")
    return True

if __name__ == "__main__":
    migrations_dir = os.path.join(os.path.dirname(__file__), "..", "migrations")
    all_ok = True
    for fname in os.listdir(migrations_dir):
        if fname.endswith(".sql"):
            p = os.path.join(migrations_dir, fname)
            if not lint_sql_file(p):
                all_ok = False
    sys.exit(0 if all_ok else 1)
