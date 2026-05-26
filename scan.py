import sys as _sys
import os as _os
#_sys.path.insert(0, _os.path.dirname(_os.path.abspath(_file_)))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

import config as _cfg
from scanner.client import SupabaseClient as _Client
from scanner.cli import parse_args as _parse, module_active as _active
from scanner import (
    jwt_analyzer as _A,
    table_scanner as _B,
    storage_scanner as _C,
    auth_scanner as _D,
    headers_scanner as _E,
    injection_scanner as _F,
    edge_scanner as _G,
    rls_analyzer as _H,
    idor_scanner as _I,
    infra_scanner as _J,
    scoring as _K,
    reporter as _L,
)


def _chk(_a, _b):
    _x = []
    if not _a or "your-project-ref" in _a:
        _x.append("SUPABASE_URL is not configured")
    if not _b or "your-anon-key" in _b:
        _x.append("ANON_KEY is not configured")
    return _x


def _out(_m, _q=False):
    if not _q:
        print(f"  \033[96m→\033[0m {_m}...")


def _go():
    _p = _parse()
    _u = _p["url"] or getattr(_cfg, "SUPABASE_URL", "")
    _k = _p["key"] or getattr(_cfg, "ANON_KEY", "")
    _sk = _p["service_key"] or getattr(_cfg, "SERVICE_ROLE_KEY", "") or ""
    _q = _p["quiet"]
    _e = _chk(_u, _k)
    if _e:
        print("\033[91m[ERROR] Fix config.py before running:\033[0m")
        for _x in _e:
            print(f"  - {_x}")
        _sys.exit(1)
    _u = _u.rstrip("/")
    _f = []
    if not _q:
        print(f"\n\033[1mStarting scan against:\033[0m {_u}\n")
    
    def _mod(_n):
        return _active(_n, _p)
    
    # JWT
    if _mod("jwt"):
        _out("Analyzing JWT token(s)", _q)
        _f += _A.analyze(_k, label="anon_key")
        if _sk:
            _f += _A.analyze(_sk, label="service_role_key")
    
    # Infra
    if _mod("infra"):
        _out("Checking TLS", _q)
        _f += _J.check_tls(_u, label="anon")
    
    if _mod("headers"):
        _out("Checking HTTP security headers", _q)
        _f += _E.scan_headers(_u, _k, label="anon")
    
    _cli = _Client(_u, _k)
    
    if _mod("infra"):
        _out("Probing infrastructure endpoints", _q)
        _f += _J.scan_endpoints(_u, _k, label="anon")
        _f += _J.scan_common_files(_u, label="anon")
    
    if _mod("graphql"):
        _out("Testing GraphQL introspection", _q)
        _f += _J.scan_graphql_introspection(_u, _k, label="anon")
    
    _tbls = []
    if _mod("tables"):
        _out("Discovering and reading tables via schema", _q)
        _f += _G.scan_postgrest_info(_cli, label="anon")
        _tbl_f, _tbls = _B.scan_tables(_cli, label="anon")
        _f += _tbl_f
    
    if _mod("rpc"):
        _out("Probing RPC functions", _q)
        _f += _B.scan_rpc(_cli, label="anon")
    
    if _mod("bruteforce"):
        _out("Brute-forcing common table names", _q)
        _bf_f, _bf_t = _B.brute_common_tables(_cli, label="anon")
        _f += _bf_f
        _tbls = list(set(_tbls + _bf_t))
    
    # RLS
    if _mod("rls"):
        _out("Analyzing RLS policies and row exposure", _q)
        _f += _H.scan_rls(_cli, _tbls, label="anon")
        _f += _H.estimate_data_exposure(_cli, _tbls, label="anon")
    
    if _mod("idor"):
        _out("Testing for IDOR and horizontal privilege escalation", _q)
        _f += _I.scan_idor(_cli, _tbls, label="anon")
        _f += _I.scan_horizontal_privilege_escalation(_cli, _tbls, label="anon")
    
    if _mod("injection"):
        _out("Testing PostgREST injection vectors", _q)
        _f += _F.scan_injections(_cli, _tbls, label="anon")
    
    if _mod("mass_assignment"):
        _out("Testing mass assignment on exposed tables", _q)
        _f += _F.scan_mass_assignment(_cli, _tbls, label="anon")
    
    if _mod("storage"):
        _out("Scanning storage buckets", _q)
        _f += _C.scan_storage(_cli, label="anon")
    
    if _mod("auth"):
        _out("Probing auth configuration", _q)
        _f += _D.scan_auth_config(_cli, label="anon")
        _out("Testing email enumeration", _q)
        _f += _D.scan_email_enumeration(_cli, label="anon")
        _out("Probing auth endpoints and brute-force protection", _q)
        _f += _D.scan_auth_endpoints(_cli, label="anon")
    
    if _mod("magic_link"):
        _out("Testing magic link endpoint", _q)
        _f += _D.scan_magic_link(_cli, label="anon")
    
    if _mod("edges"):
        _out("Probing edge functions", _q)
        _f += _G.scan_edge_functions(_cli, label="anon")
    
    if _mod("realtime"):
        _out("Checking realtime endpoint", _q)
        _f += _G.scan_realtime(_cli, label="anon")
    
    if _sk:
        if not _q:
            print(f"\n  \033[93m→\033[0m Re-scanning with service role key...")
        _svc = _Client(_u, _sk)
        if _mod("tables"):
            _svc_f, _ = _B.scan_tables(_svc, label="service_role")
            _f += _svc_f
        if _mod("storage"):
            _f += _C.scan_storage(_svc, label="service_role")
        if _mod("auth"):
            _f += _D.scan_auth_endpoints(_svc, label="service_role")
    
    _L.print_findings(_f, _u)
    _K.print_score_card(_f)
    _sd = _K.score_to_dict(_f)
    _saved = []
    if not _p["no_json"]:
        _saved.append(("JSON    ", _L.save_json(_f, _u, score_data=_sd)))
    if not _p["no_md"]:
        _saved.append(("Markdown", _L.save_markdown(_f, _u)))
    if not _p["no_html"]:
        _saved.append(("HTML    ", _L.save_html(_f, _u)))
    if _saved and not _q:
        print("  Reports saved:")
        for _fmt, _path in _saved:
            print(f"    {_fmt} → {_path}")
        print()


if __name__ == "__main__":
    _go()
