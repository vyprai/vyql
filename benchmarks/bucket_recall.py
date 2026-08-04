#!/usr/bin/env python3
"""Per-bucket recall on RealVuln: which of the v3 bug buckets did the detectors move?

Shares score_realvuln.py's scan and finding construction, so the rule -> CWE mapping
comes from VyQL's own SARIF rule metadata rather than a second copy of a regex over
vyql/packs/**.
"""
import sys, os, glob, collections
R, VYQL, HOME = sys.argv[1:4]
sys.path.insert(0, R)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scorer.matcher import load_ground_truth, match_findings
import score_realvuln as srv

srv.RV, srv.VYQL, srv.VYQL_HOME = R, VYQL, HOME

TAINT={'sql_injection','stored_xss','reflected_xss','dom_xss','xss','path_traversal','command_injection',
       'open_redirect','insecure_deserialization','ssrf','xxe','code_injection','template_injection',
       'ldap_injection','xpath_injection','nosql_injection','remote_file_inclusion','http_header_injection',
       'http_parameter_pollution'}
WRONG={'security_misconfiguration','hardcoded_credentials','weak_cryptography','insecure_cookie',
       'weak_hashing','weak_hash','insecure_randomness','weak_prng','insecure_transport',
       'weak_password_policy','plaintext_password_storage','clickjacking','password_complexity_bypass'}
MISSING={'csrf','csrf_bypass','missing_rate_limiting','missing_authentication','missing_security_headers',
         'session_fixation','improper_session_management','insecure_session','session_management',
         'session_hijacking','broken_authentication','weak_password_recovery'}
ACCESS={'missing_access_control','idor','privilege_escalation','insecure_direct_object_reference',
        'mass_assignment','credential_enumeration'}
def bucket(c):
    if c in TAINT: return 'taint'
    if c in WRONG: return 'wrong-code'
    if c in MISSING: return 'missing-code'
    if c in ACCESS: return 'access-control'
    return 'other/context'

tot=collections.Counter(); hit=collections.Counter()
for d in sorted(glob.glob(os.path.join(R,'repos','*'))):
    rid=os.path.basename(d)
    gtp=os.path.join(R,'ground-truth',rid,'ground-truth.json')
    if not os.path.exists(gtp): continue
    gt=load_ground_truth(gtp)
    cls={f['id']:f['vulnerability_class'] for f in gt['findings'] if f.get('is_vulnerable')}
    try:
        fs, _ = srv.to_findings(srv.scan(d), {})
    except Exception:
        fs = []
    for c in cls.values(): tot[bucket(c)]+=1
    # one credit per ground-truth entry: a rule carrying N CWEs is fanned out to N
    # findings for matching, and without this a single detection counts N times.
    seen=set()
    for mr in match_findings(fs,gt):
        if mr.classification=='TP' and mr.ground_truth_id in cls:
            if mr.ground_truth_id in seen: continue
            seen.add(mr.ground_truth_id)
            hit[bucket(cls[mr.ground_truth_id])]+=1

print(f'{"bucket":16s} {"detected":>9s} {"of":>6s} {"recall":>8s}')
for b in ['taint','wrong-code','missing-code','access-control','other/context']:
    if tot[b]:
        print(f'{b:16s} {hit[b]:9d} {tot[b]:6d} {100*hit[b]/tot[b]:7.1f}%')
print(f'{"TOTAL":16s} {sum(hit.values()):9d} {sum(tot.values()):6d} {100*sum(hit.values())/max(sum(tot.values()),1):7.1f}%')
