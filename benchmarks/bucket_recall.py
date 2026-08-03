#!/usr/bin/env python3
"""Per-bucket recall on RealVuln: which of the v3 bug buckets did the detectors move?"""
import sys, os, json, glob, re, subprocess, collections
R, VYQL, HOME, PACKS = sys.argv[1:5]
sys.path.insert(0, R)
from parsers.base import NormalisedFinding, normalise_path
from scorer.matcher import load_ground_truth, match_findings

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

cwes={}
for f in glob.glob(os.path.join(PACKS,'**','*.vyql'), recursive=True):
    for m in re.finditer(r'meta \{([^}]*)\}', open(f).read()):
        b=m.group(1); rid=re.search(r'id: "([^"]+)"',b); c=re.findall(r'CWE_(\d+)',b)
        if rid and c: cwes[rid.group(1)]=['CWE-'+x for x in c]

tot=collections.Counter(); hit=collections.Counter()
for d in sorted(glob.glob(os.path.join(R,'repos','*'))):
    rid=os.path.basename(d)
    gtp=os.path.join(R,'ground-truth',rid,'ground-truth.json')
    if not os.path.exists(gtp): continue
    gt=load_ground_truth(gtp)
    cls={f['id']:f['vulnerability_class'] for f in gt['findings'] if f.get('is_vulnerable')}
    try:
        p=subprocess.run([VYQL,'scan','--format','sarif',d],capture_output=True,text=True,
                         env=dict(os.environ,VYQL_HOME=HOME),timeout=1800)
        sar=json.loads(p.stdout)
    except Exception:
        sar={}
    fs=[]
    for run in sar.get('runs',[]):
        for res in run.get('results') or []:
            r=res.get('ruleId') or (res.get('message') or {}).get('text') or ''
            L=res.get('locations') or []
            if not L: continue
            ph=L[0].get('physicalLocation',{})
            for cwe in cwes.get(r,[]):
                fs.append(NormalisedFinding(file=normalise_path((ph.get('artifactLocation') or {}).get('uri','')),
                    cwe=cwe,line=(ph.get('region') or {}).get('startLine'),function=None,
                    severity='medium',rule_id=r,message=None,scanner='vyql'))
    for c in cls.values(): tot[bucket(c)]+=1
    for mr in match_findings(fs,gt):
        if mr.classification=='TP' and mr.ground_truth_id in cls:
            hit[bucket(cls[mr.ground_truth_id])]+=1

print(f'{"bucket":16s} {"detected":>9s} {"of":>6s} {"recall":>8s}')
for b in ['taint','wrong-code','missing-code','access-control','other/context']:
    if tot[b]:
        print(f'{b:16s} {hit[b]:9d} {tot[b]:6d} {100*hit[b]/tot[b]:7.1f}%')
print(f'{"TOTAL":16s} {sum(hit.values()):9d} {sum(tot.values()):6d} {100*sum(hit.values())/max(sum(tot.values()),1):7.1f}%')
