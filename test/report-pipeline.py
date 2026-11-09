"""Report contracts, plus an optional real Word/PDF render."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('report',ROOT/'.opencode/skills/rapports-cyber/scripts/build_report.py')
REPORT=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)
class ReportContract(unittest.TestCase):
    def test_known_vectors(self):
        for vector,expected in [('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',9.8),('AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',4.3),('AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',10.0),('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',0.0)]:
            self.assertEqual(REPORT.cvss31('CVSS:3.1/'+vector),expected)
    def test_invalid_vectors(self):
        for vector in ['CVSS:4.0/AV:N','CVSS:3.1/AV:N','CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']:
            with self.assertRaises(ValueError): REPORT.cvss31(vector)
    def test_coverage_contract(self):
        base=json.loads((ROOT/'test/fixtures/report-snapshot.json').read_text())
        REPORT.validate(base)
        bad=copy.deepcopy(base); bad['coverage']['owasp'].append({'id':'A99:2020','status':'tested','note':''})
        with self.assertRaises(ValueError): REPORT.validate(bad)
        mute=copy.deepcopy(base); mute['coverage']['mitre'].append({'id':'T1000','status':'not-tested','note':''})
        with self.assertRaises(ValueError): REPORT.validate(mute)
    def test_evidence_and_score(self):
        data=json.loads((ROOT/'test/fixtures/report-snapshot.json').read_text());REPORT.validate(data)
        for mutate in [lambda f:f.update(status='unverified'),lambda f:f.update(observations=[]),lambda f:f['cvss'].update(score=9.9)]:
            changed=copy.deepcopy(data);mutate(changed['findings'][0])
            with self.assertRaises(ValueError): REPORT.validate(changed)
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--render',action='store_true');parser.add_argument('--out',type=Path);args=parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReportContract))
    if not result.wasSuccessful():raise SystemExit(1)
    if args.render:
        if args.out:REPORT.build(ROOT/'test/fixtures/report-snapshot.json',args.out.resolve())
        else:
            with tempfile.TemporaryDirectory(prefix='report-smoke-') as root:REPORT.build(ROOT/'test/fixtures/report-snapshot.json',Path(root)/'output')
