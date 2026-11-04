#!/usr/bin/env python3
"""Generate versioned local reports. Never execute a PoC or clean mission resources."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def sha(file):
    digest = hashlib.sha256()
    with open(file, 'rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def cvss31(vector):
    """FIRST CVSS 3.1 base score with integer-based Roundup (Appendix A)."""
    if not isinstance(vector, str) or not vector.startswith('CVSS:3.1/'):
        raise ValueError('Only CVSS 3.1 base vectors are supported')
    choices = {'AV':'NALP','AC':'LH','PR':'NLH','UI':'NR','S':'UC','C':'NLH','I':'NLH','A':'NLH'}
    m = {}
    for part in vector.split('/')[1:]:
        pair = part.split(':')
        if len(pair) != 2 or pair[0] not in choices or pair[0] in m or len(pair[1]) != 1 or pair[1] not in choices[pair[0]]:
            raise ValueError('Invalid or repeated CVSS metric')
        m[pair[0]] = pair[1]
    if set(m) != set(choices):
        raise ValueError('Incomplete CVSS vector')
    impacts = {'N':0,'L':.22,'H':.56}
    iss = 1 - math.prod(1-impacts[m[k]] for k in ('C','I','A'))
    impact = 6.42*iss if m['S']=='U' else 7.52*(iss-.029)-3.25*(iss-.02)**15
    if impact <= 0:
        return 0.0
    pr = {'N':.85,'L':.62,'H':.27} if m['S']=='U' else {'N':.85,'L':.68,'H':.5}
    exploit = 8.22*{'N':.85,'A':.62,'L':.55,'P':.2}[m['AV']]*{'L':.77,'H':.44}[m['AC']]*pr[m['PR']]*{'N':.85,'R':.62}[m['UI']]
    score = min(10,(impact+exploit)*(1 if m['S']=='U' else 1.08))
    integer = int(math.floor(score*100000+.5))
    return integer/100000 if integer%10000==0 else (integer//10000+1)/10


def validate(data):
    if data.get('schemaVersion') != 1 or data.get('cleanupPolicy') != 'after-restitution-only':
        raise ValueError('Unsupported snapshot or cleanup policy')
    for key in ('id','sourceHash','title','client','author','period','method','boundaries'):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ValueError(f'Missing snapshot field {key}')
    if not isinstance(data.get('findings'), list) or len(data['findings']) > 100:
        raise ValueError('Missing or excessive findings')
    allowed = {'vulnerability','observation','not-reproduced','not-tested','blocked'}
    for f in data['findings']:
        if f.get('classification') not in allowed:
            raise ValueError('Invalid finding classification')
        if f['classification']=='vulnerability' and (f.get('status')!='verified' or not f.get('verification')):
            raise ValueError('Unverified vulnerability')
        if not f.get('observations') or not any(o['success'] for o in f['observations']):
            raise ValueError('Finding lacks successful observations')
        for key in ('title','asset','preconditions','impact','closure','description','limitations'):
            if not isinstance(f.get(key), str) or not f[key].strip():
                raise ValueError(f'Missing finding field {key}')
        if not f.get('steps') or not f.get('remediation'):
            raise ValueError('Missing reproduction or remediation')
        if f.get('cvss'):
            score = cvss31(f['cvss'].get('vector'))
            if isinstance(f['cvss'].get('score'), bool) or f['cvss'].get('score') != score:
                raise ValueError('CVSS score does not match its vector')
        for check in f.get('checks', []):
            obs = next((o for o in f['observations'] if o['id']==check['observationId']), None)
            if not obs or not obs['success'] or check['contains'] not in obs['output']:
                raise ValueError('Missing observed control')
        for artifact in f.get('artifacts', []):
            if artifact['kind']=='capture' and (not artifact.get('caption') or sha(artifact['path'])!=artifact['sha256']):
                raise ValueError('Capture changed or lacks a dated provenance caption')
    return data


def build(snapshot, out):
    from docx import Document
    from docx.shared import Cm, Pt, RGBColor
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from pypdf import PdfReader
    if snapshot.stat().st_size > 10_000_000:
        raise ValueError('Snapshot exceeds the report input limit')
    data = validate(json.loads(snapshot.read_text(encoding='utf-8')))
    out.mkdir(parents=True, exist_ok=False)
    os.chmod(out, 0o700)
    doc = Document()
    section = doc.sections[0]
    section.page_width, section.page_height = Cm(21), Cm(29.7)
    section.top_margin = section.bottom_margin = Cm(2)
    section.left_margin = section.right_margin = Cm(2.1)
    normal = doc.styles['Normal']
    normal.font.name, normal.font.size = 'Calibri', Pt(10.5)
    normal.paragraph_format.space_after = Pt(7)
    for name in ('Title','Heading 1','Heading 2'):
        doc.styles[name].font.name = 'Calibri'
        doc.styles[name].font.color.rgb = RGBColor.from_string('111827')
    for element in doc.styles.element.iter():
        for child in list(element):
            if child.tag == qn('w:pBdr'):
                element.remove(child)
    doc.core_properties.author, doc.core_properties.title = data['author'], data['title']
    doc.add_paragraph(data['title'], 'Title')
    doc.add_paragraph(f"{data['client']}\n{data['period']}\n{data['author']}")
    doc.add_heading('Synthèse', 1)
    vulns = [f for f in data['findings'] if f['classification']=='vulnerability']
    count = 'une vulnérabilité vérifiée' if len(vulns)==1 else f'{len(vulns)} vulnérabilités vérifiées'
    doc.add_paragraph(f'La mission a établi {count} sur le périmètre examiné. Les fiches présentent les impacts observés, les limites et les actions correctives.')
    for f in vulns:
        doc.add_paragraph(f"{f['title']} : {f['impact']}",'List Bullet')
    doc.add_heading('Périmètre et méthode', 1)
    doc.add_paragraph(data['boundaries'])
    doc.add_paragraph(data['method'])
    if any(f.get('cvss') for f in data['findings']):
        doc.add_paragraph('CVSS est la propriété de FIRST et est utilisé avec sa permission. Le score de base est calculé selon la spécification CVSS 3.1 de FIRST.')
    doc.add_heading('Vue des constats', 1)
    labels = {'vulnerability':'Vulnérabilité','observation':'Observation','not-reproduced':'Non reproduit','not-tested':'Non testé','blocked':'Bloqué'}
    severity = {'informational':'Information','low':'Faible','medium':'Moyenne','high':'Élevée','critical':'Critique'}
    table = doc.add_table(rows=1, cols=3)
    table.style = 'Light Shading Accent 1'
    for cell, value in zip(table.rows[0].cells,('Constat','Classement','Actif')):
        cell.text = value
    table.rows[0]._tr.get_or_add_trPr().append(OxmlElement('w:tblHeader'))
    for f in data['findings']:
        for cell, value in zip(table.add_row().cells,(f['title'],labels[f['classification']],f['asset'])):
            cell.text = value
    for number, f in enumerate(data['findings'],1):
        doc.add_page_break()
        doc.add_heading(f"Constat {number} {f['title']}",1)
        doc.add_paragraph(f"{labels[f['classification']]} | {severity[f['severity']]} | {f['asset']}")
        if f.get('cvss'):
            doc.add_paragraph(f"CVSS 3.1 base : {cvss31(f['cvss']['vector']):.1f}/10\n{f['cvss']['vector']}")
        if f.get('businessRisk'):
            doc.add_paragraph('Risque métier : '+f['businessRisk'])
        for heading, body in (('Description',f['description']),('Prérequis',f['preconditions']),('Impact démontré',f['impact']),('Limites',f['limitations'])):
            doc.add_heading(heading,2)
            doc.add_paragraph(body)
        doc.add_heading('Reproduction',2)
        for step in f['steps']:
            doc.add_paragraph(step,'List Number')
        doc.add_heading('Résultats et contrôles',2)
        for check in f.get('checks',[]):
            obs = next(o for o in f['observations'] if o['id']==check['observationId'])
            label = {'reproduction':'Reproduction','negative-control':'Contrôle négatif','positive-control':'Contrôle positif'}[check['purpose']]
            doc.add_paragraph(f"{label} | {obs['timestamp']} | {obs['tool']}")
            observed = obs.get('input') or {}
            command = observed.get('command') or observed.get('argv')
            if command:
                doc.add_paragraph('Commande observée : '+(command if isinstance(command,str) else json.dumps(command,ensure_ascii=False))[:1800])
            start = max(0, obs['output'].find(check['contains'])-400)
            excerpt = obs['output'][start:start+1800]
            if start or start+1800 < len(obs['output']):
                doc.add_paragraph('Extrait de la sortie enregistrée')
            paragraph = doc.add_paragraph(excerpt)
            for run in paragraph.runs:
                run.font.name, run.font.size = 'DejaVu Sans Mono', Pt(8)
        for artifact in f.get('artifacts',[]):
            if artifact['kind']=='capture':
                doc.add_picture(artifact['path'],width=Cm(15.5))
                doc.add_paragraph(artifact['caption'],'Caption')
        doc.add_heading('Correction et critère de clôture',2)
        for step in f['remediation']:
            doc.add_paragraph(step,'List Bullet')
        doc.add_paragraph(f['closure'])
    doc.add_heading('Restitution et nettoyage',1)
    doc.add_paragraph('Le nettoyage des comptes et objets de test intervient uniquement après restitution. Son exécution et la vérification de son résultat font l’objet d’un suivi distinct, selon le mandat.')
    file = out/'rapport.docx'
    doc.save(file)
    soffice = os.environ.get('SOFFICE') or shutil.which('soffice') or shutil.which('libreoffice')
    poppler = shutil.which('pdftoppm')
    if not soffice or not poppler:
        raise RuntimeError('LibreOffice (SOFFICE) and Poppler are required; no PDF/QA claimed')
    with tempfile.TemporaryDirectory(prefix='report-profile-') as profile:
        subprocess.run([soffice,f'-env:UserInstallation={Path(profile).as_uri()}','--headless','--convert-to','pdf','--outdir',str(out),str(file)],check=True,timeout=90,capture_output=True)
    pdf = out/'rapport.pdf'
    reader = PdfReader(pdf)
    if not 1 <= len(reader.pages) <= 100:
        raise ValueError('Report page limit exceeded')
    subprocess.run([poppler,'-r','110','-png',str(pdf),str(out/'page')],check=True,timeout=90,capture_output=True)
    images = sorted(out.glob('page-*.png'),key=lambda p:int(p.stem.split('-')[-1]))
    if len(images)!=len(reader.pages) or any(not page.extract_text().strip() for page in reader.pages):
        raise ValueError('Incomplete rendering or empty page')
    qa = {'snapshotId':data['id'],'snapshotHash':sha(snapshot),'docxHash':sha(file),'pdfHash':sha(pdf),'pages':len(images),'structuredChecks':True,'visualReview':'pending','pageImages':[{'path':p.name,'sha256':sha(p)} for p in images]}
    (out/'qa.json').write_text(json.dumps(qa,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'docx':str(file),'pdf':str(pdf),'qa':str(out/'qa.json'),'pages':len(images),'visualReview':'pending'}))


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot',type=Path)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    build(args.snapshot.resolve(),args.out.resolve())
