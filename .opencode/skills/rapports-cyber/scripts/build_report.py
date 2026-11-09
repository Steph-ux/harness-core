#!/usr/bin/env python3
"""Generate versioned local reports. Never execute a PoC or clean mission resources.

Input: the snapshot JSON written by `cyber_report action=snapshot`.
Output: rapport.docx, rapport.pdf, page-N.png and qa.json, inside --out.

The layout is built directly in Word: cover, computed table of contents,
running header and footer with page numbers. The table of contents is measured
on a first render and written as static entries, because LibreOffice does not
refresh a TOC field on conversion.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

YELLOW = "FFCC00"
DARK = "121212"
GREY = "5A5A5A"
RED = "A3001E"
SEVERITY_COLOR = {
    'critical': 'C62828',
    'high': 'C62828',
    'medium': 'E65100',
    'low': 'F9A825',
    'informational': '9E9E9E',
}
LABELS = {
    'vulnerability': 'Vulnérabilité',
    'observation': 'Observation',
    'not-reproduced': 'Non reproduit',
    'not-tested': 'Non testé',
    'blocked': 'Bloqué',
}
SEVERITY = {
    'informational': 'Information',
    'low': 'Faible',
    'medium': 'Moyenne',
    'high': 'Élevée',
    'critical': 'Critique',
}
MONTHS = ('janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet',
          'août', 'septembre', 'octobre', 'novembre', 'décembre')


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
    for key in ('reference','classification'):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            raise ValueError(f'Invalid snapshot field {key}')
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
            if artifact['kind']=='capture':
                path = artifact.get('path')
                if not isinstance(path,str) or not path.lower().endswith(('.png','.jpg','.jpeg')):
                    raise ValueError('A capture artifact must be a PNG or JPEG image')
                if not artifact.get('caption') or sha(path)!=artifact['sha256']:
                    raise ValueError('Capture changed or lacks a dated provenance caption')
    return data


# --------------------------------------------------------------------------
# Word primitives
# --------------------------------------------------------------------------
def rgb(value):
    from docx.shared import RGBColor
    return RGBColor.from_string(value)


def shade(element, color):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), color)
    element.append(shd)


def para_border(paragraph, side='bottom', color=YELLOW, size=12):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    pPr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement('w:pBdr')
    edge = OxmlElement(f'w:{side}')
    edge.set(qn('w:val'), 'single')
    edge.set(qn('w:sz'), str(size))
    edge.set(qn('w:space'), '4')
    edge.set(qn('w:color'), color)
    borders.append(edge)
    pPr.append(borders)


def add_field(paragraph, instruction, placeholder=''):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    run = paragraph.add_run()
    for kind in ('begin', 'instr', 'separate', 'text', 'end'):
        if kind == 'instr':
            node = OxmlElement('w:instrText')
            node.set(qn('xml:space'), 'preserve')
            node.text = instruction
        elif kind == 'text':
            node = OxmlElement('w:t')
            node.text = placeholder
        else:
            node = OxmlElement('w:fldChar')
            node.set(qn('w:fldCharType'), kind)
        run._r.append(node)


def set_style_font(style, name, size=None, bold=None, color=None):
    from docx.shared import Pt
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    style.font.name = name
    if size:
        style.font.size = Pt(size)
    if bold is not None:
        style.font.bold = bold
    if color is not None:
        style.font.color.rgb = rgb(color)
    rpr = style.element.get_or_add_rPr()
    fonts = rpr.find(qn('w:rFonts'))
    if fonts is None:
        fonts = OxmlElement('w:rFonts')
        rpr.append(fonts)
    for attr in ('w:ascii', 'w:hAnsi', 'w:cs', 'w:eastAsia'):
        fonts.set(qn(attr), name)


def setup_docx(doc):
    from docx.shared import Cm, Pt
    section = doc.sections[0]
    section.page_width, section.page_height = Cm(21), Cm(29.7)
    section.different_first_page_header_footer = True
    section.top_margin = section.bottom_margin = Cm(2.0)
    section.left_margin = section.right_margin = Cm(2.0)
    normal = doc.styles['Normal']
    set_style_font(normal, 'Calibri', 10.5, color=DARK)
    normal.paragraph_format.space_after = Pt(5)
    normal.paragraph_format.line_spacing = 1.15
    for level, size, before, after in ((1, 20, 0, 10), (2, 15.5, 18, 8),
                                       (3, 12.5, 12, 5), (4, 11, 10, 4)):
        style = doc.styles[f'Heading {level}']
        set_style_font(style, 'Calibri', size, bold=True, color=DARK)
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True
    code = doc.styles.add_style('CodeBlock', 1)
    set_style_font(code, 'Consolas', 8.5, color=DARK)
    code.paragraph_format.left_indent = Cm(0.3)
    code.paragraph_format.space_before = Pt(4)
    code.paragraph_format.space_after = Pt(8)
    code.paragraph_format.line_spacing = 1.05


def add_header_footer(section, reference, classification, client, title):
    from docx.enum.text import WD_TAB_ALIGNMENT
    from docx.shared import Cm, Pt
    header = section.header.paragraphs[0]
    header.text = ''
    run = header.add_run(f'{client} — {title}')
    run.font.size = Pt(8)
    run.font.color.rgb = rgb(GREY)
    header.alignment = 2
    footer = section.footer.paragraphs[0]
    footer.text = ''
    footer.paragraph_format.tab_stops.add_tab_stop(
        Cm(17), alignment=WD_TAB_ALIGNMENT.RIGHT)
    left = footer.add_run(f'{reference} · {classification}')
    left.font.size = Pt(8)
    left.font.color.rgb = rgb(GREY)
    footer.add_run('\t')
    add_field(footer, 'PAGE', '1')
    middle = footer.add_run(' / ')
    middle.font.size = Pt(8)
    middle.font.color.rgb = rgb(GREY)
    add_field(footer, 'NUMPAGES', '1')
    for run in footer.runs:
        run.font.size = Pt(8)
        run.font.color.rgb = rgb(GREY)
    # The cover has no running head; its footer carries the classification.
    section.first_page_header.paragraphs[0].text = ''
    first = section.first_page_footer.paragraphs[0]
    first.text = ''
    para_border(first, 'top', 'CCCCCC', 4)
    band = first.add_run(f'{classification.upper()} — DIFFUSION RESTREINTE')
    band.bold = True
    band.font.size = Pt(9)
    band.font.color.rgb = rgb(RED)


def short(value, limit):
    value = ' '.join(str(value).split())
    return value if len(value) <= limit else value[:limit - 1].rstrip() + '…'


def edition(created):
    if not created:
        return ''
    try:
        year, month, day = str(created)[:10].split('-')
        return f'{int(day)} {MONTHS[int(month) - 1]} {year}'
    except (ValueError, IndexError):
        return str(created)[:10]


def add_cover(doc, data):
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.shared import Cm, Pt
    band = doc.add_table(rows=1, cols=1)
    band.alignment = WD_TABLE_ALIGNMENT.CENTER
    band.autofit = False
    band.columns[0].width = Cm(17)
    cell = band.rows[0].cells[0]
    shade(cell._tc.get_or_add_tcPr(), YELLOW)
    first = cell.paragraphs[0]
    first.paragraph_format.space_before = Pt(14)
    first.paragraph_format.space_after = Pt(2)
    brand = first.add_run(data['client'].upper())
    brand.bold = True
    brand.font.size = Pt(14)
    sub = cell.add_paragraph()
    sub.paragraph_format.space_after = Pt(14)
    subtitle = sub.add_run('RAPPORT D’ÉVALUATION')
    subtitle.font.size = Pt(9.5)
    subtitle.font.color.rgb = rgb('333333')
    doc.add_paragraph().paragraph_format.space_after = Pt(28)
    heading = doc.add_paragraph()
    hr = heading.add_run(data['title'])
    hr.bold = True
    hr.font.size = Pt(26)
    hr.font.color.rgb = rgb(DARK)
    rule = doc.add_paragraph()
    rule.paragraph_format.space_after = Pt(22)
    para_border(rule, 'bottom', YELLOW, 24)
    rows = [
        ('Référence', data.get('reference') or data['id']),
        ('Périmètre', short(data['boundaries'], 200)),
        ('Période', data['period']),
        ('Édition', edition(data.get('createdAt'))),
    ]
    table = doc.add_table(rows=0, cols=2)
    table.autofit = False
    for key, value in rows:
        cells = table.add_row().cells
        cells[0].width, cells[1].width = Cm(4), Cm(13)
        kr = cells[0].paragraphs[0].add_run(key.upper())
        kr.font.size = Pt(8)
        kr.font.color.rgb = rgb(GREY)
        vr = cells[1].paragraphs[0].add_run(value)
        vr.font.size = Pt(10.5)
    doc.add_page_break()


def add_toc(doc, entries):
    from docx.enum.text import WD_TAB_ALIGNMENT, WD_TAB_LEADER
    from docx.shared import Cm, Pt
    title = doc.add_paragraph()
    run = title.add_run('Sommaire')
    run.bold = True
    run.font.size = Pt(18)
    title.paragraph_format.space_after = Pt(10)
    for level, text, page in entries:
        paragraph = doc.add_paragraph()
        paragraph.paragraph_format.space_after = Pt(2.6)
        paragraph.paragraph_format.left_indent = Cm(0 if level == 1 else 0.9)
        paragraph.paragraph_format.tab_stops.add_tab_stop(
            Cm(17), alignment=WD_TAB_ALIGNMENT.RIGHT, leader=WD_TAB_LEADER.DOTS)
        label = paragraph.add_run(text)
        label.font.size = Pt(10 if level == 1 else 9.2)
        number = paragraph.add_run('\t' + (str(page) if page else ''))
        number.font.size = Pt(10 if level == 1 else 9.2)
        number.font.color.rgb = rgb('666666')
    doc.add_page_break()


def add_table(doc, headers, rows):
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.shared import Pt
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    table = doc.add_table(rows=0, cols=len(headers))
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for values, header in ((headers, True), *((row, False) for row in rows)):
        cells = table.add_row().cells
        for index, value in enumerate(values):
            paragraph = cells[index].paragraphs[0]
            paragraph.paragraph_format.space_after = Pt(1)
            run = paragraph.add_run('' if value is None else str(value))
            run.font.size = Pt(8.5)
            if header:
                run.bold = True
                shade(cells[index]._tc.get_or_add_tcPr(), 'F2F2F2')
    flag = OxmlElement('w:tblHeader')
    flag.set(qn('w:val'), 'true')
    table.rows[0]._tr.get_or_add_trPr().append(flag)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def add_heading(doc, text, level, severity=None):
    from docx.shared import Pt
    paragraph = doc.add_heading('', level=level)
    if severity:
        dot = paragraph.add_run('● ')
        dot.font.color.rgb = rgb(SEVERITY_COLOR.get(severity, '9E9E9E'))
        dot.font.size = Pt(12 if level == 1 else 9)
    paragraph.add_run(text)


def add_numbered(doc, items):
    from docx.shared import Cm, Pt
    for number, item in enumerate(items, 1):
        paragraph = doc.add_paragraph()
        paragraph.paragraph_format.left_indent = Cm(0.7)
        paragraph.paragraph_format.first_line_indent = Cm(-0.5)
        paragraph.paragraph_format.space_after = Pt(2)
        paragraph.add_run(f'{number}. ')
        paragraph.add_run(item)


def add_bullets(doc, items):
    from docx.shared import Cm, Pt
    for item in items:
        paragraph = doc.add_paragraph(style='List Bullet')
        paragraph.paragraph_format.left_indent = Cm(0.7)
        paragraph.paragraph_format.space_after = Pt(1)
        paragraph.add_run(item)


def add_code(doc, text):
    paragraph = doc.add_paragraph(style='CodeBlock')
    shade(paragraph._p.get_or_add_pPr(), 'F7F7F7')
    for index, line in enumerate(str(text).strip('\n').split('\n')):
        if index:
            paragraph.add_run().add_break()
        paragraph.add_run(line)


# --------------------------------------------------------------------------
# Report body
# --------------------------------------------------------------------------
def render_body(doc, data, headings):
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Cm, Pt
    vulns = [f for f in data['findings'] if f['classification'] == 'vulnerability']
    count = ('une vulnérabilité vérifiée' if len(vulns) == 1
             else f'{len(vulns)} vulnérabilités vérifiées')
    headings.append((1, 'Synthèse'))
    add_heading(doc, 'Synthèse', 1)
    doc.add_paragraph(f'La mission a établi {count} sur le périmètre examiné. '
                      'Les fiches présentent les impacts observés, les limites et les actions correctives.')
    add_bullets(doc, [f"{f['title']} : {f['impact']}" for f in vulns])

    headings.append((1, 'Périmètre et méthode'))
    doc.add_page_break()
    add_heading(doc, 'Périmètre et méthode', 1)
    doc.add_paragraph(data['boundaries'])
    doc.add_paragraph(data['method'])
    if any(f.get('cvss') for f in data['findings']):
        doc.add_paragraph('CVSS est la propriété de FIRST et est utilisé avec sa permission. '
                          'Le score de base est calculé selon la spécification CVSS 3.1 de FIRST.')

    headings.append((1, 'Vue des constats'))
    doc.add_page_break()
    add_heading(doc, 'Vue des constats', 1)
    add_table(
        doc,
        ('Constat', 'Classement', 'Sévérité', 'Actif'),
        [(f['title'], LABELS[f['classification']], SEVERITY[f['severity']], f['asset'])
         for f in data['findings']],
    )

    for number, f in enumerate(data['findings'], 1):
        doc.add_page_break()
        title = f"Constat {number} — {f['title']}"
        headings.append((1, title))
        add_heading(doc, title, 1, f['severity'])
        meta = doc.add_paragraph()
        meta.add_run(f"{LABELS[f['classification']]} · {SEVERITY[f['severity']]} · {f['asset']}").italic = True
        if f.get('cvss'):
            doc.add_paragraph(f"CVSS 3.1 base : {cvss31(f['cvss']['vector']):.1f}/10 — {f['cvss']['vector']}")
        if f.get('businessRisk'):
            doc.add_paragraph('Risque métier : ' + f['businessRisk'])
        for heading, body in (('Description', f['description']),
                              ('Prérequis', f['preconditions']),
                              ('Impact démontré', f['impact']),
                              ('Limites', f['limitations'])):
            add_heading(doc, heading, 2)
            doc.add_paragraph(body)
        add_heading(doc, 'Reproduction', 2)
        add_numbered(doc, f['steps'])
        add_heading(doc, 'Résultats et contrôles', 2)
        for check in f.get('checks', []):
            obs = next(o for o in f['observations'] if o['id'] == check['observationId'])
            label = {'reproduction': 'Reproduction',
                     'negative-control': 'Contrôle négatif',
                     'positive-control': 'Contrôle positif'}[check['purpose']]
            doc.add_paragraph(f"{label} · {obs['timestamp']} · {obs['tool']}")
            observed = obs.get('input') or {}
            command = observed.get('command') or observed.get('argv')
            if command:
                rendered = command if isinstance(command, str) else json.dumps(command, ensure_ascii=False)
                doc.add_paragraph('Commande observée : ' + rendered[:1800])
            start = max(0, obs['output'].find(check['contains']) - 400)
            excerpt = obs['output'][start:start + 1800]
            if start or start + 1800 < len(obs['output']):
                doc.add_paragraph('Extrait de la sortie enregistrée')
            add_code(doc, excerpt)
        for artifact in f.get('artifacts', []):
            if artifact['kind'] == 'capture':
                doc.add_picture(artifact['path'], width=Cm(15.5))
                doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
                caption = doc.add_paragraph(artifact['caption'], 'Caption')
                for run in caption.runs:
                    run.italic = True
                    run.font.size = Pt(8)
                    run.font.color.rgb = rgb(GREY)
        add_heading(doc, 'Correction et critère de clôture', 2)
        add_bullets(doc, f['remediation'])
        doc.add_paragraph(f['closure'])

    headings.append((1, 'Restitution et nettoyage'))
    doc.add_page_break()
    add_heading(doc, 'Restitution et nettoyage', 1)
    doc.add_paragraph('Le nettoyage des comptes et objets de test intervient uniquement après restitution. '
                      'Son exécution et la vérification de son résultat font l’objet d’un suivi distinct, selon le mandat.')


# --------------------------------------------------------------------------
# Document assembly
# --------------------------------------------------------------------------
def parsed(payload):
    return validate(json.loads(payload.decode('utf-8')))


def body_headings(data):
    from docx import Document
    probe = Document()
    setup_docx(probe)
    headings = []
    render_body(probe, data, headings)
    return headings


def assemble(payload, pages=None):
    """Build the document. `pages` is the measured page of each heading, in order."""
    from docx import Document
    data = parsed(payload)
    classification = data.get('classification') or 'CONFIDENTIEL'
    reference = data.get('reference') or data['id']
    doc = Document()
    setup_docx(doc)
    add_header_footer(doc.sections[0], reference, classification, data['client'], data['title'])
    add_cover(doc, data)
    if pages is not None:
        entries = [(level, text, page)
                   for (level, text), page in zip(body_headings(data), pages)]
        add_toc(doc, entries)
    headings = []
    render_body(doc, data, headings)
    props = doc.core_properties
    props.title = data['title']
    props.subject = 'Rapport d’évaluation'
    props.author = data['author']
    props.category = classification
    props.language = 'fr-FR'
    return doc, data


def assemble_toc_only(payload):
    """Cover and table of contents alone: their page count fixes where the body starts."""
    from docx import Document
    data = parsed(payload)
    classification = data.get('classification') or 'CONFIDENTIEL'
    reference = data.get('reference') or data['id']
    doc = Document()
    setup_docx(doc)
    add_header_footer(doc.sections[0], reference, classification, data['client'], data['title'])
    add_cover(doc, data)
    headings = body_headings(data)
    add_toc(doc, [(level, text, 0) for level, text in headings])
    return doc, headings


def convert(directory):
    soffice = os.environ.get('SOFFICE') or shutil.which('soffice') or shutil.which('libreoffice')
    if not soffice:
        raise RuntimeError('LibreOffice (SOFFICE) is required; no PDF/QA claimed')
    with tempfile.TemporaryDirectory(prefix='report-profile-') as profile:
        subprocess.run([soffice, f'-env:UserInstallation={Path(profile).as_uri()}',
                        '--headless', '--convert-to', 'pdf', '--outdir', str(directory),
                        str(directory / 'rapport.docx')],
                       check=True, timeout=180, capture_output=True)


def measure(pdf):
    from pypdf import PdfReader
    reader = PdfReader(str(pdf))
    texts = [' '.join((page.extract_text() or '').split()) for page in reader.pages]
    return reader, texts


def locate(texts, headings, start):
    """Page of each heading, in order, searched from page `start` (1-based)."""
    pages, cursor = [], start - 1
    for _, title in headings:
        needle = ' '.join(title.split())[:60]
        found = next((index for index in range(cursor, len(texts)) if needle in texts[index]), None)
        if found is None:
            raise ValueError(f'Heading not found in the rendered report: {title}')
        pages.append(found + 1)
        cursor = found
    return pages


def build(snapshot, out):
    if snapshot.stat().st_size > 10_000_000:
        raise ValueError('Snapshot exceeds the report input limit')
    payload = snapshot.read_bytes()
    out.mkdir(parents=True, exist_ok=False)
    os.chmod(out, 0o700)
    with tempfile.TemporaryDirectory(prefix='report-build-') as staging:
        work = Path(staging) / 'report'
        probe_dir = Path(staging) / 'toc'
        work.mkdir()
        probe_dir.mkdir()
        # The cover and the table of contents always take the same number of
        # pages: measure them alone so the body page search has a fixed start.
        probe, headings = assemble_toc_only(payload)
        probe.save(str(probe_dir / 'rapport.docx'))
        convert(probe_dir)
        _, probe_texts = measure(probe_dir / 'rapport.pdf')
        start = len(probe_texts) + 1
        # First full render: read the page of each heading.
        doc, data = assemble(payload, pages=[0] * len(headings))
        doc.save(str(work / 'rapport.docx'))
        convert(work)
        _, texts = measure(work / 'rapport.pdf')
        pages = locate(texts, headings, start)
        # Second full render with the measured numbers, then verify they stay.
        doc, data = assemble(payload, pages=pages)
        doc.save(str(work / 'rapport.docx'))
        convert(work)
        reader, verified = measure(work / 'rapport.pdf')
        if locate(verified, headings, start) != pages:
            raise ValueError('Table of contents page numbers moved between renders')
        if not 1 <= len(reader.pages) <= 100:
            raise ValueError('Report page limit exceeded')
        poppler = shutil.which('pdftoppm')
        if not poppler:
            raise RuntimeError('Poppler is required; no QA claimed')
        subprocess.run([poppler, '-r', '110', '-png', str(work / 'rapport.pdf'),
                        str(work / 'page')], check=True, timeout=180, capture_output=True)
        images = sorted(work.glob('page-*.png'), key=lambda p: int(p.stem.split('-')[-1]))
        if len(images) != len(reader.pages) or any(not page.extract_text().strip() for page in reader.pages):
            raise ValueError('Incomplete rendering or empty page')
        for image in images:
            shutil.copy2(image, out / image.name)
        # rapport.docx and rapport.pdf are produced by the last render above.
        for name in ('rapport.docx', 'rapport.pdf'):
            shutil.copy2(work / name, out / name)
        qa = {
            'snapshotId': data['id'],
            'snapshotHash': sha(snapshot),
            'docxHash': sha(out / 'rapport.docx'),
            'pdfHash': sha(out / 'rapport.pdf'),
            'pages': len(images),
            'structuredChecks': True,
            'visualReview': 'pending',
            'pageImages': [{'path': p.name, 'sha256': sha(out / p.name)} for p in images],
        }
        (out / 'qa.json').write_text(json.dumps(qa, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'docx': str(out / 'rapport.docx'), 'pdf': str(out / 'rapport.pdf'),
                      'qa': str(out / 'qa.json'), 'pages': qa['pages'],
                      'visualReview': 'pending'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.snapshot.resolve(), args.out.resolve())
