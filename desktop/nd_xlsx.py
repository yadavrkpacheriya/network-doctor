# -*- coding: utf-8 -*-
"""
Network Doctor - a small Excel (.xlsx) writer and reader, so the inventory opens in Excel as a real sheet
(bold frozen header, filter buttons, column widths) and an edited sheet can be read back. Only what the app
needs: one sheet of text / number cells. No extra package (an .xlsx is a zip of small XML files).
"""
import datetime as dt
import re
import zipfile
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")   # characters XML does not allow


def col_name(i):
    """0 -> A, 25 -> Z, 26 -> AA."""
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def _col_index(ref):
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1


def _cell(ref, v, style=0):
    st = f' s="{style}"' if style else ""
    if isinstance(v, bool) or v is None:
        v = "" if v is None else ("yes" if v else "no")
    if isinstance(v, (int, float)):
        return f'<c r="{ref}"{st}><v>{v}</v></c>'
    t = _BAD.sub("", str(v))
    if not t:
        return f'<c r="{ref}"{st}/>' if style else ""
    return f'<c r="{ref}"{st} t="inlineStr"><is><t xml:space="preserve">{escape(t)}</t></is></c>'


def write(path, header, rows, widths=None, sheet="Inventory"):
    """header: list of titles; rows: list of lists (text or numbers). widths: characters per column."""
    n = len(header)
    last = f"{col_name(max(n - 1, 0))}{len(rows) + 1}"
    lines = ['<row r="1">' + "".join(_cell(f"{col_name(i)}1", h, 1) for i, h in enumerate(header)) + "</row>"]
    for ri, r in enumerate(rows, 2):
        lines.append(f'<row r="{ri}">' + "".join(_cell(f"{col_name(i)}{ri}", v) for i, v in enumerate(r[:n]))
                     + "</row>")
    cols = "".join(f'<col min="{i + 1}" max="{i + 1}" width="{max(6, min(60, w))}" customWidth="1"/>'
                   for i, w in enumerate(widths or [18] * n))
    ws = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          f'<worksheet xmlns="{_NS["m"]}"><sheetViews><sheetView workbookViewId="0">'
          '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
          f'<cols>{cols}</cols><sheetData>{"".join(lines)}</sheetData><autoFilter ref="A1:{last}"/></worksheet>')
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              f'<styleSheet xmlns="{_NS["m"]}"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
              '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
              '<fills count="3"><fill><patternFill patternType="none"/></fill>'
              '<fill><patternFill patternType="gray125"/></fill>'
              '<fill><patternFill patternType="solid"><fgColor rgb="FFDBEAFE"/></patternFill></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>'
              '</styleSheet>')
    name = escape(_BAD.sub("", sheet)[:31] or "Sheet1", {'"': "&quot;"})
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.'
            'spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-'
            'officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.'
            'spreadsheetml.styles+xml"/></Types>'),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'officeDocument" Target="xl/workbook.xml"/></Relationships>'),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<workbook xmlns="{_NS["m"]}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/'
            f'relationships"><sheets><sheet name="{name}" sheetId="1" r:id="rId1"/></sheets></workbook>'),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'worksheet" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'styles" Target="styles.xml"/></Relationships>'),
        "xl/styles.xml": styles,
        "xl/worksheets/sheet1.xml": ws,
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in parts.items():
            z.writestr(k, v)


def read(path):
    """The first sheet as a list of rows of text (what Excel saved: shared or inline text, numbers as typed)."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        shared = []
        if "xl/sharedStrings.xml" in names:
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", _NS):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t")))
        sheets = sorted(n for n in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n))
        if not sheets:
            raise ValueError("no sheet in this file")
        root = ET.fromstring(z.read(sheets[0]))
    out = []
    for row in root.iter(f"{{{_NS['m']}}}row"):
        cells = {}
        for c in row.findall("m:c", _NS):
            ref, typ = c.get("r", ""), c.get("t", "")
            v = c.find("m:v", _NS)
            if typ == "s" and v is not None:
                text = shared[int(v.text)] if v.text and int(v.text) < len(shared) else ""
            elif typ == "inlineStr":
                text = "".join(t.text or "" for t in c.iter(f"{{{_NS['m']}}}t"))
            else:
                text = (v.text or "") if v is not None else ""
                if re.fullmatch(r"-?\d+\.0+", text):
                    text = text.split(".")[0]
            if ref:
                cells[_col_index(ref)] = text
        if cells:
            out.append([cells.get(i, "") for i in range(max(cells) + 1)])
        else:
            out.append([])
    return out


def excel_date(text):
    """A date typed in Excel comes back as a day number (45413): give it back as 2024-05-01. Other text stays."""
    t = (text or "").strip()
    if re.fullmatch(r"\d{5}(\.\d+)?", t) and 20000 <= float(t) <= 80000:
        return (dt.date(1899, 12, 30) + dt.timedelta(days=int(float(t)))).isoformat()
    return t
