#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
att_pii_scan.py — 公示 / 名单类页面与附件的 PII 泄露扫描器

设计目标：把「名单页 -> 下载附件 -> 解包找未脱敏源表」这条链一步到位，
最关键的检查项是 OOXML 里的 **外部链接缓存**（xl/externalLinks/*.xml）——
正文列已脱敏、缓存里却是未脱敏源表全量。

零第三方依赖（仅标准库）。可选增强：本地装了 xlrd / pypdf 会额外解析 .xls / .pdf。

用法示例
--------
  # 扫一个公示页面：自动展开页面里的附件并逐个扫描
  python att_pii_scan.py "https://www.example.edu.cn/html/183/2026-05-22/content-14798.shtml"

  # 直接扫附件（URL 或本地路径都可，可一次传多个）
  python att_pii_scan.py "https://www.example.edu.cn/attachment/sites/item/2026_05/22_18/xxx.xlsx"

  # 批量：文件里每行一个 URL
  python att_pii_scan.py --input urls.txt --json result.json

  # 需要原始号做取证时（默认脱敏，慎用）
  python att_pii_scan.py <目标> --show-full --save ./evidence

判定口径
--------
  身份证号：GB11643 校验位 + 行政区码 + 出生年份，三者同时成立才算「确认泄露」。
  掩码形态（如 4521242003****2127）：**不算**泄露，单独计数。
  银行卡号：16~19 位 + Luhn 校验通过（且不是已识别的身份证号）。
  身份证/手机号/银行卡/住址 任一出现都值得写进报告，但定级不同。

授权提醒：只对已获书面授权的目标使用；本脚本只发 GET、不写目标、不做枚举爆破。
"""

import argparse
import html
import io
import json
import os
import re
import ssl
import sys
import time
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
ATT_EXT = (".xlsx", ".xlsm", ".xls", ".et", ".ett", ".docx", ".doc", ".wps", ".wpt",
           ".pptx", ".ppt", ".dps", ".pdf", ".zip", ".rar", ".7z", ".csv", ".tsv", ".rtf")

# ---------------------------------------------------------------- PII 规则

W_GB = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
CK_GB = "10X98765432"
REGION2 = set("11 12 13 14 15 21 22 23 31 32 33 34 35 36 37 41 42 43 44 45 46 "
              "50 51 52 53 54 61 62 63 64 65 71 81 82".split())

RE_ID = re.compile(r"(?<![0-9A-Za-z])(\d{17}[\dXx])(?![0-9A-Za-z])")
RE_MASK = re.compile(r"(?<![0-9])\d{2,6}[*＊×xX]{2,}\d{0,6}(?![0-9])")
RE_PHONE = re.compile(r"(?<![0-9])1[3-9]\d{9}(?![0-9])")
RE_LONGNUM = re.compile(r"(?<![0-9])(\d{15,20})(?![0-9])")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\.[A-Za-z]{2,}")
RE_ADDR = re.compile(r"[\u4e00-\u9fa5]{2,12}(?:省|自治区|特别行政区)[^\s，,。;；|]{2,60}"
                     r"(?:号|村|组|队|巷|路|街|室|栋|号楼|小区|社区)")
RE_HDR_WORD = re.compile(r"姓名|身份证|手机|联系电话|电话|银行|账号|账\s*号|住址|地址|学号|"
                         r"考生号|准考证|家庭住址|开户")
# 银行卡 BIN 前缀（银联 62 为主，兼容 Visa 4 / Master 5 / JCB 35 等）
BANK_PREFIX = ("62", "60", "58", "56", "55", "54", "53", "52", "51", "45", "43",
               "42", "41", "40", "37", "35", "34", "4", "5")


def id_ok(s, born_min=1900, born_max=None):
    """GB11643-1999 校验位 + 行政区码 + 出生日期合法性"""
    s = s.upper()
    if len(s) != 18 or not s[:17].isdigit():
        return False
    if CK_GB[sum(int(s[i]) * W_GB[i] for i in range(17)) % 11] != s[17]:
        return False
    if s[:2] not in REGION2:
        return False
    y, m, d = int(s[6:10]), int(s[10:12]), int(s[12:14])
    if born_max is None:
        born_max = time.localtime().tm_year
    if not (born_min <= y <= born_max and 1 <= m <= 12 and 1 <= d <= 31):
        return False
    return True


def luhn(s):
    tot = 0
    for i, ch in enumerate(reversed(s)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        tot += n
    return tot % 10 == 0


def bank_like(s):
    """纯数字 + 长度 + BIN 前缀 + Luhn；必须显式挡掉带 X 的身份证号"""
    return bool(s) and s.isdigit() and 16 <= len(s) <= 19 and s.startswith(BANK_PREFIX) and luhn(s)


def mask_id(s):
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


def mask_phone(s):
    return s[:3] + "****" + s[-4:]


def mask_num(s):
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


def mask_addr(s):
    return re.sub(r"\d", "*", s[:14]) + ("…" if len(s) > 14 else "")


def mask_email(s):
    local, _, dom = s.partition("@")
    return (local[:2] + "***@" + dom)


def pii_scan(text, born_min=1900, born_max=None):
    """从任意文本里抽取 PII 类目（返回去重后的原始值）

    银行卡给两级口径，报告里必须写清用的是哪一级：
      bank_form —— 16~19 位纯数字且不是身份证号（宽口径，容易误收学号/流水号）
      bank      —— 再加 BIN 前缀 + Luhn 校验（严口径，更可信）
    """
    ids_raw = set(RE_ID.findall(text))
    ids_ok = {i for i in ids_raw if id_ok(i, born_min, born_max)}
    phones = set(RE_PHONE.findall(text))
    bank_form, banks = set(), set()
    for n in RE_LONGNUM.findall(text):
        # 排除「身份证号本体」和「身份证号被截断后的片段」——
        # 例：11010519491231002X 里的前 17 位会被当成 17 位纯数字，误报成银行卡
        if len(n) >= 15 and any(n == i or i.startswith(n) or n.startswith(i) for i in ids_raw):
            continue
        if 16 <= len(n) <= 19:
            bank_form.add(n)
            if bank_like(n):
                banks.add(n)
    masks = set(m for m in RE_MASK.findall(text) if len(m) >= 8)
    addrs = set(RE_ADDR.findall(text))
    emails = set(RE_EMAIL.findall(text))
    hdrs = set(RE_HDR_WORD.findall(text))
    return {
        "id_raw": ids_raw, "id_ok": ids_ok, "phone": phones,
        "bank": banks, "bank_form": bank_form,
        "mask": masks, "addr": addrs, "email": emails, "hdr": hdrs,
    }


def add_pii(dst, src):
    for k in ("id_raw", "id_ok", "phone", "bank", "bank_form", "mask", "addr", "email", "hdr"):
        dst.setdefault(k, set()).update(src.get(k, ()))
    return dst


# ------------------------------------------------- 列语义核验（防误报核心）

RE_ROW = re.compile(r"<row[^>]*\br=\"(\d+)\"[^>]*>(.*?)</row>", re.S)
RE_CELL = re.compile(r"<(?:c|cell)\b[^>]*\br=\"([A-Z]+)(\d+)\"[^>]*>(.*?)</(?:c|cell)>", re.S)
RE_VAL = re.compile(r"<v>(.*?)</v>|<t[^>]*>(.*?)</t>", re.S)
RE_TAGS = re.compile(r"<[^>]+>")

HDR_ID = re.compile(r"身份证|证件号|公民身份")
HDR_BANK = re.compile(r"银行|账号|账\s*号|卡号")
HDR_OTHER = re.compile(r"学号|考号|准考证|手机|电话|住址|地址|姓名")


def _cellval(inner):
    """取单元格文本值。

    必须做 XML 实体反转义：真实案例里有一条身份证号写成
    `<v>469022200507170323&#10;</v>`（尾部换行实体），只 strip 不去实体的话
    `re.fullmatch` 会判为不合格 → 统计少 1 条（1607 vs 真值 1608）。
    """
    m = RE_VAL.search(inner)
    if not m:
        return ""
    return html.unescape(RE_TAGS.sub("", (m.group(1) or m.group(2) or ""))).strip()


def col_profile(raw, born_min=1900, born_max=None):
    """按「表头 -> 列」的语义统计，而不是把整份 XML 当一坨文本

    为什么需要：银行账号列里偶尔会出现 18 位数字，其中约 1/11 会偶然通过
    身份证校验位。只做全文正则统计会把这几个数错算成身份证号（真实案例：
    H 列"开户银行账号"里 6 个 18 位数字全过校验位）。报告里必须用列语义口径。
    """
    rows = RE_ROW.findall(raw)
    if len(rows) < 2:
        return None
    parsed = []
    for rn, body in rows:
        cells = {}
        for m in RE_CELL.finditer(body):
            cells[m.group(1)] = _cellval(m.group(3))
        if cells:
            parsed.append((int(rn), cells))
    if len(parsed) < 2:
        return None

    hdr, hdr_row = {}, None
    for rn, cells in parsed:
        joined = " ".join(cells.values())
        if HDR_ID.search(joined) or HDR_BANK.search(joined):
            hdr, hdr_row = cells, rn
            break
    if not hdr:
        return None

    id_cols = sorted(c for c, v in hdr.items() if HDR_ID.search(v))
    bank_cols = sorted(c for c, v in hdr.items() if HDR_BANK.search(v))
    prof = {"header": {c: v for c, v in hdr.items() if v},
            "header_row": hdr_row, "rows": len(parsed),
            "id_cols": id_cols, "bank_cols": bank_cols,
            "id_in_id_cols": 0, "id_in_other": {}, "id_shape_other": {},
            "bank_in_bank_cols": 0}

    for rn, cells in parsed:
        if rn == hdr_row:
            continue
        for c, v in cells.items():
            v = v.strip()
            shape = bool(RE_ID.fullmatch(v))
            if shape:
                if c in id_cols:
                    if id_ok(v, born_min, born_max):
                        prof["id_in_id_cols"] += 1
                else:
                    # 非身份证列里出现的 18 位数字：过校验位的要亮红灯（会污染口径），
                    # 不过校验位的也要列出来给人复核（多为银行账号/学号）
                    if id_ok(v, born_min, born_max):
                        prof["id_in_other"][c] = prof["id_in_other"].get(c, 0) + 1
                    else:
                        prof["id_shape_other"][c] = prof["id_shape_other"].get(c, 0) + 1
            if bank_like(v) and c in bank_cols:
                prof["bank_in_bank_cols"] += 1
    return prof


# ---------------------------------------------------------------- 抓取

def http_get(url, timeout=45):
    import urllib.request
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "close",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, dict(r.headers), r.read(), r.geturl()


def load(target, timeout=45):
    """返回 (data, meta)；本地路径直接读盘"""
    if re.match(r"^https?://", target, re.I):
        st, hd, data, final = http_get(target, timeout)
        return data, {"status": st, "ctype": hd.get("Content-Type", ""),
                      "clen": hd.get("Content-Length", ""), "final": final}
    with open(target, "rb") as f:
        return f.read(), {"status": 200, "ctype": "local", "clen": "", "final": target}


def sniff(data, url=""):
    if data[:2] == b"PK":
        return "zip"
    if data[:4] == b"\xd0\xcf\x11\xe0":
        return "ole"
    if data[:5] == b"%PDF-":
        return "pdf"
    head = data[:2048].decode("utf-8", "ignore").lower()
    if "<html" in head or "<!doctype html" in head or "<?xml" in head and "<html" in head:
        return "html"
    low = url.split("?")[0].lower()
    if low.endswith((".html", ".htm", ".shtml", ".jsp", ".asp", ".aspx", ".php")):
        return "html"
    if low.endswith((".xlsx", ".xlsm", ".docx", ".pptx")):
        return "zip"
    if low.endswith((".xls", ".doc", ".ppt")):
        return "ole"
    if low.endswith(".pdf"):
        return "pdf"
    return "text"


def find_att_links(html, base):
    import urllib.parse
    hrefs = re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", html, re.I)
    # 正文里直接以纯文本出现的路径（有些站点把附件地址写在 JS 里）
    hrefs += re.findall(r"""["']([^"'<>]{4,200}?\.(?:%s))["']""" % "|".join(
        e.lstrip(".") for e in ATT_EXT), html, re.I)
    out, seen = [], set()
    for h in hrefs:
        h = h.strip()
        if h.lower().startswith(("javascript:", "mailto:", "#", "data:")):
            continue
        if not h.lower().split("?")[0].endswith(ATT_EXT):
            continue
        full = urllib.parse.urljoin(base, h)
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out


def looks_like_login(status, ctype, data):
    if status in (401, 403) or 300 <= status < 400:
        return True
    if "text/html" in (ctype or "").lower():
        t = data[:6000].decode("utf-8", "ignore")
        if re.search(r"请登录|用户登录|login|统一身份认证|请输入账号", t, re.I) and \
           not re.search(r"<table|名单|公示|身份证", t):
            return True
    return False


# ---------------------------------------------------------------- 容器解包

CRIT_PREFIX = ("xl/externalLinks/", "xl/queryTables/", "customXml/")
CRIT_EXACT = ("xl/connections.xml", "docProps/custom.xml", "xl/vbaProject.bin",
              "word/settings.xml")


def zip_collect(data):
    """解包 OOXML；返回 (载体文本 list[(entry,text,kind)], 元信息 dict)"""
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    parts, meta = [], {"entries": names, "hidden_sheets": [], "ext_target": [],
                       "creators": set(), "sheet_names": []}

    def rd(n):
        try:
            return z.read(n).decode("utf-8", "replace")
        except Exception:
            return ""

    for n in names:
        if not (n.endswith(".xml") or n.endswith(".rels")):
            continue
        kind = "critical" if (n.startswith(CRIT_PREFIX) or n in CRIT_EXACT) else "other"
        raw = rd(n)
        if not raw:
            continue
        parts.append((n, re.sub(r"<[^>]+>", " ", raw), kind, raw))

    # 二进制部件（VBA 宏常把台账硬编码在里面）
    for n in names:
        if n.endswith(".bin"):
            try:
                b = z.read(n)
                txt = b.decode("utf-16-le", "ignore") + " " + b.decode("latin-1", "ignore")
                parts.append((n, txt, "critical", None))
            except Exception:
                pass

    # 隐藏工作表：workbook.xml 的 state 属性
    wb = rd("xl/workbook.xml")
    for tag in re.findall(r"<sheet\b[^>]*>", wb):
        nm = re.search(r'name="([^"]*)"', tag)
        st = re.search(r'state="([^"]*)"', tag)
        if nm:
            meta["sheet_names"].append(nm.group(1))
            if st and st.group(1).lower() in ("hidden", "veryhidden"):
                meta["hidden_sheets"].append(nm.group(1))

    # 外部数据源的原始落盘路径（会顺带暴露内部用户名/磁盘结构）
    for n in names:
        if "/_rels/" in n and "externalLink" in n or n.endswith("workbook.xml.rels"):
            for t in re.findall(r'Target="([^"]+)"[^>]*TargetMode="External"', rd(n)):
                meta["ext_target"].append(t)

    # 文档属性里的作者 / 最后修改人
    for n in ("docProps/core.xml", "docProps/app.xml"):
        raw = rd(n)
        for tag in ("dc:creator", "cp:lastModifiedBy", "Manager", "Company"):
            m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), raw, re.S)
            if m and m.group(1).strip():
                meta["creators"].add("%s=%s" % (tag, m.group(1).strip()[:80]))
    meta["creators"] = sorted(meta["creators"])
    return parts, meta


def ole_collect(data):
    """老格式 .xls/.doc/.ppt：有 xlrd 就正经读，没有就双编码裸扫"""
    parts, meta = [], {"entries": ["OLE(compound file)"], "hidden_sheets": [],
                       "ext_target": [], "creators": [], "sheet_names": []}
    try:
        import xlrd
        wb = xlrd.open_workbook(file_contents=data)
        for sh in wb.sheets():
            if getattr(sh, "visibility", 0):
                meta["hidden_sheets"].append(sh.name)
            meta["sheet_names"].append(sh.name)
            rows = []
            for r in range(min(sh.nrows, 5000)):
                rows.append(" ".join(str(sh.cell_value(r, c)) for c in range(min(sh.ncols, 40))))
            parts.append(("sheet:" + sh.name, "\n".join(rows), "other", None))
    except Exception:
        pass
    if not parts:
        parts.append(("raw:utf16le", data.decode("utf-16-le", "ignore"), "other", None))
        parts.append(("raw:gb18030", data.decode("gb18030", "ignore"), "other", None))
        parts.append(("raw:latin1", data.decode("latin-1", "ignore"), "other", None))
    try:
        import olefile  # 可选
        if olefile.isOleFile(io.BytesIO(data)):
            for s in olefile.OleFileIO(io.BytesIO(data)).listdir():
                meta["entries"].append("/".join(s))
    except Exception:
        pass
    return parts, meta


def pdf_collect(data):
    parts, meta = [], {"entries": ["PDF"], "hidden_sheets": [], "ext_target": [],
                       "creators": [], "sheet_names": []}
    txt = ""
    for mod, ok in (("pypdf", lambda: None), ("PyPDF2", lambda: None)):
        try:
            m = __import__(mod)
            rd = m.PdfReader(io.BytesIO(data))
            txt = " ".join((p.extract_text() or "") for p in rd.pages[:200])
            meta["entries"].append("PDF 文本层(%s) 已解析" % mod)
            break
        except Exception:
            continue
    if not txt:
        txt = data.decode("latin-1", "ignore")
        meta["entries"].append("PDF 文本层未解析（装了 pypdf 可解析更准），结果为下限")
    parts.append(("pdf:text", txt, "other", None))
    return parts, meta


def html_collect(data):
    raw = data.decode("utf-8", "ignore")
    if not raw.strip():
        raw = data.decode("gb18030", "ignore")
    txt = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.S | re.I)
    txt = re.sub(r"<[^>]+>", " ", txt)
    return [("html:body", txt, "other", None)], {"entries": ["HTML"], "hidden_sheets": [],
                                                 "ext_target": [], "creators": [], "sheet_names": []}


def text_collect(data):
    return [("text", data.decode("utf-8", "ignore") + " " + data.decode("gb18030", "ignore"),
             "other", None)], \
           {"entries": ["text"], "hidden_sheets": [], "ext_target": [], "creators": [], "sheet_names": []}


# ---------------------------------------------------------------- 主流程

def scan_one(target, args, depth=0):
    rep = {"target": target, "ok": False, "error": "", "carriers": [], "col_profiles": [],
           "pii": {}, "entries_n": 0, "attachments": []}
    try:
        data, meta = load(target, args.timeout)
    except Exception as e:
        rep["error"] = "%s: %s" % (type(e).__name__, e)
        return rep

    rep["status"] = meta.get("status")
    rep["bytes"] = len(data)
    rep["ctype"] = meta.get("ctype")
    rep["ok"] = True

    if looks_like_login(rep["status"], rep.get("ctype"), data):
        rep["error"] = "疑似需要登录 / 被拦截（状态 %s），匿名可达性需人工确认" % rep["status"]

    kind = sniff(data, target)
    rep["kind"] = kind

    if kind == "html":
        links = find_att_links(data.decode("utf-8", "ignore") or data.decode("gb18030", "ignore"), target)
        rep["attachments"] = links
        parts, cmeta = html_collect(data)
    elif kind == "zip":
        parts, cmeta = zip_collect(data)
    elif kind == "ole":
        parts, cmeta = ole_collect(data)
    elif kind == "pdf":
        parts, cmeta = pdf_collect(data)
    else:
        parts, cmeta = text_collect(data)

    rep["meta"] = {k: (sorted(v) if isinstance(v, set) else v) for k, v in cmeta.items()}
    rep["entries_n"] = len(cmeta.get("entries", []))

    total = {}
    for name, txt, ckind, raw in parts:
        p = pii_scan(txt, args.born_min, args.born_max)
        prof = col_profile(raw, args.born_min, args.born_max) if raw else None
        if not any(p[k] for k in ("id_raw", "phone", "bank", "bank_form", "mask", "addr", "email")):
            continue
        add_pii(total, p)
        car = {
            "entry": name, "kind": ckind,
            "id_ok": len(p["id_ok"]), "id_raw": len(p["id_raw"]),
            "phone": len(p["phone"]), "bank": len(p["bank"]),
            "bank_form": len(p["bank_form"]),
            "mask": len(p["mask"]), "addr": len(p["addr"]),
            "sample_id": [mask_id(x) for x in sorted(p["id_ok"])[:3]],
        }
        if prof:
            car["col_profile"] = prof
            rep.setdefault("col_profiles", []).append({"entry": name, **prof})
        rep["carriers"].append(car)
    rep["pii"] = {k: sorted(v) for k, v in total.items()}
    return rep


def verdict(rep):
    if not rep.get("ok"):
        return "⚪ 抓取失败", 0
    p = rep.get("pii", {})
    ids = p.get("id_ok", [])
    raw = p.get("id_raw", [])
    bank = p.get("bank", [])
    phone = p.get("phone", [])
    addr = p.get("addr", [])
    profs = rep.get("col_profiles") or []
    col_ids = max([x.get("id_in_id_cols", 0) for x in profs], default=None)
    if ids:
        if col_ids is not None:
            return ("🔴 确认泄露：身份证号列 %d 行过校验（列语义口径；全文口径去重 %d 个，"
                    "报告用前者）" % (col_ids, len(ids))), 3
        return "🔴 确认泄露：%d 个校验通过的完整身份证号（匿名可达）" % len(ids), 3
    if bank or (phone and addr):
        return "🟠 疑似泄露：%d 银行卡 / %d 手机号 / %d 住址，但无校验通过的身份证号" % (
            len(bank), len(phone), len(addr)), 2
    if phone or addr or p.get("mask"):
        if p.get("mask") and not phone and not addr:
            return "🟡 已脱敏：仅见 %d 处掩码形态，通常不算泄露（建议人工确认掩码位数）" % len(p["mask"]), 1
        return "🟠 疑似泄露：%d 手机号 / %d 住址（无身份证号）" % (len(phone), len(addr)), 2
    if raw:
        return "🟡 有 %d 个 18 位数字但未过校验（疑似占位/伪造），人工复核" % len(raw), 1
    return "✅ 未发现 PII", 0


def render(rep, args):
    L = []
    tag = rep["target"]
    if not rep.get("ok"):
        L.append("⚪ [抓取失败] %s  <- %s" % (tag, rep.get("error")))
        return "\n".join(L)
    v, _lvl = verdict(rep)
    L.append("=" * 96)
    L.append("%s   %s" % (v, tag))
    L.append("  HTTP=%s  %s bytes  type=%s(%s)  zip条目=%d" % (
        rep.get("status"), rep["bytes"], rep.get("ctype"), rep.get("kind"), rep["entries_n"]))
    if rep.get("error"):
        L.append("  ⚠ %s" % rep["error"])

    m = rep.get("meta", {})
    if m.get("hidden_sheets"):
        L.append("  ⚠ 隐藏工作表: %s" % ", ".join(m["hidden_sheets"]))
    if m.get("ext_target"):
        L.append("  ⚠ 外部数据源落盘路径(暴露内部路径/用户名): %s" % ", ".join(m["ext_target"][:5]))
    if m.get("creators"):
        L.append("  · 文档属性: %s" % "; ".join(m["creators"]))

    p = rep.get("pii", {})
    L.append("  身份证号: 校验通过=%d / 18位形态=%d   手机号=%d   银行卡: Luhn通过=%d / 16-19位形态=%d"
             % (len(p.get("id_ok", [])), len(p.get("id_raw", [])), len(p.get("phone", [])),
                len(p.get("bank", [])), len(p.get("bank_form", []))))
    L.append("  住址(启发式，仅作下限参考)=%d   掩码形态(不算泄露)=%d"
             % (len(p.get("addr", [])), len(p.get("mask", []))))

    crit = [c for c in rep["carriers"] if c["kind"] == "critical"]
    if crit:
        L.append("  ★ 未脱敏数据载体（重点证据）:")
        for c in sorted(crit, key=lambda x: -(x["id_ok"] + x["phone"] + x["bank"])):
            if c["id_ok"] or c["phone"] or c["bank"] or c["addr"]:
                L.append("      - %s  id=%d phone=%d bank=%d addr=%d"
                         % (c["entry"], c["id_ok"], c["phone"], c["bank"], c["addr"]))
    others = [c for c in rep["carriers"] if c["kind"] != "critical"]
    if others:
        L.append("  其他含 PII 的部件:")
        for c in sorted(others, key=lambda x: -(x["id_ok"] + x["phone"] + x["bank"]))[:6]:
            L.append("      - %s  id=%d phone=%d bank=%d addr=%d"
                     % (c["entry"], c["id_ok"], c["phone"], c["bank"], c["addr"]))

    if m.get("sheet_names") and rep.get("kind") == "zip":
        L.append("  工作表: %s" % ", ".join(m["sheet_names"][:12]))

    show = args.show_full
    if p.get("id_ok"):
        s = sorted(p["id_ok"])[:5]
        L.append("  样例身份证号%s: %s" % ("(原文)" if show else "(脱敏)", " ".join(s if show else map(mask_id, s))))

    # 列语义核验：报告数字以此为准，别用全文口径
    for prof in rep.get("col_profiles", []):
        hdr = prof.get("header", {})
        L.append("  ── 列语义核验（报告口径以此为准）──")
        for c in prof.get("id_cols", []):
            L.append("     %s 列「%s」: 校验通过的身份证号 = %d" % (c, hdr.get(c, ""), prof["id_in_id_cols"]))
        if not prof.get("id_cols"):
            L.append("     ⚠ 未找到「身份证」语义列（表头可能被删），只能用全文口径，需人工复核")
        for c, n in sorted(prof.get("id_in_other", {}).items(), key=lambda x: -x[1]):
            L.append("     ⚠ %s 列「%s」里有 %d 个 18 位数字也通过了校验位 —— 极可能是银行账号/学号，"
                     "属误报，**不计入**身份证泄露" % (c, hdr.get(c, "?"), n))
        for c, n in sorted(prof.get("id_shape_other", {}).items(), key=lambda x: -x[1]):
            L.append("     · %s 列「%s」有 %d 个 18 位数字（未过校验位/非本人生日），"
                     "已排除在身份证统计外，人工复核一下即可" % (c, hdr.get(c, "?"), n))
        if prof.get("bank_cols"):
            L.append("     %s 列「%s」疑似银行卡号 = %d"
                     % (",".join(prof["bank_cols"]),
                        "/".join(hdr.get(c, "") for c in prof["bank_cols"]),
                        prof.get("bank_in_bank_cols", 0)))
        L.append("     表头: %s" % " | ".join("%s=%s" % (k, v) for k, v in list(hdr.items())[:16]))
    if p.get("phone"):
        s = sorted(p["phone"])[:4]
        L.append("  样例手机号%s: %s" % ("(原文)" if show else "(脱敏)", " ".join(s if show else map(mask_phone, s))))
    if p.get("bank"):
        s = sorted(p["bank"])[:4]
        L.append("  样例银行卡%s: %s" % ("(原文)" if show else "(脱敏)", " ".join(s if show else map(mask_num, s))))
    if p.get("addr"):
        s = sorted(p["addr"])[:2]
        L.append("  样例住址%s: %s" % ("(原文)" if show else "(脱敏)", " ".join(s if show else map(mask_addr, s))))

    if rep.get("attachments"):
        L.append("  页面附件(%d):" % len(rep["attachments"]))
        for a in rep["attachments"][:20]:
            L.append("      %s" % a)
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="公示/名单类附件 PII 泄露扫描器（零依赖）")
    ap.add_argument("targets", nargs="*", help="URL 或本地文件路径")
    ap.add_argument("--input", help="URL 清单文件（每行一个）")
    ap.add_argument("--json", dest="json_out", help="把结构化结果写入该 JSON")
    ap.add_argument("--save", help="把原始附件另存到该目录（取证用，含未脱敏数据，慎用）")
    ap.add_argument("--show-full", action="store_true", help="输出未脱敏样例（默认全部脱敏）")
    ap.add_argument("--no-expand", action="store_true", help="HTML 页面不再自动展开附件")
    ap.add_argument("--depth", type=int, default=1, help="页面 -> 附件 的展开层数，默认 1")
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--born-min", type=int, default=1900)
    ap.add_argument("--born-max", type=int, default=None, help="默认当前年份；高校学生可设 2012")
    ap.add_argument("--only-hit", action="store_true", help="只打印有命中的目标")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.input:
        with open(args.input, encoding="utf-8", errors="replace") as f:
            targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not targets:
        ap.print_help()
        return 2

    results, hits = [], 0
    for t in targets:
        rep = scan_one(t, args)
        results.append(rep)
        text = render(rep, args)
        _v, lvl = verdict(rep)
        if lvl >= 2:
            hits += 1
        if args.only_hit and lvl < 2:
            continue
        print(text)
        sys.stdout.flush()

        # HTML 页面：自动展开附件
        if rep.get("kind") == "html" and not args.no_expand and args.depth >= 1 and rep.get("attachments"):
            for a in rep["attachments"]:
                sub = scan_one(a, args)
                results.append(sub)
                _v2, lvl2 = verdict(sub)
                if lvl2 >= 2:
                    hits += 1
                if args.only_hit and lvl2 < 2:
                    continue
                print(render(sub, args))
                sys.stdout.flush()

        if args.save:
            try:
                data, _ = load(t, args.timeout)
                os.makedirs(args.save, exist_ok=True)
                name = re.sub(r"[^A-Za-z0-9._-]", "_", t.split("?")[0].rsplit("/", 1)[-1])[:80] or "att.bin"
                with open(os.path.join(args.save, name), "wb") as f:
                    f.write(data)
            except Exception as e:
                print("  (保存失败 %s)" % e)

    print("=" * 96)
    print("扫描 %d 个目标，命中（疑似及以上）%d 个" % (len(results), hits))
    if args.json_out:
        out = []
        for r in results:
            rr = json.loads(json.dumps(r, ensure_ascii=False, default=list))
            if not args.show_full:
                def _m(k, v):
                    if k in ("id_ok", "id_raw"):
                        return [mask_id(x) for x in v]
                    if k == "phone":
                        return [mask_phone(x) for x in v]
                    if k in ("bank", "bank_form"):
                        return [mask_num(x) for x in v]
                    if k == "mask":
                        return ["<掩码形态>"] * len(v)
                    if k == "addr":
                        return [mask_addr(x) for x in v]
                    if k == "email":
                        return [mask_email(x) for x in v]
                    return v
                rr["pii"] = {k: _m(k, v) for k, v in rr.get("pii", {}).items()}
                rr["_note"] = "PII 样例已脱敏；如需原文用 --show-full（并注意别把原文提交到公开渠道）"
            rr["verdict"] = verdict(r)[0]
            out.append(rr)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("JSON 已写入 %s" % args.json_out)
    return 0 if hits == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
