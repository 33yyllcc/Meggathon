#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =====================================================================
#  مختبر تدريب أمني — VulnLab  (آمن للتعلّم فقط)
# =====================================================================
#  هذا التطبيق فيه ثغرات *عمداً* حتى تتدرّب عليها.
#  شغّله محلياً فقط. لا علاقة له بأي موقع حقيقي.
#
#  التشغيل:  python3 lab/vulnlab.py
#  بعدها افتح المتصفح على العنوان اللي يطبعه.
#
#  الثغرات الموجودة بيه (كل وحدة معلّمة بتعليق [[VULN]]):
#    1) SQL Injection   في صفحة تسجيل الدخول /login
#    2) Reflected XSS    في صفحة البحث         /search
#    3) IDOR             في صفحة الملف الشخصي   /profile
# =====================================================================

import http.server
import socketserver
import sqlite3
import tempfile
import os
import urllib.parse

PORT = 8000
DB_PATH = os.path.join(tempfile.gettempdir(), "vulnlab.db")


# ---------------------------------------------------------------------
# تجهيز قاعدة البيانات (نعيد بناءها كل تشغيل حتى تبقى نظيفة)
# ---------------------------------------------------------------------
def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role     TEXT,
            secret   TEXT
        );
        INSERT INTO users (id, username, password, role, secret) VALUES
          (1, 'admin', 'S3cr3t_Admin_2026', 'admin',
              'FLAG{sql_injection_master} — بيانات لوحة التحكم السرية'),
          (2, 'ahmed', 'ahmed123', 'user',
              'ملاحظة أحمد الخاصة: رقم بطاقتي 4455-1122'),
          (3, 'sara',  'qwerty',   'user',
              'ملاحظة سارة الخاصة: موقعي الحالي بغداد/الكرادة');
        """
    )
    con.commit()
    con.close()


# ---------------------------------------------------------------------
# قوالب HTML بسيطة (عربي RTL)
# ---------------------------------------------------------------------
def page(title, body):
    return f"""<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: system-ui, sans-serif; background:#0f1115; color:#e6e6e6;
         max-width:720px; margin:0 auto; padding:16px; line-height:1.7; }}
  .banner {{ background:#3a1d1d; border:1px solid #a33; color:#ffb4b4;
             padding:8px 12px; border-radius:8px; font-size:13px; margin-bottom:16px; }}
  a {{ color:#7bb3ff; }}
  nav a {{ margin-left:12px; }}
  input {{ padding:8px; border-radius:6px; border:1px solid #333; background:#1a1d24;
           color:#fff; width:100%; box-sizing:border-box; margin:6px 0; }}
  button {{ padding:9px 18px; border:0; border-radius:6px; background:#2d6cdf;
            color:#fff; cursor:pointer; }}
  .card {{ background:#161920; border:1px solid #262b36; border-radius:10px; padding:16px; }}
  code {{ background:#1a1d24; padding:2px 6px; border-radius:4px; }}
</style></head><body>
<div class="banner">⚠️ مختبر تدريب — فيه ثغرات عمداً. للتعلّم المحلي فقط.</div>
<nav><a href="/">الرئيسية</a><a href="/login">دخول</a>
<a href="/search">بحث</a><a href="/profile?id=2">ملف شخصي</a></nav>
<hr style="border-color:#262b36">
{body}
</body></html>"""


HOME = page("VulnLab", """
<h2>🧪 مختبر التدريب</h2>
<div class="card">
<p>هذا تطبيق تدريبي فيه 3 ثغرات كلاسيكية. مهمتك تلگاها وتستغلها:</p>
<ol>
  <li><b>SQL Injection</b> — صفحة <a href="/login">الدخول</a>: تگدر تدخل بدون باسورد صحيح.</li>
  <li><b>XSS</b> — صفحة <a href="/search">البحث</a>: تگدر تحقن كود جافاسكربت.</li>
  <li><b>IDOR</b> — صفحة <a href="/profile?id=2">الملف الشخصي</a>: تگدر تشوف بيانات غيرك.</li>
</ol>
<p>الحلول والشرح موجودين بملفات <code>lessons/</code>.</p>
</div>""")


def login_page(msg=""):
    return page("دخول", f"""
<h2>🔑 تسجيل الدخول</h2>
<div class="card">
<form method="POST" action="/login">
  <label>اسم المستخدم</label><input name="username" placeholder="username">
  <label>كلمة المرور</label><input name="password" type="password" placeholder="password">
  <button type="submit">دخول</button>
</form>
{msg}
</div>""")


# ---------------------------------------------------------------------
# معالج الطلبات
# ---------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, html_text, code=200):
        data = html_text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # نطبع طلبات مبسّطة
        print("  >>", self.command, self.path)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self._send(HOME)

        elif path == "/login":
            self._send(login_page())

        elif path == "/search":
            # [[VULN: Reflected XSS]] نطبع كلمة البحث بدون أي تنظيف/تهريب
            q = qs.get("q", [""])[0]
            body = f"""
            <h2>🔎 بحث</h2>
            <div class="card">
            <form method="GET" action="/search">
              <input name="q" placeholder="دور عن شي..." value="{q}">
              <button>بحث</button>
            </form>
            <p>نتائج البحث عن: {q}</p>   <!-- الثغرة هنا: q ينطبع مباشرة -->
            </div>"""
            self._send(page("بحث", body))

        elif path == "/profile":
            # [[VULN: IDOR]] نعرض أي id بدون أي تحقق هوية/صلاحية
            uid = qs.get("id", ["2"])[0]
            con = sqlite3.connect(DB_PATH)
            row = con.execute(
                "SELECT username, role, secret FROM users WHERE id = ?", (uid,)
            ).fetchone()
            con.close()
            if row:
                body = f"""<h2>👤 الملف الشخصي (id={uid})</h2>
                <div class="card">
                <p><b>المستخدم:</b> {row[0]}</p>
                <p><b>الدور:</b> {row[1]}</p>
                <p><b>السر الخاص:</b> {row[2]}</p>
                <p style="color:#888">جرّب تغيّر <code>?id=1</code> وشوف شتطلع 👀</p>
                </div>"""
            else:
                body = "<div class='card'>ماكو مستخدم بهذا id</div>"
            self._send(page("ملف شخصي", body))
        else:
            self._send(page("404", "<div class='card'>الصفحة مو موجودة</div>"), 404)

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8")
            form = urllib.parse.parse_qs(raw)
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]

            # [[VULN: SQL Injection]] نبني الاستعلام بدمج النص مباشرة (خطأ فادح)
            query = ("SELECT username, role FROM users "
                     f"WHERE username = '{user}' AND password = '{pw}'")
            print("  SQL:", query)   # نطبع الاستعلام حتى تشوف شصار
            con = sqlite3.connect(DB_PATH)
            try:
                row = con.execute(query).fetchone()
            except Exception as e:
                row = None
                print("  SQL ERROR:", e)
            con.close()

            if row:
                msg = (f"<p style='color:#6ee7a0'>✅ دخلت بنجاح! "
                       f"أهلاً <b>{row[0]}</b> (الدور: {row[1]})</p>")
            else:
                msg = "<p style='color:#ff8a8a'>❌ بيانات غلط</p>"
            self._send(login_page(msg))
        else:
            self._send(page("404", "<div class='card'>404</div>"), 404)


if __name__ == "__main__":
    init_db()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"✅ المختبر شغّال على: http://localhost:{PORT}")
        print("   أوقفه بـ Ctrl+C")
        httpd.serve_forever()
