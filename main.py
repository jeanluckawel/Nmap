import flet as ft
import nmap
import threading
import time
import smtplib
from datetime import datetime
from email.message import EmailMessage
import io
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import asyncio


class ScanApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.scan_history = []

        self.page.title = "🛡️ Scanner Réseau"
        self.page.scroll = True

        self.txt_target = ft.TextField(label="Cible IP", width=300, value="192.168.1.0/24")
        self.scan_type_dropdown = ft.Dropdown(
            label="Type de scan",
            options=[
                ft.dropdown.Option("Scan rapide"),
                ft.dropdown.Option("Scan complet"),
            ],
            width=300,
            value="Scan rapide"
        )

        self.result_output = ft.Text(value="", selectable=True, size=12, color="#00FF00")
        self.loading = ft.ProgressRing()

        self.table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("ID")),
                ft.DataColumn(ft.Text("CIBLE")),
                ft.DataColumn(ft.Text("TYPE")),
                ft.DataColumn(ft.Text("DATE")),
                ft.DataColumn(ft.Text("DURÉE")),
                ft.DataColumn(ft.Text("⚠️ Critique")),
                ft.DataColumn(ft.Text("🟠 Moyenne")),
                ft.DataColumn(ft.Text("🔵 Faible")),
            ],
            rows=[],
        )

        self.btn_scan = ft.ElevatedButton(text="🚀 Scanner", on_click=self.start_scan)
        self.btn_send_mail = ft.ElevatedButton(text="📤 Envoyer par Email", on_click=lambda e: self.send_email(self.result_output.value))
        self.btn_rescan = ft.OutlinedButton(text="🔁 Rescanner", on_click=self.start_scan)

        # Boutons export
        self.btn_csv = ft.ElevatedButton("📄 Export CSV", on_click=lambda e: self.export_csv())
        self.btn_excel = ft.ElevatedButton("📊 Export Excel", on_click=lambda e: self.export_excel())
        self.btn_pdf = ft.ElevatedButton("📕 Export PDF", on_click=lambda e: self.export_pdf())

        self.page.add(
            ft.Column([
                ft.Row([self.txt_target, self.scan_type_dropdown], spacing=20),
                self.btn_scan,
                ft.Divider(),
                self.table,
                ft.Divider(),
                ft.Container(self.result_output, height=200, bgcolor="#1e1e1e", padding=10, border_radius=10),
                ft.Row([self.btn_send_mail, self.btn_rescan], spacing=10),
                ft.Row([self.btn_csv, self.btn_excel, self.btn_pdf], spacing=10),
            ], spacing=20)
        )

    def update_table(self):
        self.table.rows = [
            ft.DataRow(cells=[
                ft.DataCell(ft.Text(scan["id"])),
                ft.DataCell(ft.Text(scan["target"])),
                ft.DataCell(ft.Text(scan["type"])),
                ft.DataCell(ft.Text(scan["date"])),
                ft.DataCell(ft.Text(scan["duration"])),
                ft.DataCell(ft.Text(scan["vuln_critique"])),
                ft.DataCell(ft.Text(scan["vuln_moyenne"])),
                ft.DataCell(ft.Text(scan["vuln_faible"])),
            ])
            for scan in reversed(self.scan_history)
        ]
        self.page.update()

    def run_scan(self, target, scan_type):
        # Assure-toi que nmap est dans le PATH, sinon erreur
        nm = nmap.PortScanner()
        if scan_type == "Scan rapide":
            nm.scan(hosts=target, arguments="-T4 -F")
        else:
            nm.scan(hosts=target, arguments="-T4 -A")

        return nm.csv()

    def start_scan(self, e):
        target = self.txt_target.value
        scan_type = self.scan_type_dropdown.value

        if not target or not scan_type:
            self.page.snack_bar = ft.SnackBar(ft.Text("❌ Veuillez remplir tous les champs."), bgcolor="#FF4C4C")
            self.page.snack_bar.open = True
            self.page.update()
            return

        self.result_output.value = "⏳ Scan en cours..."
        self.page.update()

        def scan_thread():
            try:
                start_time = time.time()
                result = self.run_scan(target, scan_type)
                duration = round(time.time() - start_time, 2)

                self.result_output.value = result

                # Simule des vulnérabilités, à adapter selon résultats réels du scan
                vuln_critique = "1"
                vuln_moyenne = "2"
                vuln_faible = "3"

                self.scan_history.append({
                    "id": f"#{len(self.scan_history)+1:03d}",
                    "target": target,
                    "type": scan_type,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "duration": f"{duration}s",
                    "vuln_critique": vuln_critique,
                    "vuln_moyenne": vuln_moyenne,
                    "vuln_faible": vuln_faible
                })

                self.update_table()
            except Exception as ex:
                self.result_output.value = f"Erreur lors du scan : {str(ex)}"
            self.page.update()

        threading.Thread(target=scan_thread).start()

    def send_email(self, report):
        try:
            msg = EmailMessage()
            msg.set_content(report)
            msg["Subject"] = "Rapport de Scan Réseau"
            msg["From"] = "scanner@example.com"
            msg["To"] = "admin@example.com"

            with smtplib.SMTP("smtp.example.com", 587) as server:
                server.starttls()
                server.login("scanner@example.com", "mot_de_passe")
                server.send_message(msg)

            self.page.snack_bar = ft.SnackBar(ft.Text("📧 Email envoyé avec succès !"), bgcolor="#22c55e")
        except Exception as ex:
            self.page.snack_bar = ft.SnackBar(ft.Text(f"Échec de l'envoi : {str(ex)}"), bgcolor="#ef4444")
        self.page.snack_bar.open = True
        self.page.update()

    async def save_file(self, filename: str, content: bytes):
        # Méthode async pour le téléchargement (Flet >0.5.4)
        await self.page.download(filename, content)
        self.page.snack_bar = ft.SnackBar(ft.Text(f"{filename} prêt pour téléchargement"), bgcolor="#22c55e")
        self.page.snack_bar.open = True
        self.page.update()

    def export_csv(self):
        if not self.scan_history:
            self.page.snack_bar = ft.SnackBar(ft.Text("Aucun résultat à exporter."), bgcolor="#ef4444")
            self.page.snack_bar.open = True
            self.page.update()
            return

        output = io.StringIO()
        output.write("ID,CIBLE,TYPE,DATE,DURÉE,CRITIQUE,MOYENNE,FAIBLE\n")
        for scan in self.scan_history:
            line = f'{scan["id"]},{scan["target"]},{scan["type"]},{scan["date"]},{scan["duration"]},{scan["vuln_critique"]},{scan["vuln_moyenne"]},{scan["vuln_faible"]}\n'
            output.write(line)
        output.seek(0)

        csv_bytes = output.getvalue().encode("utf-8")
        output.close()

        asyncio.create_task(self.save_file("scan_result.csv", csv_bytes))

    def export_excel(self):
        if not self.scan_history:
            self.page.snack_bar = ft.SnackBar(ft.Text("Aucun résultat à exporter."), bgcolor="#ef4444")
            self.page.snack_bar.open = True
            self.page.update()
            return

        df = pd.DataFrame(self.scan_history)
        output = io.BytesIO()
        df.to_excel(output, index=False)
        output.seek(0)

        excel_bytes = output.read()
        output.close()

        asyncio.create_task(self.save_file("scan_result.xlsx", excel_bytes))

    def export_pdf(self):
        if not self.scan_history:
            self.page.snack_bar = ft.SnackBar(ft.Text("Aucun résultat à exporter."), bgcolor="#ef4444")
            self.page.snack_bar.open = True
            self.page.update()
            return

        output = io.BytesIO()
        c = canvas.Canvas(output, pagesize=letter)
        width, height = letter
        c.setFont("Helvetica", 10)
        y = height - 40

        headers = ["ID", "CIBLE", "TYPE", "DATE", "DURÉE", "CRITIQUE", "MOYENNE", "FAIBLE"]
        col_width = width / len(headers)

        # En-tête
        for i, header in enumerate(headers):
            c.drawString(10 + i * col_width, y, header)
        y -= 20

        for scan in self.scan_history:
            for i, key in enumerate(["id", "target", "type", "date", "duration", "vuln_critique", "vuln_moyenne", "vuln_faible"]):
                c.drawString(10 + i * col_width, y, str(scan[key]))
            y -= 15
            if y < 40:
                c.showPage()
                y = height - 40

        c.save()
        output.seek(0)

        pdf_bytes = output.read()
        output.close()

        asyncio.create_task(self.save_file("scan_result.pdf", pdf_bytes))


def main(page: ft.Page):
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 900
    page.window_height = 700
    page.window_resizable = True

    header = ft.Container(
        content=ft.Row([
            ft.Icon(name=ft.Icons.SHIELD, color="#00FFFF", size=30),
            ft.Text("Nmap Security Suite Pro", size=22, weight=ft.FontWeight.BOLD),
        ]),
        padding=15,
        border_radius=12
    )

    username = ft.TextField(label="Nom d'utilisateur", width=300)
    password = ft.TextField(label="Mot de passe", password=True, can_reveal_password=True, width=300)

    def auth_user(e):
        if username.value == "admin" and password.value == "admin":
            page.clean()
            page.add(header)
            ScanApp(page)
        else:
            page.snack_bar = ft.SnackBar(ft.Text("⛔ Accès refusé !"), bgcolor="#ef4444")
            page.snack_bar.open = True
            page.update()

    login_card = ft.Container(
        content=ft.Column([
            header,
            ft.Text("Connexion Administrateur", size=18),
            username,
            password,
            ft.ElevatedButton("Se connecter", icon=ft.Icons.LOGIN, on_click=auth_user, width=300),
        ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        alignment=ft.alignment.center,
        padding=30,
        border_radius=15,
        width=400
    )

    page.add(ft.Row([login_card], alignment=ft.MainAxisAlignment.CENTER))


if __name__ == "__main__":
    ft.app(target=main)
