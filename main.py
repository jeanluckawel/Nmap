import flet as ft
import nmap
import threading
import smtplib
import os
import sys
from email.message import EmailMessage

def main(page: ft.Page):
    page.title = "Nmap Security Suite Pro"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 800
    page.window_height = 500
    page.window_resizable = False

    # Champs
    username = ft.TextField(label="Nom d'utilisateur", width=300, border_radius=8)
    password = ft.TextField(label="Mot de passe", password=True, can_reveal_password=True, width=300, border_radius=8)
    result_output = ft.Text(value="", selectable=True, size=12, color=ft.Colors.GREEN_200)
    loading = ft.ProgressRing()

    # Entête stylisé
    header = ft.Container(
        content=ft.Row([
            ft.Icon(name=ft.Icons.SECURITY, color=ft.Colors.CYAN, size=30),
            ft.Text("Nmap Security Suite Pro", size=22, weight=ft.FontWeight.BOLD),
        ]),
        padding=15,
        bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.CYAN_700),
        border_radius=12
    )

    def send_email(report):
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

            page.snack_bar = ft.SnackBar(ft.Text("Email envoyé avec succès !"), bgcolor=ft.Colors.GREEN)
        except:
            page.snack_bar = ft.SnackBar(ft.Text("Échec de l'envoi d'email."), bgcolor=ft.Colors.RED)
        page.snack_bar.open = True
        page.update()

    def run_scan():
    # Obtenir le chemin du répertoire actuel
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Chemin vers le dossier contenant nmap.exe
        nmap_dir = os.path.join(current_dir, "nmap")
        nmap_exe_path = os.path.join(nmap_dir, "nmap.exe")
        
        # Vérifier que nmap.exe existe
        if not os.path.exists(nmap_exe_path):
            raise FileNotFoundError(f"nmap.exe non trouvé à l'emplacement : {nmap_exe_path}")
        
        # Injecter nmap.exe dans PATH
        os.environ["PATH"] = nmap_dir + os.pathsep + os.environ["PATH"]
        
        # Scanner
        nm = nmap.PortScanner()
        nm.scan(hosts="192.168.1.0/24", arguments="-T4 -F")
        return nm.csv()


    def display_scan():
        page.clean()
        page.add(header)
        page.add(ft.Container(loading, alignment=ft.alignment.center, padding=30))
        page.update()

        def threaded_scan():
            try:
                result = run_scan()
                result_output.value = result
            except Exception as e:
                result_output.value = f"Erreur de scan : {str(e)}"
            
            page.clean()
            page.add(header)

            # Créer un conteneur avec défilement
            scrollable_output = ft.Column(
                [result_output],
                scroll=ft.ScrollMode.ALWAYS,
                height=200,
            )
            
            page.add(ft.Container(
                content=ft.Column([
                    ft.Text("✅ Analyse terminée", size=18, weight="bold"),
                    ft.Container(
                        content=scrollable_output,
                        bgcolor=ft.Colors.with_opacity(0.04, ft.Colors.WHITE),
                        padding=15,
                        border_radius=10,
                    ),
                    ft.Row([
                        ft.ElevatedButton("📤 Envoyer par Email", 
                                         on_click=lambda e: send_email(result_output.value), 
                                         icon=ft.Icons.SEND),
                        ft.OutlinedButton("🔁 Rescanner", 
                                         on_click=lambda e: display_scan(), 
                                         icon=ft.Icons.RESTART_ALT),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=20)
                ]),
                padding=20
            ))
            page.update()

        threading.Thread(target=threaded_scan).start()

    def auth_user(e):
        if username.value == "admin" and password.value == "admin":
            display_scan()
        else:
            page.snack_bar = ft.SnackBar(ft.Text("Accès refusé !"), bgcolor=ft.Colors.RED)
            page.snack_bar.open = True
            page.update()

    # Page de connexion stylisée
    login_card = ft.Container(
        content=ft.Column([
            header,
            ft.Text("Connexion Administrateur", size=18, weight="bold"),
            username,
            password,
            ft.ElevatedButton("Se connecter", 
                              icon=ft.Icons.LOGIN, 
                              on_click=auth_user, 
                              width=300),
        ],
        alignment=ft.MainAxisAlignment.CENTER,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        alignment=ft.alignment.center,
        padding=30,
        bgcolor=ft.Colors.with_opacity(0.08, ft.Colors.BLUE_GREY),
        border_radius=15,
        width=400
    )

    page.add(ft.Row([login_card], alignment=ft.MainAxisAlignment.CENTER))

ft.app(target=main)