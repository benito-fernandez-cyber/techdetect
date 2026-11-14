"""TechDetect - Fase 2: interfaz grafica con CustomTkinter.
Requiere: pip install customtkinter requests
Uso: python gui.py   (detector.py y rules.json en la misma carpeta)
Usar solo en sitios propios o con permiso."""
import threading

import customtkinter as ctk
import requests

from cves import enriquecer, formatear
from detector import cargar_reglas, detectar

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("TechDetect - Detector de tecnologias web")
        self.geometry("700x560")
        self.minsize(520, 420)

        try:
            self.reglas = cargar_reglas()
        except (OSError, ValueError) as e:
            self.reglas = {}
            self._aviso = f"No se pudo cargar rules.json: {e}"
        else:
            self._aviso = f"{len(self.reglas)} tecnologias en la base de reglas."

        ctk.CTkLabel(self, text="TechDetect", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(18, 2))
        ctk.CTkLabel(self, text="Analisis pasivo: solo lee lo que el servidor ya muestra.",
                     text_color="gray").pack()

        marco = ctk.CTkFrame(self, fg_color="transparent")
        marco.pack(fill="x", padx=20, pady=14)
        self.entrada = ctk.CTkEntry(marco, placeholder_text="https://tu-sitio.com")
        self.entrada.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entrada.bind("<Return>", lambda _e: self.iniciar())
        self.boton = ctk.CTkButton(marco, text="Analizar", width=110, command=self.iniciar)
        self.boton.pack(side="right")

        self.chk_cves = ctk.CTkCheckBox(self, text="Buscar CVEs en la NVD (mas lento, orientativo)")
        self.chk_cves.pack(anchor="w", padx=22, pady=(0, 8))

        self.salida = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Consolas", size=14))
        self.salida.pack(fill="both", expand=True, padx=20, pady=(0, 8))
        self.salida.configure(state="disabled")

        self.estado = ctk.CTkLabel(self, text=self._aviso, text_color="gray", anchor="w")
        self.estado.pack(fill="x", padx=22, pady=(0, 12))

    # --- UI helpers (siempre se llaman desde el hilo principal) ---
    def _mostrar(self, texto):
        self.salida.configure(state="normal")
        self.salida.delete("1.0", "end")
        self.salida.insert("end", texto)
        self.salida.configure(state="disabled")

    def _terminar(self, texto, estado):
        self._mostrar(texto)
        self.estado.configure(text=estado)
        self.boton.configure(state="normal")

    # --- Logica ---
    def iniciar(self):
        url = self.entrada.get().strip()
        if not url:
            self.estado.configure(text="Escribe una URL primero.")
            return
        if not self.reglas:
            self.estado.configure(text=self._aviso)
            return
        self.boton.configure(state="disabled")
        self.estado.configure(text=f"Analizando {url} ...")
        self._mostrar("")
        # La peticion HTTP va en un hilo para no congelar la ventana.
        con_cves = bool(self.chk_cves.get())
        threading.Thread(target=self._trabajo, args=(url, con_cves), daemon=True).start()

    def _trabajo(self, url, con_cves):
        try:
            res = detectar(url, self.reglas)
        except requests.exceptions.RequestException as e:
            self.after(0, self._terminar, "", f"Error de conexion: {type(e).__name__}")
            return
        if not res:
            self.after(0, self._terminar, "No se detecto ninguna tecnologia con las reglas actuales.", "Sin resultados.")
            return
        if con_cves:
            enr = enriquecer(res, self.reglas,
                             progreso=lambda m: self.after(0, self.estado.configure, {"text": m}))
            texto = formatear(enr)
        else:
            texto = "\n".join(f"{t}" + (f"  {v}" if v else "") for t, v in sorted(res.items()))
        self.after(0, self._terminar, texto, f"{len(res)} tecnologias detectadas.")


if __name__ == "__main__":
    App().mainloop()
