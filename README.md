# Administrador de Dispositivos Wi-Fi y USB (Android / POS)

Herramienta gráfica para la detección, conexión automática por Wi-Fi y control remoto de dispositivos Android (PAX, Landi, tablets y teléfonos) mediante ADB y Scrcpy.

## Características

- 🔍 **Detección inteligente de dispositivos:** Escaneo ARP en tiempo real, resolución de MAC/OUI para PAX, Landi y terminales POS.
- 📶 **Conexión Wi-Fi Automática:** Activación segura de TCP/IP en el puerto 5555 vía USB o Wi-Fi sin colapsar el daemon de PayDroid.
- 📱 **Control de Pantalla (Scrcpy):** Integración nativa con Scrcpy a 2 Mbps estables y opción de apagar la pantalla física durante el uso.
- 🌐 **Soporte Multi-Subred y BSSID:** Detección de salto de red entre 2.4 GHz y 5 GHz con mecanismo de wake route ARP.
- 📁 **Explorador y Gestor de Archivos:** Navegación y transferencia de APKs y logs hacia el dispositivo.

## Requisitos

- Python 3.10+
- [Scrcpy](https://github.com/Genymobile/scrcpy) instalado en `C:\scrcpy\` (o en PATH)
- Android Debug Bridge (`adb`) en PATH

## Ejecución

Haz doble clic en `Conectar dispositivos por Wi-Fi.bat` o ejecuta:

```bash
python multi_adb_wifi.py
```
