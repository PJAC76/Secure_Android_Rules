# Reglas de Secure_Android

Reglas publicables originales, licencia MIT, para la aplicación personal Secure_Android. Este repositorio no contiene código privado de la app, credenciales, archivos del usuario ni muestras de malware.

La primera versión contiene dos **heurísticas**: no constituye un catálogo validado de familias de malware. Una coincidencia necesita revisión y no se presenta como confirmación de infección.

`manifest.json` contiene el código de las reglas y sus metadatos dentro de un payload firmado Ed25519. La APK incluye `rules-public-key.der` y verifica firma, hash, versión y caducidad antes de usarlo. Publicar un archivo sin esa firma no habilita reglas en el teléfono.

## Actualizar

1. Revisar cambios y procedencia de `rules.yar`, con pruebas benignas y sin incorporar muestras.
2. Ejecutar manualmente **Publicar reglas firmadas** sobre main e indicar una versión entera mayor que la última publicada.
3. Descargar/verificar la entrega. Cada paquete caduca en 90 días; para renovarlo, publicar una versión mayor aunque las reglas no cambien.

La clave privada está únicamente en el secreto de Actions `RULES_SIGNING_KEY`. Conservar una copia privada segura fuera de Git. La app no realiza pagos ni usa credenciales de GitHub para descargar este paquete público.

La URL de actualización es `https://github.com/PJAC76/Secure_Android_Rules/releases/latest/download/manifest.json`.
