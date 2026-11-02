# Auditoría técnica y de seguridad de Ganimedes

**Fecha:** 2 de noviembre de 2026.  
**Base revisada:** `ccd6d8dde481` y cambios locales de esta auditoría.  
**Entorno de ejecución:** Windows/amd64, CGO desactivado.  
**Resultado:** hallazgos reproducidos corregidos; controles locales aprobados.

## 1. Dictamen ejecutivo

La revisión encontró problemas reales que las pruebas originales no detectaban:
paso de solicitudes sin una decisión de política, ambigüedades entre parsers,
alteraciones del log aceptadas por el verificador, fallos de correlación y
debilidades en la página de aprobación. No era correcto declarar el proyecto
libre de vulnerabilidades basándose únicamente en su cobertura y suite original.

Se corrigieron los casos reproducidos y se añadieron regresiones comprobadas
contra fallos deliberados. Se conservó el uso exclusivo de la biblioteca estándar
y el reenvío de los bytes originales de mensajes aceptados. El resultado permite
revisar una implementación más estricta, con sus límites expresados en los
documentos operativos; no constituye una certificación de ausencia de defectos.

La compilación, vet, pruebas completas, cobertura, linter y análisis de
vulnerabilidades pasan localmente. Compilan las seis plataformas distribuidas.
El detector de carreras, la ejecución nativa en Linux/macOS, los smokes con un
cliente MCP real y el CI remoto no se ejecutaron en esta sesión.

No se hicieron commits, pushes, tags ni publicaciones. El archivo preexistente
sin seguimiento `docs/CODE_REVIEW.md` se preservó; este informe contiene la
evidencia de esta revisión y no adopta sus afirmaciones de estado limpio o CI.

## 2. Alcance y método

Se revisaron `cmd/`, todos los paquetes `internal/`, `go.mod`, los workflows,
controles de publicación y documentación operativa, tomando la Constitución
Técnica como requisito. La atención se centró en los artículos 1.1, 1.3, 2.1,
2.3, 2.4, 3.1, 3.2, 3.4, 4.2 y 6.2.

El trabajo combinó lectura de código, contraste de documentación, casos
adversarios, pruebas con procesos sustitutos, análisis estático y de dependencias,
y mutaciones temporales restauradas. Las severidades siguientes son cualitativas:
valoran impacto y precondiciones dentro del modelo de una aplicación local.
No son puntuaciones CVSS ni identificadores de vulnerabilidad publicados.

## 3. Hallazgos y correcciones

| ID | Severidad | Hallazgo comprobado | Corrección |
|---|---|---|---|
| H01 | Alta | `tools/call` sin id o con errores en campos tipados podía tomar la salida de passthrough y eludir la decisión. | Validación explícita de JSON-RPC 2.0 y de parámetros; las solicitudes no interpretables se deniegan con inspección activa. |
| H02 | Alta | Duplicados, aliases de campos y Unicode inválido podían producir interpretaciones diferentes entre gateway y receptor. | `internal/jsoncheck` compartido; nombres exactos y validación de formas en los consumidores. |
| H03 | Alta | El verificador reconstruía el payload desde structs y podía descartar campos añadidos o variantes de nombres sin invalidar el sello. | Se verifica el payload almacenado completo, excluyendo únicamente `hash` y `sig`; después se comprueba el esquema admitido. |
| H04 | Alta | Cambiar números distintos que redondean al mismo binary64 podía conservar válido el sello JCS. | Nuevas llamadas incluyen `content_hash`, firmado y recalculado sin conversión numérica. Se mantiene compatibilidad explícita con el límite de logs antiguos. |
| H05 | Alta, condicionada | La página aceptaba Host arbitrario, dejando una ruta de lectura del CSRF mediante DNS rebinding cuando el navegador permite acceso a loopback. | Se exige la autoridad numérica exacta anunciada; `localhost` se resuelve a loopback al enlazar, sin depender de DNS. |
| H06 | Media | La aprobación podía embeberse en un iframe; también faltaban límites completos de HTTP y cierre de esperas. | CSP `frame-ancestors 'none'`, X-Frame-Options DENY, no-store, cuerpo de 8 KiB, deadlines y liberación fail-closed al cerrar. |
| H07 | Media | Ids equivalentes, respuestas de otros métodos o solicitudes iniciadas por el servidor podían perder o atribuir incorrectamente registros. | Ids decodificados; reserva de todos los métodos al auditar; sólo respuestas válidas completan pendientes. |
| H08 | Media | Frames y pendientes podían crecer sin límite; errores de entrada y varios cierres de procesos no se resolvían correctamente. | Frames de 16 MiB, 1024 reservas y 64 MiB de datos retenidos; errores propagados, escrituras parciales detectadas y cierre/recolección acotados. |
| H09 | Media | Escritores simultáneos podían bifurcar la cadena; la reapertura toleraba historia dañada o sin delimitador final. | Lock exclusivo cooperativo, verificación íntegra con la clave correcta antes de reanudar y rechazo de corrupción o falta de LF. |
| H10 | Media | `scan` ignoraba la paginación y aceptaba ciertas respuestas incompletas; un descendiente con stdout heredado podía prolongar la espera. | Se recorren cursores opacos con ids nuevos; errores sin informe parcial, límites de mensajes/volumen/páginas y cierre de pipes al vencer el contexto. |
| H11 | Media | Configuraciones ambiguas y raíz null podían cargarse; `verify` no respetaba la clave configurada por entorno. | Configuración con cuatro campos exactos, sin duplicados ni Unicode inválido; `verify` resuelve `GANIMEDES_SIGNING_KEY` y distingue errores reales de Stat. |
| H12 | Riesgo de construcción | Compilador antiguo, Actions por tags móviles, Trivy sin fallo explícito y publicación sin repetir el gate completo. | Go mínimo 1.26.10; Actions por SHA y Dependabot; Trivy bloqueante; cobertura exigida y CI reutilizado en el commit de publicación. |
| H13 | Baja/consistencia | Errores de salida o cierre ignorados, `template.Must` en biblioteca y afirmaciones documentales superiores a lo implementado. | Errores manejados, parser de plantilla con retorno de error, validación del escritor de auditoría y documentación sincronizada. |
| H14 | Media, operativa | Si faltaba la privada, generar una nueva podía sobrescribir el único `.pub` anterior; una publicación fallida tampoco se reparaba al reiniciar. | No se sobrescriben claves públicas; se rechaza una pública huérfana o desparejada y sólo se reconstruye una pública ausente desde la privada existente. |

Los bypasses de H01/H02 importan frente a receptores tolerantes a esos mensajes;
la revisión prueba que el gateway los reenviaba sin decidir. No se afirma que
todo servidor MCP ejecute mensajes inválidos. En H05/H06 se comprobaron handlers
y respuestas HTTP; no se realizó un ataque automatizado en un navegador real.

### Evidencia representativa

Una llamada sin id como
`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_file"}}`
podía escapar de la evaluación anterior. Ahora se rechaza. También se rechaza
una combinación de miembros `method` o `name` duplicados, incluyendo nombres
equivalentes escritos con escapes JSON.

La edición de `args.amount` desde `9007199254740992` a `9007199254740993` en una
entrada antigua produjo `accepted=true` en la reproducción inicial. El cambio
conserva el mismo valor binary64 y por ello el mismo JCS. Las regresiones nuevas
detectan ese caso, decimales de mayor precisión, exponentes y subnormales, en
argumentos, resultados y errores.

Un servidor que cerraba stdout pero permanecía vivo con el cliente conectado
también bloqueaba el ciclo de vida. La regresión falló al retirar su terminación
acotada y pasó después de restaurarla. Otra prueba mantiene stdout en un
descendiente: desactivar el cierre del pipe volvió a prolongar el scan hasta
4,28 segundos frente al deadline de un segundo empleado por esa prueba.

## 4. Formato de integridad y compatibilidad

El sello principal sigue siendo SHA-256 y Ed25519 sobre RFC 8785. Se corrigió la
validación de su dominio: sin claves repetidas, Unicode inválido ni valores JSON
adicionales ignorados. Ningún campo almacenado del payload queda fuera del sello.

Cada llamada nueva añade `content_hash`: SHA-256 hexadecimal de la codificación
JSON de un objeto con `args`, `result`, `error`, en ese orden, omitiendo campos
ausentes. Sus valores son `json.RawMessage`; el encoder compacta y escapa HTML,
sin convertir números a float64. El digest entra en el payload firmado y el
verificador lo recalcula. Una edición numérica que JCS redondearía igual cambia
ese compromiso. Los headers de sesión no lo incluyen.

Los registros antiguos sin `content_hash` conservan su verificabilidad y su
limitación numérica original. No se migraron ni se reescribieron logs del usuario.
Una validación de firma no puede añadir retrospectivamente evidencia que el
productor antiguo no firmó. El formato nuevo exige actualizar verificadores que
sólo comprendan el anterior.

## 5. Validaciones y cobertura

| Control | Resultado local |
|---|---|
| `go build ./...` | Aprobado |
| `go vet ./...` | Aprobado |
| `gofmt -l .` | Sin archivos pendientes al cierre |
| `go test ./... -cover`, sin caché de resultados | Todos los paquetes aprobados |
| golangci-lint 2.15.0 | 0 incidencias; sin supresiones añadidas |
| `govulncheck ./...` con Go 1.26.10 | No vulnerabilities found |
| Gitleaks 8.30.1 | Sin secretos detectados; historial completo de 58 commits y árbol revisados |
| actionlint 1.7.12 | Workflows sin incidencias |
| Checker de cobertura | Perfil final aprobado; regresión artificial 100% → 0% rechazada |
| Cross-compilación, CGO=0 | linux/darwin/windows × amd64/arm64: 6/6 |
| Binario Windows/amd64 | Ejecutado: `ganimedes 0.0.0-dev` |

El análisis inicial con Go 1.26.5 reportó **14 avisos de la biblioteca estándar**
por alcanzabilidad conservadora de símbolos. No son 14 exploits demostrados de
Ganimedes; algunas rutas TLS/HTTP2 no están expuestas por la página HTTP local.
Tras actualizar a Go 1.26.10 y repetir el análisis, el resultado fue cero avisos.
`go list -m all` sólo devuelve el módulo del proyecto: no se añadió una dependencia
de runtime. Linter y actionlint se usaron como herramientas de auditoría externas.

| Paquete | Medición inicial | Final | Variación, puntos porcentuales |
|---|---:|---:|---:|
| approval | 95,0% | 96,7% | +1,7 |
| audit | 85,1% | 86,3% | +1,2 |
| cli | 93,9% | 95,7% | +1,8 |
| config | 100,0% | 100,0% | 0 |
| jsoncheck | Nuevo | 96,0% | Nuevo |
| policy | 100,0% | 100,0% | 0 |
| proxy | 85,1% | 92,4% | +7,3 |
| scan | 87,2% | 96,3% | +9,1 |

`cmd/ganimedes` conserva 0% directo: contiene la única llamada de terminación y
delega su comportamiento a `cli`, probado en proceso. Las métricas antiguas de
los documentos eran históricas; la comparación inicial/final anterior se midió
en este árbol y plataforma. Los umbrales de CI se elevaron a los valores finales.

### Capacidad de detectar regresiones

Se vieron fallar las pruebas al retirar las protecciones de parsing, normalización
de ids, límites de memoria/frames, clasificación de respuestas, escrituras
parciales y cierres de procesos. Se repitió el procedimiento con Host, headers
antiframe, tamaño del cuerpo, cierre de aprobaciones, esquema de configuración,
validación JCS, bloqueo del log, historia corrupta, formas de entradas y
`content_hash` y conservación/recuperación de claves públicas. Cada experimento
se restauró y las suites posteriores pasaron.

Ejemplos de regresiones auditables en el repositorio:

- `TestHandleRequest_RefusesAmbiguousToolCalls` y
  `TestPending_RecognizesEquivalentIDs`.
- `TestVerify_DetectsUnsealedFields`,
  `TestVerifyDetectsNumberEditsBeyondIEEE754` y
  `TestOpenRejectsDamagedHistory`.
- `TestDiscover_Pagination`, `TestReadResponse_RejectsAmbiguity` y
  `TestScan_TimeoutClosesInheritedOutput`.

## 6. Límites y riesgo residual

1. **No hay prueba de completitud absoluta.** Las llamadas permitidas se registran
   al responder; una llamada sin respuesta o un append fallido puede no dejar
   registro. La auditoría continúa siendo observadora y falla abierta en escritura.
2. **No hay ancla externa ni fsync por entrada.** Un prefijo válido no demuestra
   que no se eliminó una cola, y una pérdida de energía puede perder escrituras.
3. **Logs antiguos:** sin `content_hash`, ciertas diferencias numéricas siguen
   siendo indistinguibles. Conservar originales y digests externos confiables.
4. **Confianza local:** quien puede leer la página local puede decidir; quien
   controla la clave puede firmar otra historia. En Windows la privacidad depende
   de ACL del directorio. El log contiene argumentos/resultados y puede contener
   secretos; no hay redacción automática.
5. **Lock cooperativo:** no cubre hardlinks ni procesos que lo ignoren. Tras un
   crash, confirmar que el escritor murió antes de retirar el lock; conservar y
   recuperar el archivo original offline. Usar un log distinto por servidor.
   La publicación del par de claves tampoco es atómica: una pública ausente se
   recupera desde la privada, pero una pública existente incompatible no se pisa.

   *Nota posterior (mismo día):* el lock `.lock` con O_EXCL descrito aquí
   sobrevivía a que el cliente MCP matara el proceso y bloqueaba todo arranque
   posterior. Se sustituyó por un lock del kernel sobre el propio log (`flock` /
   `LockFileEx`), que se libera al morir el proceso y cubre hardlinks. Ver
   `SECURITY.md` y `TESTING.md` §L4.
6. **Límites de recursos:** los 64 MiB de pendientes cuentan id, herramienta y
   argumentos, no RSS total. No se matan árboles de descendientes ni se pueden
   interrumpir implementaciones arbitrarias de io.Reader/io.Writer bloqueantes.
7. **Ámbito del gateway:** política por nombre y default-allow. No es sandbox,
   no inspecciona semántica de argumentos, no gobierna herramientas externas al
   servidor envuelto ni la renegociación de Roots.

La deuda que permanece tiene causa y mitigación documentadas en
[`TECH_DEBT.md`](TECH_DEBT.md), junto con los límites en
[`SECURITY.md`](../SECURITY.md). No se presentan como garantías implementadas.

## 7. Evaluación de calidad del código y cierre

La estructura por paquetes, stdlib-only y conservación del wire son propiedades
útiles y se preservaron. Los defectos de calidad importantes fueron errores
ignorados, decodificación permisiva usada como decisión de seguridad,
documentación desactualizada y controles de CI declarativos que no bloqueaban.
Se corrigieron esos comportamientos; no se hicieron reescrituras cosméticas ni se
eliminaron comentarios de razonamiento para aparentar limpieza.

La rama queda preparada para revisión de los cambios y ejecución del CI remoto.
Antes de una publicación corresponde confirmar Linux/macOS/Windows en CI,
detector de carreras en Linux y smokes del cliente y navegador reales. No se
atribuye a la revisión local una evidencia que esas ejecuciones aún no aportaron.

## 8. Referencias técnicas contrastadas

- [RFC 8785, JCS](https://www.rfc-editor.org/rfc/rfc8785.txt): dominio de Unicode,
  unicidad de miembros y modelo numérico empleado por el sello.
- [Paginación MCP](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination):
  cursores opacos y continuación de `tools/list`.
- [Go, historial oficial de versiones](https://go.dev/doc/devel/release):
  política de soporte y parches del toolchain.
- [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809): uno de los avisos oficiales
  contrastados con la salida inicial del scanner.
- [OWASP, defensa contra clickjacking](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html):
  controles antiframe aplicados a la aprobación.
