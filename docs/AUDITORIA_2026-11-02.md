# Auditoría técnica y de seguridad de Ganimedes

**Fecha:** 2 de noviembre de 2026.  
**Base revisada:** `ccd6d8dde481` y cambios locales de esta auditoría.  
**Entorno de ejecución:** Windows/amd64, CGO desactivado.  
**Resultado:** hallazgos reproducidos corregidos; controles locales aprobados.  
**Estado posterior (mismo día):** correcciones revisadas, integradas en `main`
mediante el PR #1 y publicadas como `v1.0.0`. El seguimiento, con seis hallazgos
nuevos encontrados al verificar, está en §8; las secciones 1 a 7 conservan el
informe tal como se entregó.

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

## 8. Seguimiento: de la auditoría a `v1.0.0`

Esta sección registra lo que ocurrió después de entregar el informe: una
revisión independiente de sus conclusiones, las verificaciones que §7 dejaba
pendientes y los defectos que esas verificaciones encontraron. Cada afirmación
se apoya en una ejecución, no en una lectura.

### 8.1. Revisión del informe

Se repitieron localmente los controles de §5 y coincidieron cifra por cifra:
compilación, vet, formato, pruebas y cobertura por paquete. Se leyó el código de
las correcciones centrales (`internal/proxy/request.go`, `internal/jsoncheck`,
el `content_hash`, el control de Host) y se confirmó el criterio: toda
interpretación dudosa termina en denegación. Las severidades de §3 se
consideraron razonables.

La revisión discrepó en un punto. §6.5 trataba el lock huérfano como riesgo
residual "tras un crash", y no lo era: era el cierre normal (S1).

### 8.2. Hallazgos posteriores

| ID | Severidad | Hallazgo comprobado | Corrección |
|---|---|---|---|
| S1 | Alta, operativa | El lock `.lock` creado con O_EXCL (H09) sobrevivía a que el cliente MCP matara el proceso, el cierre habitual: sin manejo de señales no se ejecuta ningún `defer`. Todo arranque posterior fallaba hasta borrarlo a mano. Reproducido con el binario real. | Lock del kernel sobre el propio log: `flock` en Unix, `LockFileEx` en Windows, sobre un byte fuera del contenido porque allí los locks son obligatorios. El sistema lo libera al morir el proceso y cubre hardlinks, el límite que §6.5 dejaba abierto. En otras plataformas el log no se abre. |
| S2 | Media | `verify` tomaba cada argumento como ruta del log, quedándose con el último. `verify a.jsonl b.jsonl` verificaba solo `b` e informaba OK aunque `a` estuviera manipulado; un flag mal escrito se buscaba como archivo. Encontrado al comprobar los códigos de salida que `v1.0.0` iba a prometer. | Una sola ruta; una segunda ruta o un flag desconocido son error de uso (código 2). |
| S3 | Baja, CI | El gate de cobertura (H12) nunca podía pasar en Windows: PowerShell parte `-coverprofile=coverage.out` en el punto y el perfil se escribía como `coverage`. Primer fallo real del PR #1. | Argumento entre comillas, con un comentario que explica por qué. |
| S4 | Baja, CI | Dependabot (H12) abrió un PR para `codeql-action/init` y otro para `analyze`; cada uno mezclaba v3 y v4 y CodeQL lo rechazaba, así que ninguno podía pasar. | Grupo de Dependabot para actualizar ambos juntos; el PR agrupado pasó. |
| S5 | Baja, uso | Al vencer su plazo, `scan` decía `read \|0: file already closed`, porque H10 cierra las tuberías. v0.3.3 al menos sugería "timed out?". Apareció en la prueba con cliente real, mientras `npx` descargaba el servidor. | El mensaje dice que venció el plazo y nombra la descarga como causa probable; un servidor que se cae no se atribuye al plazo. |
| S6 | Compatibilidad | Un `verify` de v0.3.3 marca como `TAMPERED` un log nuevo y legítimo, porque no conoce `content_hash` (§4 lo anticipaba sin haberlo ejecutado). | Documentado en `SECURITY.md`, el README y las notas de versión; es uno de los motivos de la versión mayor. |

Cada corrección de S1, S2 y S5 tiene pruebas que se vieron fallar al romper el
código a propósito, con estas mutaciones:

- **S1:** sin lock; con el O_EXCL original; con el lock de Windows sobre el
  contenido; con un handle de solo escritura, que Windows se niega a bloquear.
- **S2:** el análisis de argumentos anterior, que devolvía 0 con el log
  manipulado delante.
- **S5:** ocultar el plazo vencido, y culpar al plazo de una caída.

### 8.3. Verificaciones que §7 dejaba pendientes

- **CI remoto.** Verde en Linux, macOS y Windows, con el detector de carreras en
  Linux, para el PR #1, para `main` tras cada integración y dentro del propio
  `release.yml` en el commit del tag.
- **Compatibilidad hacia atrás.** Se compilaron `v0.1.0`, `v0.2.0` y `v0.3.3`
  desde sus tags. Cada una escribió un log con una llamada real; el binario
  nuevo lo verificó, siguió escribiendo en él y verificó el log mixto.
- **Cliente real.** Claude Code 2.1.314 como cliente, el servidor oficial
  `@modelcontextprotocol/server-filesystem@2026.8.31` y una persona en el
  navegador. Pasaron lectura permitida, deny antes del servidor, Approve, Reject,
  el rechazo de `localhost` por Host en un navegador real, las cabeceras
  anti-iframe en la página viva (sin intentar enmarcarla) y `verify` antes y
  después de manipular. Detalle en `TESTING.md` §L3.
- **Artefactos publicados.** Los seis binarios de `v1.0.0` se verificaron desde
  fuera:
  - descarga anónima, checksums, buildinfo del commit del tag, formato real,
    ausencia de rutas filtradas y attestations, con controles negativos;
  - reconstrucción reproducible desde un clon limpio, con contenido idéntico.
    Los 58 bytes distintos se localizaron uno a uno: 38 en el build ID y 20 en
    `.note.gnu.build-id`, que Go deriva de él desde 1.24.

  Detalle en `TESTING.md`, Release artifacts.

### 8.4. Integración y publicación

Los cambios entraron en `main` en commits separados por hallazgo, cada uno
compilando y pasando sus pruebas por sí solo, sin commits de merge:

- **Correcciones de la auditoría:** del `8472195` al `1175fac`.
- **Seguimiento:** `d71ec40`, `603b083`, `7ce3d79`, `df3a45d` y los registros
  de pruebas.
- **Dependabot:** cinco actualizaciones de Actions (#2, #3, #6, #7, #8). Cada SHA
  se comprobó con `git ls-remote` contra las etiquetas del repositorio oficial
  antes de integrarla.

`v1.0.0` se publicó sobre `f6f0361` con una promesa de estabilidad escrita
(README, "Stability"): dentro de 1.x no se rompen comandos, códigos de salida,
configuraciones ni la verificación de logs existentes. El Art. 1.1 de la
Constitución se aclaró a "Ganimedes usa solo la biblioteca estándar", versión
1.1.1, para que no pareciera caducar con la v0. El README se regeneró con
salidas reales del binario publicado.

### 8.5. Evaluación al cierre

Puntuación global: **7 sobre 10**. La media combina ingeniería sólida con un
producto todavía estrecho.

| Dimensión | Nota | Motivo |
|---|:---:|---|
| Cadena de publicación | 9 | Pins verificados, procedencia, binarios reproducibles, CI en el tag |
| Honestidad documental | 8,5 | Declara límites y lo no probado; hubo ejemplos que corregir |
| Calidad del código | 8 | stdlib-only, fail-closed, razonamiento escrito; pero 14 defectos reales sobrevivieron a una revisión previa que lo daba por limpio |
| Pruebas | 8 | Mutaciones, tres sistemas, detector de carreras y cliente real; la prueba con cliente real no está automatizada |
| Seguridad de lo prometido | 7,5 | Cerrados bypasses y manipulaciones; abierto TD-8 |
| Alcance del producto | 5 | Un servidor stdio, política por nombre y permisiva por defecto, sin redacción |
| Madurez y adopción | 3 | Sin usuarios reales conocidos |

### 8.6. Riesgo que sigue abierto

Los límites de §6 se mantienen, salvo el lock de §6.5, cerrado por S1. El
siguiente trabajo recomendado es **TD-8**: hoy el log demuestra que no se
alteró, pero no que esté completo. Una llamada sin respuesta o una escritura
fallida no dejan rastro, y sin un ancla externa no se detecta que falte la cola.
Cerrarlo exige una decisión de producto entre disponibilidad y garantía.

`docs/CODE_REVIEW.md`, que §1 preservó, se revisó entero. Era una revisión de
`v0.3.3` que daba el árbol por limpio. Sus conclusiones quedan refutadas por §3,
sus tres primeros gaps están cerrados y los otros dos ya están documentados en
`DESIGN.md` y `PRODUCT_SPEC.md`. Nunca estuvo versionado; se recomienda retirarlo
del árbol de trabajo, y se guardó una copia fuera del repositorio.

## 9. Referencias técnicas contrastadas

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
