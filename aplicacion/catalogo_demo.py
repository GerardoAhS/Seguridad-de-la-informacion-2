"""Contenido del catálogo de demostración: libros electrónicos, manuales, documentos técnicos, apuntes, guías y
material educativo. Todo se genera en memoria (texto propio, sin material de terceros) en .md, .txt, .pdf o .png.

Cada producto: (nombre, descripción, precio en centavos, archivo, categoría, puntos "qué incluye", secciones)
Cada sección: (título, [párrafos]); un párrafo que empieza con "- " es una viñeta.
"""

PRODUCTOS = [
    # ------------------------------------------------------------------ Libros electrónicos
    ("Python desde cero: libro práctico",
     "Libro electrónico en PDF para aprender a programar en Python con ejemplos cortos, buenas prácticas y ejercicios al final de cada capítulo.",
     24900, "python_desde_cero.pdf", "Libros electrónicos",
     ["8 capítulos con ejemplos ejecutables", "Ejercicios con respuestas", "Buenas prácticas y errores comunes", "Ideal para primer semestre"],
     [("Capítulo 1. Primeros pasos", [
         "Python es un lenguaje interpretado, de tipado dinámico y con una sintaxis que privilegia la legibilidad. Un programa es una secuencia de instrucciones que el intérprete ejecuta de arriba hacia abajo.",
         "Para comenzar instala Python 3, abre una terminal y escribe python. El símbolo >>> indica que el intérprete espera una instrucción.",
         "- print('Hola, mundo') muestra texto en pantalla.",
         "- input('Tu nombre: ') lee lo que escribe el usuario y siempre devuelve una cadena."]),
      ("Capítulo 2. Variables y tipos", [
         "Una variable es un nombre asociado a un valor. Los tipos básicos son int, float, str y bool. La función type() indica el tipo de cualquier valor.",
         "- Convierte con int('42'), float('3.5') o str(10).",
         "- Los nombres de variables usan minúsculas y guiones bajos: total_ventas.",
         "Error común: sumar una cadena y un número. '5' + 3 provoca TypeError; primero convierte con int('5')."]),
      ("Capítulo 3. Decisiones", [
         "La instrucción if evalúa una condición. Los bloques se delimitan con sangría de cuatro espacios, no con llaves.",
         "- if, elif y else permiten varias ramas.",
         "- Los operadores lógicos son and, or y not.",
         "Ejercicio: escribe un programa que diga si un año es bisiesto (divisible entre 4, salvo los divisibles entre 100 que no lo sean entre 400)."]),
      ("Capítulo 4. Ciclos", [
         "for recorre los elementos de una secuencia; while repite mientras una condición sea verdadera. range(inicio, fin, paso) genera secuencias de enteros.",
         "- break termina el ciclo; continue salta a la siguiente vuelta.",
         "Ejercicio: suma los números del 1 al 100 con un for y comprueba que el resultado es 5050."]),
      ("Capítulo 5. Funciones", [
         "Una función agrupa instrucciones reutilizables. Se define con def, recibe parámetros y devuelve un valor con return.",
         "- Usa nombres que describan la acción: calcular_promedio(calificaciones).",
         "- Documenta con una cadena de documentación entre comillas triples.",
         "Buena práctica: una función debe hacer una sola cosa y hacerla bien."]),
      ("Capítulo 6. Listas y diccionarios", [
         "Las listas guardan elementos en orden y se modifican con append, insert y remove. Los diccionarios asocian claves con valores.",
         "- Comprensión de listas: cuadrados = [x * x for x in range(10)].",
         "- Recorre un diccionario con for clave, valor in datos.items()."]),
      ("Capítulo 7. Archivos y excepciones", [
         "Abre archivos con with open('datos.txt', encoding='utf-8') as f: así se cierran solos aunque ocurra un error.",
         "try y except capturan errores esperados sin detener el programa. Captura excepciones específicas, nunca un except vacío."]),
      ("Capítulo 8. Proyecto final", [
         "Construye una agenda de contactos que guarde nombre, teléfono y correo en un archivo CSV, permita buscar por nombre y valide los datos de entrada.",
         "Respuesta del ejercicio del capítulo 3: es bisiesto si (a % 4 == 0 and a % 100 != 0) or a % 400 == 0."])]),

    ("Estructuras de datos y algoritmos explicados",
     "Libro electrónico en PDF con explicaciones visuales de pilas, colas, árboles, grafos, ordenamiento y análisis de complejidad Big-O.",
     27900, "estructuras_de_datos.pdf", "Libros electrónicos",
     ["Notación Big-O sin misterio", "Pilas, colas, listas, árboles y grafos", "Ordenamiento y búsqueda", "Preguntas tipo examen"],
     [("1. ¿Por qué importa la complejidad?", [
         "La notación Big-O describe cómo crece el tiempo o la memoria de un algoritmo cuando crece la entrada. Permite comparar soluciones sin depender de la computadora.",
         "- O(1): acceder a un elemento de un arreglo por índice.",
         "- O(log n): búsqueda binaria en un arreglo ordenado.",
         "- O(n): recorrer una lista una vez.",
         "- O(n log n): merge sort y, en promedio, quicksort.",
         "- O(n²): dos ciclos anidados sobre la misma entrada."]),
      ("2. Pilas y colas", [
         "Una pila sigue la regla LIFO (último en entrar, primero en salir): sirve para deshacer acciones y evaluar expresiones. Una cola sigue la regla FIFO y modela turnos y tareas pendientes.",
         "Ambas ofrecen inserción y extracción en O(1) cuando se implementan correctamente."]),
      ("3. Listas enlazadas", [
         "Cada nodo guarda un valor y una referencia al siguiente. Insertar al inicio cuesta O(1), pero acceder al elemento k cuesta O(k) porque hay que recorrer los nodos."]),
      ("4. Árboles", [
         "Un árbol binario de búsqueda mantiene a la izquierda los valores menores y a la derecha los mayores. Si está balanceado, buscar, insertar y borrar cuestan O(log n).",
         "- Recorrido en orden: izquierda, raíz, derecha (devuelve los valores ordenados).",
         "- Un árbol degenerado se comporta como una lista: O(n)."]),
      ("5. Grafos", [
         "Un grafo es un conjunto de vértices unidos por aristas. Se representa con matriz de adyacencia o con listas de adyacencia.",
         "- BFS (búsqueda en anchura) encuentra el camino con menos aristas.",
         "- DFS (búsqueda en profundidad) detecta ciclos y componentes.",
         "- Dijkstra calcula rutas mínimas con pesos no negativos."]),
      ("6. Ordenamiento", [
         "Burbuja e inserción son O(n²) y útiles solo para entradas pequeñas. Merge sort garantiza O(n log n) y es estable; quicksort es muy rápido en promedio pero O(n²) en el peor caso."]),
      ("7. Preguntas tipo examen", [
         "- ¿Qué estructura usarías para verificar paréntesis balanceados? (pila)",
         "- ¿Por qué la búsqueda binaria exige un arreglo ordenado?",
         "- ¿Cuál es la complejidad de buscar en una tabla hash en promedio? (O(1))"])]),

    # ------------------------------------------------------------------ Manuales
    ("Manual de Git y GitHub para equipos",
     "Manual en Markdown para trabajar en equipo con Git: ramas, commits, pull requests, resolución de conflictos y flujo de trabajo recomendado.",
     15900, "manual_git_github.md", "Manuales",
     ["Configuración inicial paso a paso", "Flujo de ramas para proyectos escolares", "Cómo resolver conflictos", "Comandos de emergencia"],
     [("1. Configuración inicial", [
         "Configura tu identidad una sola vez por computadora; aparecerá en cada commit.",
         "- git config --global user.name \"Tu Nombre\"",
         "- git config --global user.email tu@correo.com",
         "- git config --global init.defaultBranch main"]),
      ("2. El ciclo básico", [
         "Git guarda instantáneas del proyecto. El área de preparación (staging) permite elegir qué cambios entran en cada commit.",
         "- git status: muestra qué cambió.",
         "- git add archivo: prepara el cambio.",
         "- git commit -m \"Agrega validación de correo\": guarda la instantánea.",
         "- git push: envía los commits al repositorio remoto."]),
      ("3. Ramas", [
         "Cada funcionalidad se desarrolla en su propia rama para no romper main. Nombra las ramas por su propósito: feature/carrito, fix/login.",
         "- git switch -c feature/carrito crea la rama y cambia a ella.",
         "- git switch main regresa a la rama principal."]),
      ("4. Pull requests", [
         "Un pull request propone integrar una rama en main. Otro integrante revisa el código, comenta y aprueba. Así se detectan errores antes de que lleguen a la versión estable.",
         "Buena práctica: pull requests pequeños, con una descripción de qué cambia y cómo probarlo."]),
      ("5. Conflictos", [
         "Un conflicto ocurre cuando dos ramas cambian las mismas líneas. Git marca el archivo con <<<<<<<, ======= y >>>>>>>. Edita el archivo dejando la versión correcta, borra las marcas, y luego haz git add y git commit."]),
      ("6. Comandos de emergencia", [
         "- git restore archivo: descarta cambios sin preparar.",
         "- git restore --staged archivo: saca un archivo del staging.",
         "- git revert <commit>: crea un commit que deshace otro sin reescribir la historia.",
         "- Nunca subas contraseñas ni claves: agrégalas a .gitignore."])]),

    ("Manual de hoja de cálculo para principiantes",
     "Manual de usuario en PDF: fórmulas, referencias absolutas, funciones SI, BUSCARV, tablas dinámicas y formato condicional con ejemplos.",
     13900, "manual_hoja_de_calculo.pdf", "Manuales",
     ["Fórmulas y referencias", "Funciones más usadas", "Tablas dinámicas", "Ejercicios con datos de ventas"],
     [("1. Conceptos básicos", [
         "Una hoja de cálculo organiza datos en celdas identificadas por columna y fila (por ejemplo, B3). Toda fórmula comienza con el signo igual.",
         "- =A1+A2 suma dos celdas.",
         "- =SUMA(A1:A10) suma un rango.",
         "- =PROMEDIO(B2:B20) calcula la media."]),
      ("2. Referencias relativas y absolutas", [
         "Al copiar una fórmula, las referencias relativas se ajustan solas. Para fijar una celda usa el signo de pesos: $B$1. Es indispensable cuando todas las filas usan la misma tasa o el mismo precio."]),
      ("3. Funciones lógicas", [
         "=SI(condición; valor_si_verdadero; valor_si_falso) devuelve un resultado según una condición.",
         "- =SI(C2>=6; \"Aprobado\"; \"Reprobado\")",
         "- Y() y O() combinan varias condiciones."]),
      ("4. Búsquedas", [
         "BUSCARV busca un valor en la primera columna de una tabla y devuelve el dato de otra columna de la misma fila. Usa FALSO como último argumento para coincidencia exacta.",
         "- =BUSCARV(\"P-102\"; A2:D50; 3; FALSO)"]),
      ("5. Tablas dinámicas", [
         "Resumen grandes volúmenes de datos sin fórmulas: arrastra campos a filas, columnas y valores para obtener totales por categoría, mes o vendedor."]),
      ("6. Formato condicional", [
         "Colorea celdas automáticamente según su valor: por ejemplo, en rojo los inventarios por debajo del mínimo. Facilita detectar problemas a simple vista."])]),

    # ------------------------------------------------------------------ Documentos técnicos
    ("Especificación técnica: API REST de pedidos",
     "Documento técnico en Markdown con el diseño de una API REST: recursos, verbos HTTP, códigos de estado, autenticación y ejemplos JSON.",
     18900, "especificacion_api_rest.md", "Documentos técnicos",
     ["Diseño de recursos y rutas", "Códigos de estado HTTP", "Autenticación con tokens", "Ejemplos de petición y respuesta"],
     [("1. Alcance", [
         "Este documento especifica la API de pedidos de una tienda en línea. La API usa HTTPS, intercambia JSON en UTF-8 y sigue el estilo REST."]),
      ("2. Recursos y rutas", [
         "- GET /api/v1/productos: lista productos activos (paginado).",
         "- GET /api/v1/productos/{id}: detalle de un producto.",
         "- POST /api/v1/pedidos: crea un pedido para el usuario autenticado.",
         "- GET /api/v1/pedidos/{id}: consulta un pedido propio.",
         "- POST /api/v1/pedidos/{id}/pago: registra el pago de un pedido pendiente."]),
      ("3. Códigos de estado", [
         "- 200 OK y 201 Created para operaciones exitosas.",
         "- 400 Bad Request si el cuerpo no es válido.",
         "- 401 Unauthorized si falta el token; 403 Forbidden si el usuario no tiene permiso.",
         "- 404 Not Found si el recurso no existe o no pertenece al usuario.",
         "- 409 Conflict si el pedido ya fue pagado."]),
      ("4. Autenticación", [
         "Cada petición protegida envía Authorization: Bearer <token>. Los tokens expiran en 30 minutos y se renuevan con un token de actualización. El servidor nunca confía en el precio que envía el cliente: lo calcula a partir del catálogo."]),
      ("5. Ejemplo", [
         "Petición: POST /api/v1/pedidos con el cuerpo {\"productos\": [3, 7]}.",
         "Respuesta 201: {\"id\": 120, \"estado\": \"PENDIENTE\", \"total_centavos\": 43800}."]),
      ("6. Requisitos no funcionales", [
         "- Tiempo de respuesta menor a 300 ms en el percentil 95.",
         "- Registro de auditoría de creación y pago de pedidos.",
         "- Límite de 60 peticiones por minuto por usuario."])]),

    ("Documento técnico: arquitectura de microservicios",
     "Documento técnico en PDF que compara monolito y microservicios, describe comunicación síncrona y asíncrona, despliegue con contenedores y observabilidad.",
     22900, "arquitectura_microservicios.pdf", "Documentos técnicos",
     ["Monolito vs microservicios", "Patrones de comunicación", "Contenedores y orquestación", "Checklist de decisión"],
     [("1. Contexto", [
         "Una arquitectura monolítica despliega toda la aplicación como una sola unidad. Es sencilla al principio, pero cada cambio obliga a desplegar todo y un fallo puede afectar al sistema completo.",
         "Los microservicios dividen el sistema en servicios pequeños, cada uno con su propia base de datos y su propio ciclo de despliegue."]),
      ("2. Cuándo conviene cada una", [
         "- Equipo pequeño y dominio aún cambiante: monolito modular.",
         "- Varios equipos independientes y partes con carga muy distinta: microservicios.",
         "- Los microservicios agregan complejidad operativa: red, monitoreo y consistencia de datos."]),
      ("3. Comunicación", [
         "La comunicación síncrona (HTTP/REST o gRPC) es simple pero acopla la disponibilidad de los servicios. La asíncrona con colas de mensajes desacopla y absorbe picos de carga, a cambio de consistencia eventual."]),
      ("4. Despliegue", [
         "Cada servicio se empaqueta en un contenedor con sus dependencias. Un orquestador reinicia instancias caídas, escala según la demanda y distribuye el tráfico."]),
      ("5. Observabilidad", [
         "- Registros estructurados con un identificador de correlación por petición.",
         "- Métricas de latencia, tasa de errores y saturación.",
         "- Trazas distribuidas para seguir una petición entre servicios."]),
      ("6. Checklist de decisión", [
         "- ¿Los límites del dominio están claros?",
         "- ¿El equipo puede operar varios despliegues independientes?",
         "- ¿Existe monitoreo centralizado antes de dividir el sistema?"])]),

    ("Plantilla de requerimientos de software (IEEE 830)",
     "Documento técnico en texto plano con la estructura completa de una especificación de requerimientos, lista para llenar en proyectos escolares.",
     9900, "plantilla_requerimientos.txt", "Documentos técnicos",
     ["Estructura completa por secciones", "Ejemplos de requerimientos bien escritos", "Matriz de trazabilidad", "Lista para llenar"],
     [("1. Introducción", [
         "1.1 Propósito: describe qué sistema se especifica y para quién es el documento.",
         "1.2 Alcance: nombre del sistema, qué hará y qué NO hará.",
         "1.3 Definiciones y acrónimos.",
         "1.4 Referencias."]),
      ("2. Descripción general", [
         "2.1 Perspectiva del producto: relación con otros sistemas.",
         "2.2 Funciones principales en una lista breve.",
         "2.3 Características de los usuarios.",
         "2.4 Restricciones: normativas, tecnológicas o de presupuesto."]),
      ("3. Requerimientos funcionales", [
         "Escribe cada requerimiento con un identificador, una sola acción y un criterio verificable.",
         "- RF-01 El sistema permitirá al cliente registrarse con correo y contraseña.",
         "- RF-02 El sistema enviará un código de confirmación al correo registrado.",
         "- Mal ejemplo: 'El sistema será fácil de usar' (no se puede verificar)."]),
      ("4. Requerimientos no funcionales", [
         "- RNF-01 Las contraseñas se almacenarán con un algoritmo de derivación lento (Argon2id).",
         "- RNF-02 El 95% de las páginas responderá en menos de 2 segundos.",
         "- RNF-03 El sistema estará disponible el 99% del tiempo mensual."]),
      ("5. Matriz de trazabilidad", [
         "Relaciona cada requerimiento con su caso de uso, su módulo y su caso de prueba. Así se demuestra que todo lo pedido se construyó y se probó."])]),

    # ------------------------------------------------------------------ Apuntes
    ("Apuntes de bases de datos relacionales y SQL",
     "Apuntes en Markdown: modelo entidad-relación, normalización hasta 3FN, consultas SQL con JOIN, agrupación y transacciones.",
     9900, "apuntes_bases_de_datos.md", "Apuntes",
     ["Modelo E-R y llaves", "Normalización 1FN, 2FN y 3FN", "SQL con ejemplos", "Transacciones y ACID"],
     [("Modelo entidad-relación", [
         "Una entidad es un objeto del dominio (Cliente, Pedido). Sus atributos la describen y la llave primaria la identifica de forma única. Las relaciones tienen cardinalidad: uno a uno, uno a muchos o muchos a muchos.",
         "- Una relación muchos a muchos se resuelve con una tabla intermedia (por ejemplo, detalle_pedido)."]),
      ("Normalización", [
         "- 1FN: cada celda contiene un solo valor y no hay grupos repetidos.",
         "- 2FN: además, ningún atributo depende solo de una parte de la llave compuesta.",
         "- 3FN: además, ningún atributo depende de otro atributo que no sea llave."]),
      ("Consultas básicas", [
         "- SELECT nombre, precio FROM productos WHERE precio > 100 ORDER BY precio DESC;",
         "- INSERT INTO clientes(nombre, correo) VALUES ('Ana', 'ana@correo.com');",
         "- UPDATE productos SET precio = 120 WHERE id = 3;"]),
      ("JOIN y agrupación", [
         "INNER JOIN devuelve solo las filas con coincidencia en ambas tablas; LEFT JOIN conserva todas las de la izquierda.",
         "- SELECT c.nombre, COUNT(p.id) FROM clientes c LEFT JOIN pedidos p ON p.cliente_id = c.id GROUP BY c.nombre;",
         "- HAVING filtra después de agrupar; WHERE filtra antes."]),
      ("Transacciones", [
         "Una transacción agrupa operaciones que deben ocurrir todas o ninguna. Las propiedades ACID son atomicidad, consistencia, aislamiento y durabilidad.",
         "Seguridad: usa siempre consultas parametrizadas; nunca concatenes texto del usuario en el SQL."])]),

    ("Apuntes de cálculo diferencial",
     "Apuntes en texto plano con límites, reglas de derivación, regla de la cadena, máximos y mínimos y ejercicios resueltos paso a paso.",
     7900, "apuntes_calculo_diferencial.txt", "Apuntes",
     ["Límites y continuidad", "Reglas de derivación", "Aplicaciones: máximos y mínimos", "Ejercicios resueltos"],
     [("LIMITES", [
         "El límite de f(x) cuando x tiende a a es el valor al que se acerca f(x) cuando x se acerca a a, sin importar el valor de f en a.",
         "- Si al sustituir aparece 0/0, factoriza o racionaliza antes de evaluar.",
         "- Ejemplo: lim (x^2 - 9)/(x - 3) cuando x->3 = lim (x + 3) = 6."]),
      ("CONTINUIDAD", [
         "f es continua en a si f(a) existe, el límite existe y ambos son iguales."]),
      ("REGLAS DE DERIVACION", [
         "- (c)' = 0",
         "- (x^n)' = n x^(n-1)",
         "- (f g)' = f' g + f g'",
         "- (f / g)' = (f' g - f g') / g^2",
         "- (sen x)' = cos x ; (cos x)' = -sen x ; (e^x)' = e^x ; (ln x)' = 1/x"]),
      ("REGLA DE LA CADENA", [
         "Si y = f(g(x)), entonces y' = f'(g(x)) * g'(x).",
         "- Ejemplo: y = (3x^2 + 1)^5 -> y' = 5(3x^2 + 1)^4 * 6x = 30x(3x^2 + 1)^4"]),
      ("MAXIMOS Y MINIMOS", [
         "1. Deriva y resuelve f'(x) = 0 para hallar puntos críticos.",
         "2. Evalúa f''(x): si es positiva hay un mínimo; si es negativa, un máximo.",
         "- Ejemplo: f(x) = x^2 - 4x + 1 -> f'(x) = 2x - 4 = 0 -> x = 2; f''(2) = 2 > 0, mínimo en (2, -3)."]),
      ("EJERCICIOS PROPUESTOS", [
         "- Deriva y = x^3 sen x.",
         "- Encuentra las dimensiones del rectángulo de área máxima con perímetro 40 (respuesta: cuadrado de 10 x 10)."])]),

    # ------------------------------------------------------------------ Guías
    ("Guía de estudio para entrevistas técnicas",
     "Guía en Markdown para preparar entrevistas de prácticas profesionales y empleos de software: método para resolver problemas, temas clave y plan de 4 semanas.",
     16900, "guia_entrevistas_tecnicas.md", "Guías",
     ["Método de 5 pasos para resolver problemas", "Temas que más se preguntan", "Preguntas conductuales (STAR)", "Plan de estudio de 4 semanas"],
     [("1. Método para resolver un problema en vivo", [
         "- Repite el problema con tus palabras y pregunta por los casos límite.",
         "- Propón primero una solución sencilla aunque sea lenta, y di su complejidad.",
         "- Mejórala: ¿una tabla hash, dos apuntadores u ordenar primero ayudarían?",
         "- Escribe el código explicando en voz alta.",
         "- Prueba con un ejemplo pequeño y con casos límite (lista vacía, un solo elemento)."]),
      ("2. Temas clave", [
         "- Arreglos y cadenas: dos apuntadores, ventana deslizante.",
         "- Tablas hash: conteo de frecuencias, detección de duplicados.",
         "- Árboles y grafos: BFS, DFS, recorridos.",
         "- Recursión y programación dinámica básica.",
         "- Complejidad de tiempo y memoria."]),
      ("3. Preguntas conductuales", [
         "Responde con el método STAR: Situación, Tarea, Acción y Resultado. Prepara historias reales de proyectos escolares: un conflicto en el equipo, un error que corregiste, algo que aprendiste rápido."]),
      ("4. Plan de 4 semanas", [
         "- Semana 1: arreglos, cadenas y tablas hash (2 problemas diarios).",
         "- Semana 2: listas enlazadas, pilas, colas y árboles.",
         "- Semana 3: grafos y recursión.",
         "- Semana 4: simulacros cronometrados y preguntas conductuales."])]),

    ("Guía rápida de comandos Linux",
     "Guía visual en PNG (tamaño carta) con los comandos de terminal más usados: archivos, permisos, procesos, red y búsqueda.",
     5900, "guia_comandos_linux.png", "Guías",
     ["Navegación y archivos", "Permisos", "Procesos y red", "Lista para imprimir"],
     [("Navegación", ["pwd · ls -la · cd ruta · cd ..", "mkdir dir · touch archivo", "cp origen destino · mv · rm -i"]),
      ("Ver archivos", ["cat · less · head -n 20 · tail -f log", "wc -l archivo · diff a b"]),
      ("Permisos", ["chmod 640 archivo · chmod u+x script.sh", "chown usuario:grupo archivo", "sudo comando (solo si es necesario)"]),
      ("Buscar", ["grep -rn \"texto\" carpeta/", "find . -name \"*.py\"", "which python3"]),
      ("Procesos", ["ps aux · top · kill PID", "comando & · jobs · fg"]),
      ("Red", ["ip a · ping host · ss -tulpn", "curl -I https://sitio · ssh usuario@host"])]),

    ("Guía para redactar tu reporte de investigación",
     "Guía en PDF para estructurar un reporte o tesis: planteamiento del problema, objetivos, marco teórico, metodología, resultados y citas en formato APA.",
     12900, "guia_reporte_investigacion.pdf", "Guías",
     ["Estructura capítulo por capítulo", "Cómo escribir objetivos medibles", "Citas y referencias APA", "Lista de revisión final"],
     [("1. Planteamiento del problema", [
         "Describe la situación actual, por qué es un problema y a quién afecta. Respáldalo con datos o antecedentes. Termina con una pregunta de investigación clara y delimitada."]),
      ("2. Objetivos", [
         "El objetivo general dice qué se logrará; los específicos, los pasos para lograrlo. Empiezan con un verbo en infinitivo y deben poder comprobarse.",
         "- Correcto: Evaluar el tiempo de depuración de 30 estudiantes con y sin la dinámica propuesta.",
         "- Incorrecto: Conocer más sobre la depuración."]),
      ("3. Marco teórico", [
         "Reúne los conceptos y estudios previos que sustentan tu trabajo. Cada idea ajena lleva su cita. Organízalo por temas, no por autor."]),
      ("4. Metodología", [
         "Indica el enfoque (cuantitativo, cualitativo o mixto), la población y muestra, los instrumentos y el procedimiento, con suficiente detalle para que otra persona pueda repetirlo."]),
      ("5. Resultados y conclusiones", [
         "Presenta los resultados con tablas y gráficas numeradas y explícalos. En las conclusiones responde la pregunta de investigación y menciona limitaciones y trabajo futuro."]),
      ("6. Citas en formato APA", [
         "- Cita en el texto: (Apellido, año) o Apellido (año).",
         "- Referencia de libro: Apellido, A. (año). Título en cursiva. Editorial.",
         "- Referencia de artículo: Apellido, A. (año). Título. Nombre de la revista, volumen(número), páginas."]),
      ("7. Revisión final", [
         "- ¿Cada objetivo tiene un resultado?",
         "- ¿Todas las citas están en las referencias y viceversa?",
         "- ¿Tablas y figuras están numeradas y citadas en el texto?"])]),

    # ------------------------------------------------------------------ Material educativo
    ("Ejercicios resueltos de lógica de programación",
     "Material educativo en texto plano: 12 ejercicios de lógica con pseudocódigo y solución comentada, de menor a mayor dificultad.",
     6900, "ejercicios_logica_programacion.txt", "Material educativo",
     ["12 ejercicios graduados", "Pseudocódigo y solución", "Pruebas de escritorio", "Ideal para practicar antes de un examen"],
     [("EJERCICIO 1 - PAR O IMPAR", [
         "Leer un número entero e indicar si es par.",
         "Solución: si numero mod 2 = 0 entonces escribir 'par' si no escribir 'impar'."]),
      ("EJERCICIO 2 - MAYOR DE TRES", [
         "Leer a, b y c y mostrar el mayor.",
         "Solución: mayor <- a; si b > mayor entonces mayor <- b; si c > mayor entonces mayor <- c."]),
      ("EJERCICIO 3 - FACTORIAL", [
         "Calcular n! con un ciclo.",
         "Solución: f <- 1; para i desde 2 hasta n hacer f <- f * i. Prueba de escritorio con n = 5: 2, 6, 24, 120."]),
      ("EJERCICIO 4 - NUMERO PRIMO", [
         "Determinar si n es primo.",
         "Solución: basta probar divisores desde 2 hasta la raíz cuadrada de n; si ninguno divide a n, es primo."]),
      ("EJERCICIO 5 - INVERTIR UNA CADENA", [
         "Mostrar una palabra al revés.",
         "Solución: recorrer desde el último índice hasta 0 concatenando cada carácter."]),
      ("EJERCICIO 6 - PROMEDIO SIN EXTREMOS", [
         "Leer 10 calificaciones y promediar sin contar la mayor ni la menor.",
         "Solución: (suma - mayor - menor) / 8."]),
      ("EJERCICIOS 7 A 12", [
         "- 7. Serie de Fibonacci hasta n términos.",
         "- 8. Contar vocales de una frase.",
         "- 9. Convertir de decimal a binario con divisiones sucesivas.",
         "- 10. Búsqueda lineal en un arreglo.",
         "- 11. Ordenar un arreglo con burbuja.",
         "- 12. Validar un palíndromo ignorando espacios."])]),

    ("Infografía: ciclo de vida del desarrollo de software",
     "Material educativo en PNG: las fases del ciclo de vida del software, sus entregables y cómo se relacionan con la seguridad.",
     4900, "infografia_ciclo_de_vida.png", "Material educativo",
     ["6 fases con entregables", "Seguridad en cada fase", "Lista para imprimir o proyectar"],
     [("1. Requisitos", ["Entregable: especificación", "Seguridad: casos de abuso"]),
      ("2. Diseño", ["Entregable: arquitectura y modelos", "Seguridad: modelado de amenazas"]),
      ("3. Implementación", ["Entregable: código y pruebas unitarias", "Seguridad: validación de entradas"]),
      ("4. Pruebas", ["Entregable: reporte de pruebas", "Seguridad: pruebas de penetración"]),
      ("5. Despliegue", ["Entregable: versión en producción", "Seguridad: configuración segura y TLS"]),
      ("6. Mantenimiento", ["Entregable: parches y mejoras", "Seguridad: monitoreo y respaldos"])]),
]

# Categoría y "qué incluye" de los 4 productos originales (se asignan también en bases de datos ya existentes)
ORIGINALES = {
    "guia_criptografia.md": ("Libros electrónicos", ["Los cinco servicios de seguridad", "Hash, AES, RSA y PKI explicados", "Ejercicios al final"]),
    "apuntes_redes_seguras.txt": ("Apuntes", ["TLS, SSH, IPSec y VPN", "Arquitectura de administración", "Preguntas de repaso"]),
    "manual_seguridad_web.pdf": ("Manuales", ["Validación de entradas", "Sesiones y control de acceso", "Registro y manejo de errores"]),
    "infografia_tls.png": ("Material educativo", ["Cadena de confianza en un vistazo", "Lista para imprimir"]),
}


# ================================================================ generadores por formato
def _es_vineta(p):
    return p.startswith("- ")


def a_markdown(nombre, descripcion, secciones):
    partes = [f"# {nombre}", "", f"> {descripcion}", ""]
    for titulo, parrafos in secciones:
        partes += [f"## {titulo}", ""]
        previo_vineta = False
        for p in parrafos:
            if _es_vineta(p):
                partes.append(p)
                previo_vineta = True
            else:
                if previo_vineta:
                    partes.append("")
                partes += [p, ""]
                previo_vineta = False
        if previo_vineta:
            partes.append("")
    partes.append("---\nMaterial de uso personal. Esta copia está asociada a tu cuenta.\n")
    return "\n".join(partes).encode("utf-8")


def a_texto(nombre, descripcion, secciones):
    import textwrap
    lineas = [nombre.upper(), "=" * min(len(nombre), 70), "", *textwrap.wrap(descripcion, 90), ""]
    for titulo, parrafos in secciones:
        lineas += [titulo, "-" * len(titulo)]
        for p in parrafos:
            if _es_vineta(p):
                lineas += textwrap.wrap(p, 90, subsequent_indent="  ")
            else:
                lineas += textwrap.wrap(p, 90) + [""]
        lineas.append("")
    lineas.append("Material de uso personal. Esta copia esta asociada a tu cuenta.")
    return ("\n".join(lineas) + "\n").encode("utf-8")


_COLORES = {"Libros electrónicos": "#3a86ff", "Manuales": "#e63946", "Documentos técnicos": "#8338ec",
            "Apuntes": "#ffbe0b", "Guías": "#2ec4b6", "Material educativo": "#fb8500"}


def a_pdf(nombre, descripcion, secciones, categoria):
    """PDF con portada de color, encabezados y viñetas (reportlab/platypus, texto real seleccionable)."""
    import io
    from xml.sax.saxutils import escape
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer
    color = colors.HexColor(_COLORES.get(categoria, "#1f3a5f"))
    est = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=est["Title"], fontSize=26, leading=32, textColor=colors.white, alignment=0)
    sub = ParagraphStyle("sub", parent=est["Normal"], fontSize=12, leading=17, textColor=colors.white)
    h2 = ParagraphStyle("h2", parent=est["Heading2"], textColor=color, spaceBefore=14, spaceAfter=6)
    cuerpo = ParagraphStyle("c", parent=est["BodyText"], fontSize=11, leading=16, spaceAfter=6)

    def portada(c, _doc):
        c.saveState()
        c.setFillColor(colors.HexColor("#0b1426"))
        c.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
        c.setFillColor(color)
        c.rect(0, letter[1] - 9 * cm, letter[0], 9 * cm, fill=1, stroke=0)
        for i in range(0, int(letter[0]) + 40, 40):             # toldo a rayas
            c.setFillColor(colors.HexColor("#e63946") if (i // 40) % 2 == 0 else colors.white)
            c.rect(i, letter[1] - 1.1 * cm, 40, 1.1 * cm, fill=1, stroke=0)
        c.setFillColor(colors.HexColor("#9fb0cf"))
        c.setFont("Helvetica", 9)
        c.drawString(2 * cm, 1.5 * cm, f"Tienda Segura · {categoria}")
        c.restoreState()

    def pagina(c, doc):
        c.saveState()
        c.setFillColor(color)
        c.rect(0, letter[1] - 0.4 * cm, letter[0], 0.4 * cm, fill=1, stroke=0)
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.grey)
        c.drawString(2 * cm, 1.2 * cm, nombre)
        c.drawRightString(letter[0] - 2 * cm, 1.2 * cm, f"Página {doc.page}")
        c.restoreState()

    historia = [Spacer(1, 2.2 * cm), Paragraph(escape(nombre), h1), Spacer(1, 0.4 * cm), Paragraph(escape(descripcion), sub),
                Spacer(1, 9 * cm), Paragraph(escape(categoria.upper()), sub), PageBreak()]
    for titulo, parrafos in secciones:
        historia.append(Paragraph(escape(titulo), h2))
        vinetas = []
        for p in parrafos + [""]:
            if p and _es_vineta(p):
                vinetas.append(ListItem(Paragraph(escape(p[2:]), cuerpo), leftIndent=12))
                continue
            if vinetas:
                historia.append(ListFlowable(vinetas, bulletType="bullet", start="•", leftIndent=14))
                vinetas = []
            if p:
                historia.append(Paragraph(escape(p), cuerpo))
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=letter, leftMargin=2.2 * cm, rightMargin=2.2 * cm, topMargin=2 * cm, bottomMargin=2 * cm,
                      title=nombre, author="Tienda Segura").build(historia, onFirstPage=portada, onLaterPages=pagina)
    return buf.getvalue()


def _fuente(tamano, negrita=False):
    from PIL import ImageFont
    nombres = (["DejaVuSans-Bold.ttf", "arialbd.ttf", "Arial Bold.ttf"] if negrita else ["DejaVuSans.ttf", "arial.ttf", "Arial.ttf"])
    for n in nombres:
        for base in ("", "/usr/share/fonts/truetype/dejavu/", "C:/Windows/Fonts/", "/Library/Fonts/"):
            try:
                return ImageFont.truetype(base + n, tamano)
            except OSError:
                continue
    try:
        return ImageFont.load_default(size=tamano)
    except TypeError:
        return ImageFont.load_default()


def a_png(nombre, secciones, categoria):
    """Ficha visual / infografía: título, y una tarjeta de color por sección."""
    import io
    from PIL import Image, ImageDraw
    color = _COLORES.get(categoria, "#3a86ff")
    ancho, alto = 850, 1100
    img = Image.new("RGB", (ancho, alto), (11, 20, 38))
    d = ImageDraw.Draw(img)
    for i in range(0, ancho, 34):                                   # toldo
        d.rectangle((i, 0, i + 34, 40), fill=(230, 57, 70) if (i // 34) % 2 == 0 else (255, 255, 255))
    for i in range(0, ancho + 34, 34):
        d.pieslice((i - 17, 23, i + 17, 57), 0, 180, fill=(230, 57, 70) if (i // 34) % 2 == 0 else (255, 255, 255))
    for y in range(80, alto, 6):                                     # textura sutil (mejora la huella LSB)
        d.line((0, y, ancho, y), fill=(13 + (y // 6) % 3, 22, 42 + (y // 6) % 4))
    tam = 34
    while tam > 22 and d.textlength(nombre, font=_fuente(tam, True)) > ancho - 96:
        tam -= 2
    d.text((48, 82), nombre, font=_fuente(tam, True), fill=(255, 255, 255))
    d.text((48, 132), categoria.upper() + " · TIENDA SEGURA", font=_fuente(16, True), fill=(255, 190, 11))
    columnas, x0, y0, gx, gy = 2, 48, 185, 20, 22
    n_filas = (len(secciones) + 1) // 2
    w = (ancho - 2 * x0 - gx) // columnas
    h = (alto - y0 - 60 - gy * (n_filas - 1)) // n_filas
    acento = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
    for k, (titulo, lineas) in enumerate(secciones):
        x = x0 + (k % columnas) * (w + gx)
        y = y0 + (k // columnas) * (h + gy)
        d.rounded_rectangle((x, y, x + w, y + h), radius=22, fill=(19, 33, 59), outline=acento, width=3)
        d.rounded_rectangle((x + 18, y + 18, x + 62, y + 62), radius=12, fill=acento)
        d.text((x + 40, y + 40), str(k + 1), font=_fuente(26, True), fill=(255, 255, 255), anchor="mm")
        d.text((x + 78, y + 26), titulo, font=_fuente(24, True), fill=(255, 255, 255))
        yy = y + 84
        for linea in lineas:
            for trozo in _partir(linea, 34):
                d.text((x + 22, yy), trozo, font=_fuente(17), fill=(200, 212, 235))
                yy += 26
            yy += 8
    d.text((48, alto - 40), "Copia personal: cada descarga lleva una huella invisible ligada al comprador.",
           font=_fuente(14), fill=(120, 140, 175))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _partir(texto, n):
    import textwrap
    return textwrap.wrap(texto, n) or [""]


def generar(nombre, descripcion, archivo, categoria, secciones):
    ext = archivo.rsplit(".", 1)[-1]
    if ext == "md":
        return a_markdown(nombre, descripcion, secciones)
    if ext == "txt":
        return a_texto(nombre, descripcion, secciones)
    if ext == "pdf":
        return a_pdf(nombre, descripcion, secciones, categoria)
    return a_png(nombre, secciones, categoria)
