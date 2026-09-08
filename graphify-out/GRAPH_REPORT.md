# Graph Report - exam-network-lock  (2026-09-08)

## Corpus Check
- 65 files · ~46,860 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1040 nodes · 1748 edges · 54 communities (46 shown, 8 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 75 edges (avg confidence: 0.83)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `885341b0`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- MainForm
- MainForm
- MonitorReporter
- AudioAlerter
- MainForm
- Shared.cs
- MainForm
- English
- FileActivityMonitor
- Dominios/IPs considerados IA
- ExamShared.csproj
- Full Pipeline
- Query Workflow
- Incremental Update
- ShieldControl
- Escudo de examen Client Window
- ConfigPayload
- AiConnectionEvidence
- ExamShared
- Lang
- Generador de configuración de examen
- Student edu10@EDU
- Lang
- Lang
- LogEntry
- ConfigEnvelope
- StatusTier
- .InitializeServices
- EventCatalog
- ProcessPolicy
- ExamLogVerifierUI
- DnsCacheMonitor
- ProcessMonitor
- Extraction Subagent Prompt
- Export Flags
- .DocumentArguments
- LogVerificationResult
- process-rules.md
- folder-monitoring.md
- Cross Repo Merge
- /graphify
- TcpConnectionOwner
- What You Must Do When Invoked
- Català
- Castellano
- graphify reference: extra exports and benchmark
- graphify reference: query, path, explain
- graphify reference: add a URL and watch a folder
- graphify reference: commit hook and native CLAUDE.md integration
- graphify reference: incremental update and cluster-only
- graphify reference: GitHub clone and cross-repo merge
- graphify reference: transcribe video and audio
- AGENTS.md
- extraction-spec.md

## God Nodes (most connected - your core abstractions)
1. `MainForm` - 62 edges
2. `MainForm` - 61 edges
3. `MainForm` - 44 edges
4. `ConfigPayload` - 32 edges
5. `MainForm` - 26 edges
6. `FileActivityMonitor` - 22 edges
7. `AudioAlerter` - 21 edges
8. `ExamShared` - 18 edges
9. `ExamLockClient` - 17 edges
10. `LogEntry` - 17 edges

## Surprising Connections (you probably didn't know these)
- `Query First Rule` --semantically_similar_to--> `Existing Graph Fast Path`  [INFERRED] [semantically similar]
  AGENTS.md → .codex/skills/graphify/SKILL.md
- `CLAUDE.md Integration` --semantically_similar_to--> `Project Graphify Instructions`  [INFERRED] [semantically similar]
  .codex/skills/graphify/references/hooks.md → AGENTS.md
- `MainForm` --references--> `ConfigPayload`  [EXTRACTED]
  ExamLockClient/MainForm.cs → ExamShared/Shared.cs
- `MainForm` --references--> `SecureLogService`  [EXTRACTED]
  ExamLockClient/MainForm.cs → ExamShared/Shared.cs
- `MainForm` --references--> `SessionStateService`  [EXTRACTED]
  ExamLockClient/MainForm.cs → ExamShared/Shared.cs

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Exam Locking Evidence Workflow** — readme_examconfiggenerator, readme_examlockclient, readme_examshared, readme_examlogverifier, readme_exammonitor, readme_tamper_evident_log [EXTRACTED 1.00]
- **Graphify Default Pipeline** — codex_skills_graphify_skill_file_detection, codex_skills_graphify_skill_ast_extraction, codex_skills_graphify_skill_semantic_extraction, codex_skills_graphify_skill_graph_build_cluster_analysis, codex_skills_graphify_skill_html_export, codex_skills_graphify_skill_manifest_cost_cleanup [EXTRACTED 1.00]
- **Control Panel Actions** — docs_img_client_wifi_password_input, docs_img_client_close_password_input, docs_img_client_restore_wifi_button, docs_img_client_close_program_button, docs_img_client_load_config_button [EXTRACTED 1.00]
- **Folder Scope Configuration** — docs_img_generator_bottom_folder_restriction, docs_img_generator_bottom_base_folder_exam_config, docs_img_generator_bottom_optional_subfolder, docs_img_generator_bottom_browse_subfolder [EXTRACTED 1.00]
- **AI Provider Domain Set** — docs_img_generator_top_claude_ai_domain, docs_img_generator_top_anthropic_domain, docs_img_generator_top_openai_domain, docs_img_generator_top_chatgpt_domain, docs_img_generator_top_oaistatic_domain, docs_img_generator_top_gemini_domain, docs_img_generator_top_bard_domain [EXTRACTED 1.00]
- **Exam Configuration Form Sections** — docs_img_generator_top_password_configuration, docs_img_generator_top_network_startup_controls, docs_img_generator_top_anti_ai_shield, docs_img_generator_top_generate_configuration_action [EXTRACTED 1.00]
- **Exam Monitor Operator Controls** — docs_img_monitor_load_config_button, docs_img_monitor_save_logs_button, docs_img_monitor_language_selector_flags [EXTRACTED 1.00]
- **Student Status Snapshot** — docs_img_monitor_student_identity, docs_img_monitor_exam_status_ok, docs_img_monitor_exam_in_progress_event, docs_img_monitor_event_count, docs_img_monitor_integrity_ok, docs_img_monitor_last_seen_recent [EXTRACTED 1.00]
- **Graphify Query Navigation** — agents_query_first_rule, codex_skills_graphify_references_query_constrained_query_expansion, codex_skills_graphify_references_query_bfs_traversal, codex_skills_graphify_references_query_dfs_traversal, codex_skills_graphify_references_query_save_result_feedback, codex_skills_graphify_references_query_networkx_fallback [INFERRED 0.85]
- **Restriction Inputs** — docs_img_generator_bottom_allowed_site_bard_google_com, docs_img_generator_bottom_allowed_executables, docs_img_generator_bottom_allowed_extensions, docs_img_generator_bottom_folder_restriction [INFERRED 0.85]
- **Exam Protection State Indicators** — docs_img_client_green_shield_check, docs_img_client_protected_status, docs_img_client_active_exam_message, docs_img_client_lock_started_event [INFERRED 0.95]

## Communities (54 total, 8 thin omitted)

### Community 0 - "MainForm"
Cohesion: 0.05
Nodes (35): DragEventArgs, Button, Color, Font, TextBox, Theme, Button, Color (+27 more)

### Community 1 - "MainForm"
Cohesion: 0.06
Nodes (23): error, EventArgs, Action, Button, Control, HashSet, Label, List (+15 more)

### Community 2 - "MonitorReporter"
Cohesion: 0.06
Nodes (28): List, Timer, MonitorReporter, IEnumerable, IPAddress, IReadOnlyList, JsonSerializerOptions, Task (+20 more)

### Community 3 - "AudioAlerter"
Cohesion: 0.09
Nodes (17): DllImport, IntPtr, AudioAlerter, Pattern, VolumePercent, BeepPattern, Continuous, ThreeBeeps (+9 more)

### Community 4 - "MainForm"
Cohesion: 0.06
Nodes (23): CheckBox, control, Button, ComboBox, Control, ctrl, GroupBox, IPAddress (+15 more)

### Community 5 - "Shared.cs"
Cohesion: 0.22
Nodes (6): BeepModes, ConfigDefaults, ConfigIntegrityService, LogEvents, WorkFolderModes, WorkFolderResolver

### Community 6 - "MainForm"
Cohesion: 0.05
Nodes (32): ClientRow, ExamMonitor, DateTime, Bitmap, Graphics, Flags, Dictionary, Lang (+24 more)

### Community 7 - "English"
Cohesion: 0.07
Nodes (43): Admin Permissions, AI detection is a safety net, AI Detection Safety Net, AI Shield, Allowed File Types, Allowed Programs, Blocked File Types, Build (+35 more)

### Community 8 - "FileActivityMonitor"
Cohesion: 0.17
Nodes (5): HashSet, IEnumerable, Timer, FileActivityMonitor, FileSystemWatcher

### Community 9 - "Dominios/IPs considerados IA"
Cohesion: 0.11
Nodes (21): Contraseña B - Cerrar / Admin, Subir volumen y pitar al detectar IA, Dominios/IPs considerados IA, anthropic.com, Escudo anti-IA, bard.google.com, chatgpt.com, claude.ai (+13 more)

### Community 10 - "ExamShared.csproj"
Cohesion: 0.09
Nodes (20): ExamConfigGenerator, net8.0-windows, Microsoft.NET.Sdk, ExamLockClient, System.Management (8.0.0), Microsoft.NET.Sdk, net8.0, Microsoft.NET.Sdk (+12 more)

### Community 11 - "Full Pipeline"
Cohesion: 0.13
Nodes (16): Transcript Docs, Video Audio Transcription, Whisper Model, Whisper Prompt Strategy, Cluster Only, Community Labeling, File Detection, Full Pipeline (+8 more)

### Community 12 - "Query Workflow"
Cohesion: 0.18
Nodes (13): Dirty Graph Tolerance, Query First Rule, BFS Traversal, Constrained Query Expansion, DFS Traversal, Graph Vocabulary, NetworkX Fallback, Node Explanation (+5 more)

### Community 13 - "Incremental Update"
Cohesion: 0.14
Nodes (18): Graph Report Fallback, Update After Modifying Code, Code Only AST Update, Docs Need Update Flag, Supported URL Types, URL Ingest, Watch Mode, Doc Image Manual Update (+10 more)

### Community 14 - "ShieldControl"
Cohesion: 0.12
Nodes (15): color, Control, Color, ShieldControl, Caption, Status, ShieldStatus, Green (+7 more)

### Community 15 - "Escudo de examen Client Window"
Cohesion: 0.20
Nodes (14): Examen en curso Message, Contraseña B cerrar Input, Cerrar programa Button, Config Path Display, ExamLockClient Debug Build Path, Escudo de examen Client Window, Green Shield Check Icon, Incidencias Log (+6 more)

### Community 16 - "ConfigPayload"
Cohesion: 0.07
Nodes (27): ConfigPayload, AdminPasswordHashBase64, AdminSaltBase64, AiBlocklist, AiShieldEnabled, AlarmVolumePercent, AllowedFileExtensions, AllowedProcesses (+19 more)

### Community 17 - "AiConnectionEvidence"
Cohesion: 0.05
Nodes (30): HashSet, IPAddress, Process, AiConnectionEvidence, CommandLine, DedupKey, Destination, IsStudentFacingProcess (+22 more)

### Community 18 - "ExamShared"
Cohesion: 0.15
Nodes (5): ExamShared, ExamLogVerifier, ExamLockClient, Dictionary, UiHelp

### Community 19 - "Lang"
Cohesion: 0.17
Nodes (11): Bitmap, Graphics, Flags, Dictionary, Lang, Current, FilePath, Language (+3 more)

### Community 20 - "Generador de configuración de examen"
Cohesion: 0.21
Nodes (12): Añadir and Quitar controls, Ejecutables permitidos, Extensiones permitidas, Allowed site bard.google.com, Base folder where exam.config is located, Examinar subfolder button, Vacío = sin restricción, Generador de configuración de examen (+4 more)

### Community 21 - "Student edu10@EDU"
Cohesion: 0.18
Nodes (12): Event Count 7, Exam In Progress Event, Monitor de examen Window, Exam Status OK, Integrity OK, exam.config Loaded Integrity Verification Message, Language Selector Flags, Last Seen hace 2s (+4 more)

### Community 22 - "Lang"
Cohesion: 0.12
Nodes (14): ExamConfigGenerator, Bitmap, Graphics, Flags, Dictionary, Lang, Current, FilePath (+6 more)

### Community 23 - "Lang"
Cohesion: 0.17
Nodes (11): Bitmap, Graphics, Flags, Dictionary, Lang, Current, FilePath, Language (+3 more)

### Community 24 - "LogEntry"
Cohesion: 0.21
Nodes (8): LogEntry, EventData, EventType, HmacBase64, PrevHmacBase64, Sequence, Timestamp, SecureLogService

### Community 25 - "ConfigEnvelope"
Cohesion: 0.22
Nodes (6): Program, JsonSerializerOptions, ConfigEnvelope, HmacBase64, Payload, ConfigSerializer

### Community 26 - "StatusTier"
Cohesion: 0.33
Nodes (6): StatusTier, Error, Ok, Red, Unverified, Warning

### Community 28 - "EventCatalog"
Cohesion: 0.23
Nodes (8): Color, Dictionary, EventCatalog, Severity, Critical, Good, Info, Warning

### Community 29 - "ProcessPolicy"
Cohesion: 0.24
Nodes (7): HashSet, IEnumerable, ProcessDecision, Allowed, Blocked, Unknown, ProcessPolicy

### Community 30 - "ExamLogVerifierUI"
Cohesion: 0.22
Nodes (3): ExamLogVerifierUI, STAThread, Program

### Community 31 - "DnsCacheMonitor"
Cohesion: 0.31
Nodes (3): HashSet, Timer, DnsCacheMonitor

### Community 32 - "ProcessMonitor"
Cohesion: 0.28
Nodes (5): HashSet, Timer, ProcessMonitor, Name, Pid

### Community 33 - "Extraction Subagent Prompt"
Cohesion: 0.28
Nodes (9): Confidence Rubric, Deep Mode, Extraction Subagent Prompt, File Type Taxonomy, Hyperedges, JSON Schema, Node ID Format, Semantic Similarity Edges (+1 more)

### Community 34 - "Export Flags"
Cohesion: 0.25
Nodes (8): Wiki Navigation, Export Flags, FalkorDB Export, Neo4j Export, Token Reduction Benchmark, Visual Exports, Wiki Export, HTML Export

### Community 36 - "LogVerificationResult"
Cohesion: 0.12
Nodes (17): IReadOnlyList, LogIntegrity, Empty, Ok, Tampered, LogVerificationResult, Entries, Error (+9 more)

### Community 39 - "Cross Repo Merge"
Cohesion: 0.33
Nodes (6): MCP Server, Cross Repo Merge, GitHub Clone, Monorepo Subfolder Flow, Reusable Clones, GraphRAG JSON

### Community 42 - "/graphify"
Cohesion: 0.18
Nodes (10): Project Graphify Instructions, CLAUDE.md Integration, For /graphify add and --watch, For /graphify query, For the commit hook and native CLAUDE.md integration, For --update and --cluster-only, /graphify, Interpreter guard for subcommands (+2 more)

### Community 46 - "TcpConnectionOwner"
Cohesion: 0.09
Nodes (26): DllImport, IntPtr, IPAddress, List, MibTcp6RowOwnerPid, MibTcpRowOwnerPid, TcpConnectionOwner, ProcessId (+18 more)

### Community 47 - "What You Must Do When Invoked"
Cohesion: 0.14
Nodes (14): Part A - Structural extraction for code files, Part B - Semantic extraction (parallel subagents), Part C - Merge AST + semantic into final extraction, Step 0 - GitHub repos and multi-path merge (only if a URL or several paths), Step 1 - Ensure graphify is installed, Step 2.5 - Video and audio (only if video files detected), Step 2 - Detect files, Step 3 - Extract entities and relationships (+6 more)

### Community 48 - "Català"
Cohesion: 0.14
Nodes (14): App de l'alumne — ExamLockClient, App del professor — ExamConfigGenerator, Català, Com funciona, Compilació, Executar, Fitxers en temps d'execució, La detecció d'IA és una xarxa de seguretat (+6 more)

### Community 49 - "Castellano"
Cohesion: 0.14
Nodes (14): App del alumno — ExamLockClient, App del profesor — ExamConfigGenerator, Archivos en tiempo de ejecución, Build, Castellano, Cómo funciona, Ejecutar, La detección de IA es una red de seguridad (+6 more)

### Community 53 - "graphify reference: extra exports and benchmark"
Cohesion: 0.22
Nodes (8): graphify reference: extra exports and benchmark, Step 6b - Wiki (only if --wiki flag), Step 7 - Neo4j export (only if --neo4j or --neo4j-push flag), Step 7a - FalkorDB export (only if --falkordb or --falkordb-push flag), Step 7b - SVG export (only if --svg flag), Step 7c - GraphML export (only if --graphml flag), Step 7d - MCP server (only if --mcp flag), Step 8 - Token reduction benchmark (only if total_words > 5000)

### Community 56 - "graphify reference: query, path, explain"
Cohesion: 0.33
Nodes (5): For /graphify explain, For /graphify path, graphify reference: query, path, explain, Step 0 — Constrained query expansion (REQUIRED before traversal), Step 1 — Traversal

### Community 57 - "graphify reference: add a URL and watch a folder"
Cohesion: 0.50
Nodes (3): For /graphify add, For --watch, graphify reference: add a URL and watch a folder

### Community 58 - "graphify reference: commit hook and native CLAUDE.md integration"
Cohesion: 0.50
Nodes (3): For git commit hook, For native CLAUDE.md integration, graphify reference: commit hook and native CLAUDE.md integration

### Community 59 - "graphify reference: incremental update and cluster-only"
Cohesion: 0.50
Nodes (3): For --cluster-only, For --update (incremental re-extraction), graphify reference: incremental update and cluster-only

## Knowledge Gaps
- **292 isolated node(s):** `net8.0-windows`, `Microsoft.NET.Sdk`, `En`, `Ca`, `Es` (+287 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 425 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MainForm` connect `MainForm` to `ProcessMonitor`, `MonitorReporter`, `AudioAlerter`, `MainForm`, `FileActivityMonitor`, `ShieldControl`, `ConfigPayload`, `AiConnectionEvidence`, `ExamShared`, `LogEntry`, `.InitializeServices`, `DnsCacheMonitor`?**
  _High betweenness centrality (0.238) - this node is a cross-community bridge._
- **Why does `ExamShared` connect `ExamShared` to `MonitorReporter`, `.DocumentArguments`, `LogVerificationResult`, `Shared.cs`, `MainForm`, `Lang`, `ProcessPolicy`, `ExamLogVerifierUI`?**
  _High betweenness centrality (0.102) - this node is a cross-community bridge._
- **Why does `MainForm` connect `MainForm` to `StatusTier`, `MainForm`, `ExamLogVerifierUI`?**
  _High betweenness centrality (0.095) - this node is a cross-community bridge._
- **What connects `net8.0-windows`, `Microsoft.NET.Sdk`, `En` to the rest of the system?**
  _292 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `MainForm` be split into smaller, more focused modules?**
  _Cohesion score 0.05422838031533684 - nodes in this community are weakly interconnected._
- **Should `MainForm` be split into smaller, more focused modules?**
  _Cohesion score 0.06322624743677376 - nodes in this community are weakly interconnected._
- **Should `MonitorReporter` be split into smaller, more focused modules?**
  _Cohesion score 0.05612244897959184 - nodes in this community are weakly interconnected._