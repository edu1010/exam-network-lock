# Graph Report - linux  (2026-09-08)

## Corpus Check
- 92 files · ~59,289 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1967 nodes · 3544 edges · 118 communities (96 shown, 22 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 114 edges (avg confidence: 0.82)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4a48df6d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- MainForm
- MainForm
- MonitorProtocol
- AudioAlerter
- .StartMonitors
- Shared.cs
- MainForm
- Exam Network Locking
- FileActivityMonitor
- Dominios/IPs considerados IA
- ExamShared.csproj
- Full Pipeline
- Query Workflow
- Incremental Update
- ShieldControl
- Escudo de examen Client Window
- T
- AiConnectionMonitor
- ProcessMonitor
- Bitmap
- Generador de configuración de examen
- Student edu10@EDU
- Bitmap
- Lang
- WindowsPlatform
- Theme
- MainForm
- Padding
- Bitmap
- LinuxPlatform
- .SetStatus
- Lang
- MainForm
- Extraction Subagent Prompt
- Export Flags
- ConfigPayload
- LogVerificationResult
- MainForm
- What You Must Do When Invoked
- Cross Repo Merge
- MainWindow
- ExamLockClient.Core.Platform
- /graphify
- Program
- ProcessTestPlatform
- FileActivityMonitor
- TcpConnectionOwner
- What You Must Do When Invoked
- Català
- Castellano
- AiProcessClassifier
- AiProcessClassifier
- ThreatProcessMonitor
- graphify reference: extra exports and benchmark
- DnsCacheMonitor
- IPlatform
- graphify reference: query, path, explain
- graphify reference: add a URL and watch a folder
- graphify reference: commit hook and native CLAUDE.md integration
- graphify reference: incremental update and cluster-only
- graphify reference: GitHub clone and cross-repo merge
- graphify reference: transcribe video and audio
- AGENTS.md
- .codex/skills/graphify/references/extraction-spec.md
- ExamConfigGenerator
- .AttemptAdminClose
- AiConnectionMonitor
- English
- AiConnectionEvidence
- AiConnectionMonitor
- AiConnectionEvidence
- ThreatProcessMonitor
- IDisposable
- ConfigEnvelope
- MonitorBroadcaster
- Bitmap
- DnsCacheMonitor
- Monitoring.cs
- MonitorReporter
- Color
- SecureLogService
- graphify reference: extra exports and benchmark
- MonitorReporter
- ConfigSerializer
- SecureLogService
- AudioAlerter
- ProcessPolicy
- StatusMessage
- graphify reference: query, path, explain
- .SetBluetoothAsync
- .ScanPaths
- StatusTier
- .Verify
- .BuildControlsCard
- graphify reference: add a URL and watch a folder
- graphify reference: commit hook and native CLAUDE.md integration
- graphify reference: incremental update and cluster-only
- Revisión del port Linux
- DragEventArgs
- ProcessMonitor
- graphify reference: GitHub clone and cross-repo merge
- graphify reference: transcribe video and audio
- .VerifyHmac
- PasswordHasher
- linux/.codex/skills/graphify/references/extraction-spec.md
- publish-linux.sh
- ExamShared
- TcpConnectionInfo
- Program
- ProcessMonitor
- ExamConfigGenerator/Program.cs
- .Get
- LogEntry
- process-rules.md
- NetworkAdapterService
- NetworkAdapterService
- ConfigIntegrityService
- folder-monitoring.md

## God Nodes (most connected - your core abstractions)
1. `MainForm` - 62 edges
2. `MainWindow` - 61 edges
3. `MainForm` - 61 edges
4. `MainForm` - 60 edges
5. `MainForm` - 56 edges
6. `MainForm` - 44 edges
7. `MainForm` - 39 edges
8. `ConfigPayload` - 33 edges
9. `WindowsPlatform` - 29 edges
10. `LinuxPlatform` - 28 edges

## Surprising Connections (you probably didn't know these)
- `Query First Rule` --semantically_similar_to--> `Existing Graph Fast Path`  [INFERRED] [semantically similar]
  AGENTS.md → .codex/skills/graphify/SKILL.md
- `CLAUDE.md Integration` --semantically_similar_to--> `Project Graphify Instructions`  [INFERRED] [semantically similar]
  .codex/skills/graphify/references/hooks.md → AGENTS.md
- `Deterrent System With Evidence` --rationale_for--> `Exam Network Locking`  [EXTRACTED]
  README.md → .worktrees/linux/README.md
- `Exam Network Locking` --references--> `ExamConfigGenerator`  [EXTRACTED]
  .worktrees/linux/README.md → README.md
- `Exam Network Locking` --references--> `ExamLockClient`  [EXTRACTED]
  .worktrees/linux/README.md → README.md

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

## Communities (118 total, 22 thin omitted)

### Community 0 - "MainForm"
Cohesion: 0.12
Nodes (13): bool, byte, ComboBox, Control, DataGridView, int, List, string (+5 more)

### Community 1 - "MainForm"
Cohesion: 0.06
Nodes (25): AiConnectionMonitor, AudioAlerter, ConfigPayload, DnsCacheMonitor, Action, AiConnectionEvidence, bool, Control (+17 more)

### Community 2 - "MonitorProtocol"
Cohesion: 0.17
Nodes (5): int, JsonSerializerOptions, T, MonitorProtocol, MonitorProtocol

### Community 3 - "AudioAlerter"
Cohesion: 0.05
Nodes (25): AudioAlerter, bool, byte, DllImport, Guid, IMMDevice, int, IntPtr (+17 more)

### Community 4 - ".StartMonitors"
Cohesion: 0.18
Nodes (5): AiConnectionMonitor, DnsCacheMonitor, FileActivityMonitor, ProcessMonitor, ThreatProcessMonitor

### Community 5 - "Shared.cs"
Cohesion: 0.16
Nodes (11): BeepModes, ConfigDefaults, string, BeepModes, ConfigDefaults, LogEvents, WorkFolderModes, WorkFolderResolver (+3 more)

### Community 6 - "MainForm"
Cohesion: 0.07
Nodes (21): ClientRow, DateTime, ClientRow, Action, Button, Color, Control, DataGridView (+13 more)

### Community 7 - "Exam Network Locking"
Cohesion: 0.19
Nodes (15): Deterrent System With Evidence, exam.config, Exam Network Locking, ExamLogVerifier, ExamLogVerifierUI, ExamMonitor, ExamShared, File Monitoring (+7 more)

### Community 8 - "FileActivityMonitor"
Cohesion: 0.09
Nodes (10): bool, FileSystemWatcher, HashSet, IEnumerable, object, string, Timer, FileActivityMonitor (+2 more)

### Community 9 - "Dominios/IPs considerados IA"
Cohesion: 0.11
Nodes (21): Contraseña B - Cerrar / Admin, Subir volumen y pitar al detectar IA, Dominios/IPs considerados IA, anthropic.com, Escudo anti-IA, bard.google.com, chatgpt.com, claude.ai (+13 more)

### Community 10 - "ExamShared.csproj"
Cohesion: 0.06
Nodes (33): ExamConfigGenerator, net8.0-windows, Microsoft.NET.Sdk, ExamLockClient.App, net8.0, Microsoft.NET.Sdk, net8.0, System.Management (8.0.0) (+25 more)

### Community 11 - "Full Pipeline"
Cohesion: 0.12
Nodes (18): Graph Report Fallback, Transcript Docs, Video Audio Transcription, Whisper Model, Whisper Prompt Strategy, Cluster Only, Community Labeling, File Detection (+10 more)

### Community 12 - "Query Workflow"
Cohesion: 0.18
Nodes (13): Dirty Graph Tolerance, Query First Rule, BFS Traversal, Constrained Query Expansion, DFS Traversal, Graph Vocabulary, NetworkX Fallback, Node Explanation (+5 more)

### Community 13 - "Incremental Update"
Cohesion: 0.19
Nodes (14): Update After Modifying Code, Code Only AST Update, Docs Need Update Flag, Watch Mode, Doc Image Manual Update, Post Commit Hook, Build Merge Pruning, Code Only Shortcut (+6 more)

### Community 14 - "ShieldControl"
Cohesion: 0.06
Nodes (31): color, Control, DrawingContext, Color, glyph, ShieldControl, Caption, Status (+23 more)

### Community 15 - "Escudo de examen Client Window"
Cohesion: 0.20
Nodes (14): Examen en curso Message, Contraseña B cerrar Input, Cerrar programa Button, Config Path Display, ExamLockClient Debug Build Path, Escudo de examen Client Window, Green Shield Check Icon, Incidencias Log (+6 more)

### Community 17 - "AiConnectionMonitor"
Cohesion: 0.33
Nodes (4): AiConnectionMonitor, IPAddress, object, string

### Community 18 - "ProcessMonitor"
Cohesion: 0.28
Nodes (5): HashSet, Pid, Timer, ProcessMonitor, Name

### Community 19 - "Bitmap"
Cohesion: 0.05
Nodes (31): ExamLogVerifierUI, Color, Dictionary, string, EventCatalog, EventCatalog, Severity, Critical (+23 more)

### Community 20 - "Generador de configuración de examen"
Cohesion: 0.21
Nodes (12): Añadir and Quitar controls, Ejecutables permitidos, Extensiones permitidas, Allowed site bard.google.com, Base folder where exam.config is located, Examinar subfolder button, Vacío = sin restricción, Generador de configuración de examen (+4 more)

### Community 21 - "Student edu10@EDU"
Cohesion: 0.18
Nodes (12): Event Count 7, Exam In Progress Event, Monitor de examen Window, Exam Status OK, Integrity OK, exam.config Loaded Integrity Verification Message, Language Selector Flags, Last Seen hace 2s (+4 more)

### Community 22 - "Bitmap"
Cohesion: 0.06
Nodes (25): ExamConfigGenerator, Bitmap, Graphics, int, Language, Flags, Flags, Dictionary (+17 more)

### Community 23 - "Lang"
Cohesion: 0.16
Nodes (10): Dictionary, Language, Lang, Current, FilePath, Language, Ca, En (+2 more)

### Community 24 - "WindowsPlatform"
Cohesion: 0.05
Nodes (26): ProcessNames, DllImport, error, Guid, IEnumerable, IMMDevice, IntPtr, IReadOnlyList (+18 more)

### Community 25 - "Theme"
Cohesion: 0.18
Nodes (7): Button, Color, Font, TextBox, Theme, Theme, Panel

### Community 26 - "MainForm"
Cohesion: 0.12
Nodes (7): ctrl, key, Label, MainForm, Func, LogItem, SplitContainer

### Community 27 - "Padding"
Cohesion: 0.16
Nodes (9): Button, Button, Color, ComboBox, DataGridView, Font, Theme, Theme (+1 more)

### Community 28 - "Bitmap"
Cohesion: 0.06
Nodes (25): ExamMonitor, Bitmap, Graphics, int, Language, Flags, Flags, Dictionary (+17 more)

### Community 29 - "LinuxPlatform"
Cohesion: 0.09
Nodes (13): Dictionary, DllImport, error, IEnumerable, IPAddress, IReadOnlyList, List, ok (+5 more)

### Community 31 - "Lang"
Cohesion: 0.08
Nodes (19): AppBuilder, Application, ExamLockClient.App, ExamLockClient.App.Views, App, Dictionary, Lang, Current (+11 more)

### Community 32 - "MainForm"
Cohesion: 0.06
Nodes (20): CheckBox, control, Button, ComboBox, Control, ctrl, GroupBox, int (+12 more)

### Community 33 - "Extraction Subagent Prompt"
Cohesion: 0.28
Nodes (9): Confidence Rubric, Deep Mode, Extraction Subagent Prompt, File Type Taxonomy, Hyperedges, JSON Schema, Node ID Format, Semantic Similarity Edges (+1 more)

### Community 34 - "Export Flags"
Cohesion: 0.25
Nodes (8): Wiki Navigation, Export Flags, FalkorDB Export, Neo4j Export, Token Reduction Benchmark, Visual Exports, Wiki Export, HTML Export

### Community 35 - "ConfigPayload"
Cohesion: 0.07
Nodes (27): ConfigPayload, AdminPasswordHashBase64, AdminSaltBase64, AiBlocklist, AiShieldEnabled, AlarmVolumePercent, AllowedFileExtensions, AllowedProcesses (+19 more)

### Community 36 - "LogVerificationResult"
Cohesion: 0.10
Nodes (20): IReadOnlyList, LogIntegrity, Empty, Ok, Tampered, LogVerificationResult, Entries, Error (+12 more)

### Community 37 - "MainForm"
Cohesion: 0.19
Nodes (5): EventArgs, Button, List, ToolTip, MainForm

### Community 38 - "What You Must Do When Invoked"
Cohesion: 0.08
Nodes (23): For /graphify add and --watch, For /graphify query, For the commit hook and native CLAUDE.md integration, For --update and --cluster-only, /graphify, Honesty Rules, Interpreter guard for subcommands, Part A - Structural extraction for code files (+15 more)

### Community 39 - "Cross Repo Merge"
Cohesion: 0.33
Nodes (6): MCP Server, Cross Repo Merge, GitHub Clone, Monorepo Subfolder Flow, Reusable Clones, GraphRAG JSON

### Community 40 - "MainWindow"
Cohesion: 0.15
Nodes (12): Action, AiConnectionMonitor, DnsCacheMonitor, FileActivityMonitor, HashSet, ProcessMonitor, TextBox, ThreatProcessMonitor (+4 more)

### Community 41 - "ExamLockClient.Core.Platform"
Cohesion: 0.15
Nodes (7): ExamLockClient.Core.Platform, ExamLockClient.App.Controls, ExamLockClient.Core.Monitoring, BeepPattern, Continuous, ThreeBeeps, Shell

### Community 42 - "/graphify"
Cohesion: 0.15
Nodes (12): Project Graphify Instructions, Supported URL Types, URL Ingest, CLAUDE.md Integration, For /graphify add and --watch, For /graphify query, For the commit hook and native CLAUDE.md integration, For --update and --cluster-only (+4 more)

### Community 43 - "Program"
Cohesion: 0.18
Nodes (5): STAThread, Program, StartupConfigPath, Program, IWin32Window

### Community 44 - "ProcessTestPlatform"
Cohesion: 0.13
Nodes (10): ProcessInfo, Summary, error, IEnumerable, IReadOnlyList, ok, Task, ProcessTestPlatform (+2 more)

### Community 45 - "FileActivityMonitor"
Cohesion: 0.12
Nodes (7): FileSystemWatcher, HashSet, IEnumerable, Timer, FileActivityMonitor, IEnumerable, FileActivityNoiseFilter

### Community 46 - "TcpConnectionOwner"
Cohesion: 0.09
Nodes (29): DllImport, int, IntPtr, IPAddress, List, TcpState, uint, MibTcp6RowOwnerPid (+21 more)

### Community 47 - "What You Must Do When Invoked"
Cohesion: 0.14
Nodes (14): Part A - Structural extraction for code files, Part B - Semantic extraction (parallel subagents), Part C - Merge AST + semantic into final extraction, Step 0 - GitHub repos and multi-path merge (only if a URL or several paths), Step 1 - Ensure graphify is installed, Step 2.5 - Video and audio (only if video files detected), Step 2 - Detect files, Step 3 - Extract entities and relationships (+6 more)

### Community 48 - "Català"
Cohesion: 0.13
Nodes (15): App de l'alumne — ExamLockClient, App del professor — ExamConfigGenerator, Català, Com funciona, Compilació, Executar, Fitxers en temps d'execució, La detecció d'IA és una xarxa de seguretat (+7 more)

### Community 49 - "Castellano"
Cohesion: 0.12
Nodes (16): App del alumno — ExamLockClient, App del profesor — ExamConfigGenerator, Archivos en tiempo de ejecución, Build, Build, Castellano, Cómo funciona, Ejecutar (+8 more)

### Community 50 - "AiProcessClassifier"
Cohesion: 0.21
Nodes (4): AiConnectionEvidence, AiProcessClassifier, string, ProcessEvidence

### Community 51 - "AiProcessClassifier"
Cohesion: 0.18
Nodes (9): HashSet, Process, AiProcessClassifier, ProcessEvidence, CommandLine, ProcessId, ProcessName, ProcessPath (+1 more)

### Community 52 - "ThreatProcessMonitor"
Cohesion: 0.17
Nodes (7): bool, HashSet, object, Process, Timer, ThreatProcessMonitor, ThreatProcessMonitor

### Community 53 - "graphify reference: extra exports and benchmark"
Cohesion: 0.22
Nodes (8): graphify reference: extra exports and benchmark, Step 6b - Wiki (only if --wiki flag), Step 7 - Neo4j export (only if --neo4j or --neo4j-push flag), Step 7a - FalkorDB export (only if --falkordb or --falkordb-push flag), Step 7b - SVG export (only if --svg flag), Step 7c - GraphML export (only if --graphml flag), Step 7d - MCP server (only if --mcp flag), Step 8 - Token reduction benchmark (only if total_words > 5000)

### Community 54 - "DnsCacheMonitor"
Cohesion: 0.19
Nodes (5): HashSet, string, Timer, DnsCacheMonitor, DnsCacheMonitor

### Community 55 - "IPlatform"
Cohesion: 0.13
Nodes (10): Thread, AudioAlerter, Pattern, VolumePercent, IReadOnlyList, IPlatform, IsElevated, Name (+2 more)

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

### Community 64 - "ExamConfigGenerator"
Cohesion: 0.22
Nodes (15): Admin Permissions, AI Detection Safety Net, AI Shield, Allowed File Types, Allowed Programs, Blocked File Types, DNS Cache Monitoring, ExamConfigGenerator (+7 more)

### Community 65 - ".AttemptAdminClose"
Cohesion: 0.15
Nodes (5): error, ok, Task, PasswordHasher, WindowClosingEventArgs

### Community 66 - "AiConnectionMonitor"
Cohesion: 0.29
Nodes (5): AiConnectionEvidence, HashSet, IPAddress, Timer, AiConnectionMonitor

### Community 67 - "English"
Cohesion: 0.14
Nodes (14): AI detection is a safety net, Build, English, File monitoring is a deterrent, How it works, Linux / cross-platform client — ExamLockClient.App, Notes, Permissions (+6 more)

### Community 68 - "AiConnectionEvidence"
Cohesion: 0.15
Nodes (12): IPAddress, AiConnectionEvidence, CommandLine, DedupKey, Destination, IsStudentFacingProcess, ProcessId, ProcessName (+4 more)

### Community 69 - "AiConnectionMonitor"
Cohesion: 0.26
Nodes (4): AiConnectionEvidence, HashSet, Timer, AiConnectionMonitor

### Community 70 - "AiConnectionEvidence"
Cohesion: 0.15
Nodes (12): IPAddress, AiConnectionEvidence, CommandLine, DedupKey, Destination, IsStudentFacingProcess, ProcessId, ProcessName (+4 more)

### Community 71 - "ThreatProcessMonitor"
Cohesion: 0.18
Nodes (5): HashSet, AiProcessClassifier, HashSet, Timer, ThreatProcessMonitor

### Community 72 - "IDisposable"
Cohesion: 0.19
Nodes (6): bool, Task, MonitorListener, MonitorListener, IDisposable, UdpClient

### Community 73 - "ConfigEnvelope"
Cohesion: 0.33
Nodes (5): JsonSerializerOptions, ConfigEnvelope, HmacBase64, Payload, ConfigSerializer

### Community 74 - "MonitorBroadcaster"
Cohesion: 0.33
Nodes (6): IEnumerable, IPAddress, MonitorBroadcaster, MonitorBroadcaster, IPEndPoint, UnicastIPAddressInformation

### Community 75 - "Bitmap"
Cohesion: 0.30
Nodes (6): Bitmap, Graphics, int, Language, Flags, Flags

### Community 76 - "DnsCacheMonitor"
Cohesion: 0.24
Nodes (4): HashSet, Timer, DnsCacheMonitor, IEnumerable

### Community 77 - "Monitoring.cs"
Cohesion: 0.25
Nodes (7): LogChunkMessage, Entries, Kind, Machine, User, LogChunkMessage, StatusMessage

### Community 78 - "MonitorReporter"
Cohesion: 0.15
Nodes (8): int, List, LogEntry, string, Timer, MonitorReporter, MonitorReporter, MonitorBroadcaster

### Community 79 - "Color"
Cohesion: 0.31
Nodes (4): Color, HashSet, LogItem, StatusTier

### Community 80 - "SecureLogService"
Cohesion: 0.24
Nodes (4): MonitorReporter, MonitorReporter, SecureLogService, SessionStateService

### Community 81 - "graphify reference: extra exports and benchmark"
Cohesion: 0.22
Nodes (8): graphify reference: extra exports and benchmark, Step 6b - Wiki (only if --wiki flag), Step 7 - Neo4j export (only if --neo4j or --neo4j-push flag), Step 7a - FalkorDB export (only if --falkordb or --falkordb-push flag), Step 7b - SVG export (only if --svg flag), Step 7c - GraphML export (only if --graphml flag), Step 7d - MCP server (only if --mcp flag), Step 8 - Token reduction benchmark (only if total_words > 5000)

### Community 82 - "MonitorReporter"
Cohesion: 0.22
Nodes (3): List, Timer, MonitorReporter

### Community 83 - "ConfigSerializer"
Cohesion: 0.29
Nodes (4): ConfigEnvelope, ConfigPayload, ConfigSerializer, WorkFolderResolver

### Community 84 - "SecureLogService"
Cohesion: 0.33
Nodes (3): int, LogEntry, SecureLogService

### Community 85 - "AudioAlerter"
Cohesion: 0.24
Nodes (6): Thread, AudioAlerter, Pattern, VolumePercent, IMMDevice, MMDeviceEnumerator

### Community 86 - "ProcessPolicy"
Cohesion: 0.24
Nodes (7): HashSet, IEnumerable, ProcessDecision, Allowed, Blocked, Unknown, ProcessPolicy

### Community 87 - "StatusMessage"
Cohesion: 0.25
Nodes (8): StatusMessage, Kind, LogCount, Machine, State, StatusText, Timestamp, User

### Community 88 - "graphify reference: query, path, explain"
Cohesion: 0.33
Nodes (5): For /graphify explain, For /graphify path, graphify reference: query, path, explain, Step 0 — Constrained query expansion (REQUIRED before traversal), Step 1 — Traversal

### Community 89 - ".SetBluetoothAsync"
Cohesion: 0.22
Nodes (7): error, error, ok, Task, RadioService, RadioService, ok

### Community 90 - ".ScanPaths"
Cohesion: 0.33
Nodes (3): IEnumerable, ScanResult, ScanResult

### Community 91 - "StatusTier"
Cohesion: 0.33
Nodes (6): StatusTier, Error, Ok, Red, Unverified, Warning

### Community 92 - ".Verify"
Cohesion: 0.47
Nodes (3): LogEntry, LogChainVerifier, IReadOnlyList

### Community 93 - ".BuildControlsCard"
Cohesion: 0.33
Nodes (3): Border, Button, Control

### Community 94 - "graphify reference: add a URL and watch a folder"
Cohesion: 0.50
Nodes (3): For /graphify add, For --watch, graphify reference: add a URL and watch a folder

### Community 95 - "graphify reference: commit hook and native CLAUDE.md integration"
Cohesion: 0.50
Nodes (3): For git commit hook, For native CLAUDE.md integration, graphify reference: commit hook and native CLAUDE.md integration

### Community 96 - "graphify reference: incremental update and cluster-only"
Cohesion: 0.50
Nodes (3): For --cluster-only, For --update (incremental re-extraction), graphify reference: incremental update and cluster-only

### Community 97 - "Revisión del port Linux"
Cohesion: 0.50
Nodes (3): Comprobaciones reproducibles, Diferencias de plataforma, Revisión del port Linux

### Community 99 - "ProcessMonitor"
Cohesion: 0.24
Nodes (5): HashSet, Name, Pid, Timer, ProcessMonitor

### Community 107 - "TcpConnectionInfo"
Cohesion: 0.25
Nodes (5): IPAddress, List, TcpState, TcpConnectionInfo, List

### Community 110 - "ExamConfigGenerator/Program.cs"
Cohesion: 0.40
Nodes (3): STAThread, Program, Program

### Community 112 - "LogEntry"
Cohesion: 0.20
Nodes (9): IReadOnlyList, LogChainVerifier, LogEntry, EventData, EventType, HmacBase64, PrevHmacBase64, Sequence (+1 more)

## Knowledge Gaps
- **462 isolated node(s):** `net8.0-windows`, `Microsoft.NET.Sdk`, `En`, `Ca`, `Es` (+457 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 634 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **22 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MainForm` connect `MainForm` to `MainForm`, `ConfigPayload`, `.StartMonitors`, `AiConnectionMonitor`, `MainForm`, `FileActivityMonitor`, `ExamShared`, `Program`, `MonitorReporter`, `ShieldControl`, `SecureLogService`, `ProcessMonitor`, `NetworkAdapterService`, `ThreatProcessMonitor`, `AudioAlerter`, `DnsCacheMonitor`, `.SetBluetoothAsync`?**
  _High betweenness centrality (0.182) - this node is a cross-community bridge._
- **Why does `MainWindow` connect `MainWindow` to `.AttemptAdminClose`, `AiConnectionMonitor`, `ProcessMonitor`, `ConfigPayload`, `ThreatProcessMonitor`, `ExamLockClient.Core.Platform`, `DnsCacheMonitor`, `FileActivityMonitor`, `ShieldControl`, `.Get`, `SecureLogService`, `MonitorReporter`, `IPlatform`, `.BuildControlsCard`, `.SetStatus`, `Lang`?**
  _High betweenness centrality (0.155) - this node is a cross-community bridge._
- **Why does `ExamShared` connect `ExamShared` to `MainForm`, `ProcessMonitor`, `LogVerificationResult`, `Shared.cs`, `MainForm`, `ExamLockClient.Core.Platform`, `Program`, `FileActivityMonitor`, `ExamConfigGenerator/Program.cs`, `MonitorReporter`, `Monitoring.cs`, `.Get`, `MonitorReporter`, `Bitmap`, `Bitmap`, `ProcessPolicy`?**
  _High betweenness centrality (0.153) - this node is a cross-community bridge._
- **What connects `net8.0-windows`, `Microsoft.NET.Sdk`, `En` to the rest of the system?**
  _462 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `MainForm` be split into smaller, more focused modules?**
  _Cohesion score 0.11561561561561562 - nodes in this community are weakly interconnected._
- **Should `MainForm` be split into smaller, more focused modules?**
  _Cohesion score 0.06349206349206349 - nodes in this community are weakly interconnected._
- **Should `AudioAlerter` be split into smaller, more focused modules?**
  _Cohesion score 0.053821800090456805 - nodes in this community are weakly interconnected._