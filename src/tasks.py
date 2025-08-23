import os
import subprocess
import time
import logging
from collections import deque

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.logging import Logger
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery
from celery import signals

TASK_NAME = "openrelik-worker-amcache-evilhunter.tasks.amcache-evilhunter"

TASK_METADATA = {
    "display_name": "AmCache-EvilHunter",
    "description": "OpenRelik worker that runs AmCache-EvilHunter to parse Windows Amcache.hve.",
    "task_config": [
        {"name": "VT Enable",           "label": "Enable VT",              "description": "Enable VirusTotal lookups (requires VT_API_KEY).",           "type": "checkbox", "required": False},
        {"name": "OpenTIP Enable",      "label": "Enable OpenTIP",         "description": "Enable Kaspersky OpenTIP (requires OPENTIP_API_KEY).",      "type": "checkbox", "required": False},
        {"name": "start",               "label": "Start (YYYY-MM-DD)",     "description": "Only records on or after this date.",                        "type": "text",     "required": False},
        {"name": "end",                 "label": "End (YYYY-MM-DD)",       "description": "Only records on or before this date.",                        "type": "text",     "required": False},
        {"name": "search",              "label": "Search terms",           "description": "Comma-separated, case-insensitive.",                          "type": "text",     "required": False},
        {"name": "find_suspicious",     "label": "Find suspicious",        "description": "Filter by suspicious name patterns.",                          "type": "checkbox", "required": False},
        {"name": "missing_publisher",   "label": "Missing publisher",      "description": "Only records with missing Publisher.",                         "type": "checkbox", "required": False},
        {"name": "exclude_os",          "label": "Exclude OS components",  "description": "Only non-OS component files.",                                 "type": "checkbox", "required": False},
        {"name": "only_detections",     "label": "Only detections (≥1)",   "description": "Show/save only files with ≥1 detection. (requires VT_API_KEY)",     "type": "checkbox", "required": False},
    ],
}

log = Logger()
logger = log.get_logger(__name__)


@signals.task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **_):
    # Bind contextual fields to the logger for better correlation
    log.bind(task_id=task_id, task_name=task.name,
             worker_name=TASK_METADATA.get("display_name"))


def _pathify(x):
    """Return a filesystem path string from dict/obj/PathLike/str."""
    if isinstance(x, dict):
        x = x.get("path") or x.get("name")
    elif hasattr(x, "path"):
        x = x.path
    elif hasattr(x, "name"):
        x = x.name
    return os.fspath(x)  # type: ignore


def _cfg_bool(cfg: dict | None, key: str, env_var: str | None = None) -> bool:
    """True if task_config[key] is truthy or env_var is set to 1/true/yes/on."""
    v = bool(cfg.get(key)) if isinstance(cfg, dict) else False
    if not v and env_var:
        v = str(os.getenv(env_var, "")).lower() in ("1", "true", "yes", "on")
    return v


def _cfg_str(cfg: dict | None, key: str) -> str | None:
    """Normalized string value from task_config[key] or None."""
    if not isinstance(cfg, dict):
        return None
    val = cfg.get(key)
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _apply_flags_from_config(cmd: list[str], cfg: dict | None) -> None:
    """Append CLI flags based on task_config and env."""
    # VT / OpenTIP
    if _cfg_bool(cfg, "VT Enable", "VT_API_KEY"):
        cmd.append("--vt")
    if _cfg_bool(cfg, "OpenTIP Enable", "OPENTIP_API_KEY"):
        cmd.append("--opentip")
    # Booleans
    if _cfg_bool(cfg, "find_suspicious"):
        cmd.append("--find-suspicious")
    if _cfg_bool(cfg, "missing_publisher"):
        cmd.append("--missing-publisher")
    if _cfg_bool(cfg, "exclude_os"):
        cmd.append("--exclude-os")
    if _cfg_bool(cfg, "only_detections"):
        cmd.append("--only-detections")
    # Values
    start = _cfg_str(cfg, "start")
    if start:
        cmd += ["--start", start]
    end = _cfg_str(cfg, "end")
    if end:
        cmd += ["--end", end]
    search = _cfg_str(cfg, "search")
    if search:
        cmd += ["--search", search]


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str = None,   # type: ignore
    input_files: list = None,  # type: ignore
    output_path: str = None,   # type: ignore
    workflow_id: str = None,   # type: ignore
    task_config: dict = None,  # type: ignore
) -> str:
    """Run AmCache-EvilHunter on input files."""
    log.bind(workflow_id=workflow_id)
    logger.debug(f"Starting {TASK_NAME} for {workflow_id}")

    # Resolve inputs from previous task or provided list
    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []
    executed_cmds = []

    # Pick only the hive; LOG1/LOG2 must be in the same directory for replay
    hve_items = [it for it in input_files if str(_pathify(it)).lower().endswith(".hve")]
    if not hve_items:
        raise RuntimeError("No Amcache.hve provided among input_files")

    for item in hve_items:
        hve_path = _pathify(item)
        work_dir = os.path.dirname(hve_path) or "."

        # Robust display name for output artifacts
        display_name = item.get("display_name") if isinstance(item, dict) else None
        if not display_name:
            display_name = os.path.basename(hve_path)

        # Prepare output artifacts (JSON, CSV, raw stdout)
        output_file_json = create_output_file(
            output_path,
            display_name=f"{display_name}_RESULT.json",
            data_type="openrelik:worker:amcache-evilhunter:json_result",
        )
        output_file_csv = create_output_file(
            output_path,
            display_name=f"{display_name}_RESULT.csv",
            data_type="openrelik:worker:amcache-evilhunter:csv_result",
        )
        output_file_stdout = create_output_file(
            output_path,
            display_name=f"{display_name}_RESULT.txt",
            data_type="openrelik:worker:amcache-evilhunter:stdout_result",
        )

        # Build CLI
        cmd = [
            "amcache-evilhunter",
            "--json", str(_pathify(output_file_json)),
            "--csv",  str(_pathify(output_file_csv)),
            "-i",     str(hve_path),
        ]
        _apply_flags_from_config(cmd, task_config)

        logger.debug("AmCache-EvilHunter")
        logger.debug(f"Command: {' '.join(cmd)}; cwd={work_dir}")
        executed_cmds.append(" ".join(cmd))

        # Execute with stdout streaming to file and periodic progress events
        progress_update_interval_in_s = 2
        last_tick = 0.0
        tail = deque(maxlen=80)  # keep last N lines for error context

        with open(_pathify(output_file_stdout), "w", encoding="utf-8", errors="replace") as fh:
            with subprocess.Popen(
                cmd,
                cwd=work_dir,                      # ensures LOG1/LOG2 are discoverable
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            ) as proc:
                logger.debug("Waiting for AmCache-EvilHunter to finish")
                while proc.poll() is None:
                    self.send_event("task-progress", data=None)
                    time.sleep(progress_update_interval_in_s)
                for line in proc.stdout or []:
                    fh.write(line)
                    tail.append(line)
                    # # heartbeat every ~2s
                    # now = time.time()
                    # if now - last_tick >= progress_update_interval_in_s:
                    #     self.send_event("task-progress", data=None)
                    #     last_tick = now
                rc = proc.wait()
                if rc != 0:
                    err_tail = "".join(tail)
                    raise RuntimeError(
                        f"AmCache-EvilHunter exited with {rc}\n"
                        f"--- stdout (last {len(tail)} lines) ---\n{err_tail}"
                    )

        # Collect produced artifacts
        output_files.extend([
            output_file_json.to_dict(),
            output_file_csv.to_dict(),
            output_file_stdout.to_dict(),
        ])

    if not output_files:
        raise RuntimeError("[!] Error processing task")

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command=" && ".join(executed_cmds),
        meta={},
    )
