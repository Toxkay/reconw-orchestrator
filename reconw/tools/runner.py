import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from rich.console import Console

from reconw.storage.repository import create_tool_result, utc_now

console = Console(highlight=False)


class ToolNotFoundError(Exception):
    """Raised when an external tool executable is not found on PATH."""
    pass


class ToolTimeoutError(Exception):
    """Raised when a tool execution exceeds its allotted timeout."""
    pass


@dataclass(slots=True)
class ToolExecutionResult:
    """Encapsulates the execution results of an external security tool."""
    tool_name: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    started_at: str
    finished_at: str
    raw_output_path: Path | None = None
    tool_result_id: int | None = None
    item_count: int = 0
    error_message: str | None = None

    @property
    def is_success(self) -> bool:
        """Returns True if the tool process exited with 0 and without error message."""
        return self.exit_code == 0 and not self.error_message

    def lines(self) -> list[str]:
        """Extracts non-empty stripped lines from stdout or the raw output file."""
        content = self._get_content()
        return [line.strip() for line in content.splitlines() if line.strip()]

    def parse_ndjson(self) -> list[dict[str, Any]]:
        """Parses stdout or the raw output file as Newline-Delimited JSON (NDJSON)."""
        content = self._get_content()
        items: list[dict[str, Any]] = []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return items

    def _get_content(self) -> str:
        """Reads raw output file if available; otherwise returns stdout."""
        if self.raw_output_path and self.raw_output_path.exists():
            try:
                return self.raw_output_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return self.stdout


def _is_pd_httpx(binary_path: str) -> bool:
    """Verifies that the binary is ProjectDiscovery httpx, not Python httpx."""
    try:
        res = subprocess.run(
            [binary_path, "-version"],
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
            errors="replace",
        )
        combined = ((res.stdout or "") + (res.stderr or "")).lower()
        if "projectdiscovery" in combined or "current version" in combined:
            return True
        if "usage: httpx [options] url" in combined or "no such option" in combined:
            return False
        return res.returncode == 0
    except Exception:
        return False


def resolve_tool_binary(tool_name: str) -> str | None:
    """Resolves the correct binary path, prioritizing ~/go/bin and handling Kali's httpx-toolkit."""
    home_dir = Path.home()
    go_bin = home_dir / "go" / "bin"

    # 1. Check ~/go/bin first (most common for Go tools)
    if go_bin.exists():
        candidates = [go_bin / tool_name]
        if os.name == "nt":
            candidates.append(go_bin / f"{tool_name}.exe")
        for c in candidates:
            if c.exists() and c.is_file():
                return str(c)

    # 2. For httpx, handle Kali Linux httpx-toolkit alias & avoid Python httpx
    if tool_name == "httpx":
        kali_toolkit = shutil.which("httpx-toolkit")
        if kali_toolkit:
            return kali_toolkit

        std_httpx = shutil.which("httpx")
        if std_httpx:
            if _is_pd_httpx(std_httpx):
                return std_httpx

    # 3. Standard system PATH lookup
    path = shutil.which(tool_name)
    if path:
        return path

    return None


def is_tool_available(tool_name: str) -> bool:
    """Check if an external binary is available in PATH or ~/go/bin."""
    return resolve_tool_binary(tool_name) is not None


def require_tool(tool_name: str) -> str:
    """Validate that a tool binary exists and return its resolved path."""
    resolved = resolve_tool_binary(tool_name)
    if not resolved:
        raise ToolNotFoundError(
            f"External tool '{tool_name}' is not installed or not found in system PATH."
        )
    return resolved


def get_tool_version(tool_name: str, timeout: int = 5) -> str:
    """Safely attempts to query the tool's version string."""
    binary = resolve_tool_binary(tool_name)
    if not binary:
        return ""

    for flag in ["-version", "--version", "version", "-v"]:
        try:
            res = subprocess.run(
                [binary, flag],
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                errors="replace",
            )
            output = (res.stdout or res.stderr or "").strip()
            if res.returncode == 0 and output:
                first_line = output.splitlines()[0].strip()
                return first_line[:100]
        except (subprocess.SubprocessError, OSError):
            continue

    return "installed"


def write_temp_targets(
    targets: Sequence[str],
    prefix: str = "recon_targets_",
    dir: Path | str | None = None
) -> Path:
    """Writes a collection of target strings into a temporary file."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        prefix=prefix,
        suffix=".txt",
        delete=False,
        encoding="utf-8",
        dir=str(dir) if dir else None,
    )
    with tmp as f:
        for target in targets:
            clean = target.strip()
            if clean:
                f.write(f"{clean}\n")
    return Path(tmp.name)


class ToolRunner:
    """Engine for executing external recon binaries with timeout and audit logging."""

    def __init__(
        self,
        default_timeout: int = 300,
        default_retries: int = 1,
        retry_backoff: float = 2.0,
        artifacts_dir: Path | str = Path("artifacts"),
    ):
        self.default_timeout = default_timeout
        self.default_retries = default_retries
        self.retry_backoff = retry_backoff
        self.artifacts_dir = Path(artifacts_dir)

    def run(
        self,
        tool_name: str,
        args: list[str],
        stage_name: str = "generic",
        run_id: int | None = None,
        timeout: int | None = None,
        retries: int | None = None,
        raw_output_path: Path | None = None,
        save_stdout_as_artifact: bool = False,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> ToolExecutionResult:
        """Executes the external tool safely without shell=True."""
        binary_path = resolve_tool_binary(tool_name)
        if not binary_path:
            now = utc_now()
            err_msg = f"Binary '{tool_name}' was not found in system PATH or ~/go/bin."
            result = ToolExecutionResult(
                tool_name=tool_name,
                command=[tool_name, *args],
                exit_code=127,
                stdout="",
                stderr="",
                duration_seconds=0.0,
                started_at=now,
                finished_at=now,
                raw_output_path=raw_output_path,
                error_message=err_msg,
            )
            self._log_provenance(result, stage_name, run_id)
            return result

        full_command = [binary_path, *args]
        effective_timeout = timeout if timeout is not None else self.default_timeout
        max_attempts = 1 + max(0, retries if retries is not None else self.default_retries)

        last_result: ToolExecutionResult | None = None

        for attempt in range(1, max_attempts + 1):
            started_at = utc_now()
            t0 = time.perf_counter()

            exit_code = -1
            stdout_str = ""
            stderr_str = ""
            error_message: str | None = None

            try:
                proc = subprocess.run(
                    full_command,
                    capture_output=True,
                    text=True,
                    timeout=effective_timeout,
                    shell=False,
                    env=env,
                    cwd=str(cwd) if cwd else None,
                    errors="replace",
                )
                exit_code = proc.returncode
                stdout_str = proc.stdout or ""
                stderr_str = proc.stderr or ""
                if exit_code != 0 and stderr_str:
                    error_message = stderr_str.strip().splitlines()[-1][:200]

            except subprocess.TimeoutExpired as exc:
                exit_code = 124
                stdout_str = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
                stderr_str = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
                error_message = f"Process timed out after {effective_timeout} seconds (attempt {attempt}/{max_attempts})."

            except FileNotFoundError:
                exit_code = 127
                error_message = f"Executable not found: {binary_path}"

            except OSError as exc:
                exit_code = 1
                error_message = f"Execution error: {exc}"

            duration_seconds = round(time.perf_counter() - t0, 3)
            finished_at = utc_now()

            final_raw_path = raw_output_path
            if save_stdout_as_artifact and stdout_str and not final_raw_path:
                final_raw_path = self._save_stdout_artifact(stage_name, tool_name, stdout_str)

            item_count = 0
            if final_raw_path and final_raw_path.exists():
                try:
                    lines = [l for l in final_raw_path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                    item_count = len(lines)
                except OSError:
                    pass
            elif stdout_str:
                lines = [l for l in stdout_str.splitlines() if l.strip()]
                item_count = len(lines)

            last_result = ToolExecutionResult(
                tool_name=tool_name,
                command=full_command,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_seconds=duration_seconds,
                started_at=started_at,
                finished_at=finished_at,
                raw_output_path=final_raw_path,
                item_count=item_count,
                error_message=error_message,
            )

            if last_result.is_success:
                break

            if attempt < max_attempts:
                time.sleep(self.retry_backoff)

        assert last_result is not None
        self._log_provenance(last_result, stage_name, run_id)

        # TEMPORARY DEBUG DUMP: Save raw unfiltered tool output to debug_<tool_name>_raw.txt
        try:
            debug_path = Path(f"debug_{tool_name}_raw.txt")
            out_content = last_result.stdout
            if last_result.raw_output_path and last_result.raw_output_path.exists():
                out_content = last_result.raw_output_path.read_text(encoding="utf-8", errors="replace")
            if out_content:
                debug_path.write_text(out_content, encoding="utf-8")
                console.print(f"[bold yellow][DEBUG DUMP][/bold yellow] Saved raw unfiltered [cyan]{tool_name}[/cyan] output to [bold green]{debug_path.resolve()}[/bold green] ({len(out_content)} bytes)")
        except Exception:
            pass

        return last_result

    def _save_stdout_artifact(self, stage_name: str, tool_name: str, stdout: str) -> Path:
        stage_artifacts_dir = self.artifacts_dir / stage_name
        stage_artifacts_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        raw_file = stage_artifacts_dir / f"{tool_name}_{timestamp}.raw"
        raw_file.write_text(stdout, encoding="utf-8")
        return raw_file

    def _log_provenance(
        self,
        result: ToolExecutionResult,
        stage_name: str,
        run_id: int | None
    ) -> None:
        if run_id is None:
            return

        try:
            tool_ver = get_tool_version(result.tool_name)
            tool_res_id = create_tool_result(
                run_id=run_id,
                stage_name=stage_name,
                tool_name=result.tool_name,
                command=" ".join(result.command),
                exit_code=result.exit_code,
                tool_version=tool_ver,
                started_at=result.started_at,
                finished_at=result.finished_at,
                raw_output_path=str(result.raw_output_path) if result.raw_output_path else "",
                item_count=result.item_count,
                error_message=result.error_message or "",
            )
            result.tool_result_id = tool_res_id
        except Exception as exc:
            if result.error_message:
                result.error_message += f" | DB logging error: {exc}"
            else:
                result.error_message = f"DB logging error: {exc}"


default_runner = ToolRunner()


def run_tool(
    tool_name: str,
    args: list[str],
    stage_name: str = "generic",
    run_id: int | None = None,
    timeout: int = 300,
    retries: int = 0,
    raw_output_path: Path | None = None,
    save_stdout_as_artifact: bool = False,
) -> ToolExecutionResult:
    return default_runner.run(
        tool_name=tool_name,
        args=args,
        stage_name=stage_name,
        run_id=run_id,
        timeout=timeout,
        retries=retries,
        raw_output_path=raw_output_path,
        save_stdout_as_artifact=save_stdout_as_artifact,
    )