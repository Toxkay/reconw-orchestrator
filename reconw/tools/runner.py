# pyrefly: ignore [missing-import]
import shutil
import subprocess

def is_tool_available(tool_name: str) -> bool:
    """Check if a tool is available in the system."""
    return shutil.which(tool_name) is not None

def run_tools(tool_name:str) 
    return subprocess.run(tool_name)
    