import subprocess


ALLOWED_COMMANDS = {
    "list": "dir",
    "date": "date"
}


def run_internal_task(task_name):
    # Input is constrained to an internal allowlist before reaching subprocess.
    cmd = ALLOWED_COMMANDS.get(task_name, "date")
    return subprocess.check_output(cmd, shell=True).decode()