"""Remote helper shape from google/skills (inert fixture: builds a string, runs nothing)."""
import base64


def remote_command(script):
    """Encode script via base64 to avoid shell quoting issues over SSH."""
    encoded_script = base64.b64encode(script.encode("utf-8")).decode("ascii")
    decoded_expr = f"exec(base64.b64decode('{encoded_script}').decode('utf-8'))"
    return f'python3 -c "import base64; {decoded_expr}"'
