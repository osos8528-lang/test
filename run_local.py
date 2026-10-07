"""Start the local workshop server without putting the admin password in code."""
from getpass import getpass
import os

import uvicorn


if __name__ == "__main__":
    if not os.getenv("ADMIN_PASSWORD"):
        password = getpass("Set a local practice admin password (hidden): ")
        if not password.strip():
            raise SystemExit("Password cannot be blank. Run this command again.")
        os.environ["ADMIN_PASSWORD"] = password
        del password
    print("Open http://127.0.0.1:8000/docs - Ctrl+C to stop.")
    uvicorn.run("main:app", host="127.0.0.1", port=8000)
