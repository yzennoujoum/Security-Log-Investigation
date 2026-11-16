def load_lines(path):
    "Read a text file and return its lines as a list of strings."
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise SystemExit(f"ERROR: Input file not found: {path}")


firewall_lines = load_lines("data/firewall.log")
auth_lines = load_lines("data/authentication.log")

print(len(firewall_lines), "firewall lines")
print(len(auth_lines), "authentication lines")
print(firewall_lines[0])
print(auth_lines[0])