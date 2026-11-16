def load_lines(path):
    "Read a text file and return its lines as a list of strings."
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise SystemExit(f"ERROR: Input file not found: {path}")


firewall_lines = load_lines("data/firewall.log")
auth_lines = load_lines("data/authentication.log")

#parsing 
def parse_line(line):
    "Turn one log line into a dictionary. Raises ValueError if the line is bad."
    parts = line.split()
    if len(parts) < 4:
        raise ValueError("not enough fields")

    event = {"date": parts[0], "time": parts[1], "type": parts[2]}

    for item in parts[3:]:
        if "=" not in item:
            raise ValueError("expected key=value but got " + item)
        key, value = item.split("=", 1)
        event[key] = value

    if "port" in event:
        event["port"] = int(event["port"])

    return event


def parse_log(lines, required_fields, allowed_types):
    """Parse every line. Returns a list of good events and a list of bad lines."""
    events = []
    bad_lines = []

    for number, line in enumerate(lines, start=1):
        try:
            event = parse_line(line)
            if event["type"] not in allowed_types:
                raise ValueError("unexpected event type " + event["type"])
            for field in required_fields:
                if field not in event:
                    raise ValueError("missing field " + field)
            events.append(event)
        except ValueError as error:
            bad_lines.append((number, str(error), line))

    return events, bad_lines

firewall_events, firewall_bad = parse_log(
    firewall_lines, ["src", "dst", "port"], ["ALLOWED", "BLOCKED"])
auth_events, auth_bad = parse_log(
    auth_lines, ["user", "src"], ["LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED", "LOGOUT"])

print(len(firewall_events), "valid firewall events,", len(firewall_bad), "bad lines")
print(len(auth_events), "valid authentication events,", len(auth_bad), "bad lines")
print(firewall_events[0])

for bad in firewall_bad + auth_bad:
    print(bad)

print(set(event["type"] for event in firewall_events))
print(set(event["type"] for event in auth_events))