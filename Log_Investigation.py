import csv
import json
import os


# Thresholds used for risk scoring
FAILED_LOGIN_LIMIT = 10     # failed logins from one IP
BLOCKED_LIMIT = 20          # blocked firewall events from one IP
PORT_LIMIT = 10             # different blocked ports from one IP
USER_LIMIT = 4              # different usernames tried by one IP
HIGH_SCORE = 60
MEDIUM_SCORE = 30


def load_lines(path):
    "Read a text file and return its lines as a list of strings."
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise SystemExit(f"ERROR: Input file not found: {path}")


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
    "Parse every line. Returns a list of good events and a list of bad lines."
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


def count_values(events, field):
    "Count how many times each value of a field appears. Returns a dictionary."
    counts = {}
    for event in events:
        value = event[field]
        if value in counts:
            counts[value] += 1
        else:
            counts[value] = 1
    return counts


def top_items(counts, how_many):
    "Return the highest-count items as a list of (name, count), biggest first."
    names = sorted(counts, key=counts.get, reverse=True)
    result = []
    for name in names[:how_many]:
        result.append((name, counts[name]))
    return result


def analyse_firewall(events):
    "Work out the firewall summary figures. Returns a dictionary of results."
    blocked = []
    for event in events:
        if event["type"] == "BLOCKED":
            blocked.append(event)

    type_counts = count_values(events, "type")

    return {
        "valid_events": len(events),
        "allowed": type_counts.get("ALLOWED", 0),
        "blocked": type_counts.get("BLOCKED", 0),
        "unique_sources": len(count_values(events, "src")),
        "top_blocked_sources": top_items(count_values(blocked, "src"), 5),
        "top_ports": top_items(count_values(events, "port"), 5),
        "top_blocked_ports": top_items(count_values(blocked, "port"), 5),
    }


def analyse_auth(events):
    "Work out the authentication summary figures. Returns a dictionary of results."
    failed = []
    locked_users = []
    for event in events:
        if event["type"] == "LOGIN_FAILED":
            failed.append(event)
        elif event["type"] == "ACCOUNT_LOCKED":
            if event["user"] not in locked_users:
                locked_users.append(event["user"])

    type_counts = count_values(events, "type")

    return {
        "valid_events": len(events),
        "login_success": type_counts.get("LOGIN_SUCCESS", 0),
        "login_failed": type_counts.get("LOGIN_FAILED", 0),
        "account_locked": type_counts.get("ACCOUNT_LOCKED", 0),
        "logout": type_counts.get("LOGOUT", 0),
        "locked_users": locked_users,
        "top_failed_sources": top_items(count_values(failed, "src"), 5),
        "top_targeted_users": top_items(count_values(failed, "user"), 5),
    }


def load_suspicious_ips(path):
    "Read the suspicious IP list. Returns an empty list if the file is missing."
    ips = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                ip = line.strip()
                if ip != "" and not ip.startswith("#") and ip not in ips:
                    ips.append(ip)
    except FileNotFoundError:
        print("WARNING: suspicious IP list not found, continuing without it")
    return ips


def get_profile(profiles, ip):
    "Return the profile for an IP, creating an empty one the first time."
    if ip not in profiles:
        profiles[ip] = {"ip": ip, "blocked": 0, "ports": [], "failed": 0,
                        "users": [], "lockouts": 0, "success_after_failures": False,
                        "success_user": ""}
    return profiles[ip]


def build_ip_profiles(firewall_events, auth_events):
    "Combine both logs into one dictionary of evidence per source IP."
    profiles = {}

    for event in firewall_events:
        if event["type"] == "BLOCKED":
            profile = get_profile(profiles, event["src"])
            profile["blocked"] += 1
            if event["port"] not in profile["ports"]:
                profile["ports"].append(event["port"])

    for event in auth_events:
        profile = get_profile(profiles, event["src"])
        if event["type"] == "LOGIN_FAILED":
            profile["failed"] += 1
            if event["user"] not in profile["users"]:
                profile["users"].append(event["user"])
        elif event["type"] == "ACCOUNT_LOCKED":
            profile["lockouts"] += 1
        elif event["type"] == "LOGIN_SUCCESS":
            if profile["failed"] >= FAILED_LOGIN_LIMIT:
                profile["success_after_failures"] = True
                profile["success_user"] = event["user"]

    return profiles


def calculate_risk(profile, suspicious_ips):
    "Score one IP. Returns the score, the risk level and a list of reasons."
    score = 0
    reasons = []

    if profile["success_after_failures"]:
        score += 40
        reasons.append("successful login as " + profile["success_user"]
                       + " after many failures (possible compromise)")
    if profile["failed"] >= FAILED_LOGIN_LIMIT:
        score += 25
        reasons.append(str(profile["failed"]) + " failed logins (brute-force pattern)")
    if len(profile["users"]) >= USER_LIMIT:
        score += 15
        reasons.append(str(len(profile["users"])) + " different usernames tried")
    if profile["blocked"] >= BLOCKED_LIMIT:
        score += 15
        reasons.append(str(profile["blocked"]) + " blocked firewall events")
    if len(profile["ports"]) >= PORT_LIMIT:
        score += 15
        reasons.append(str(len(profile["ports"])) + " different ports blocked (scan pattern)")
    if profile["lockouts"] > 0:
        score += 10
        reasons.append("caused " + str(profile["lockouts"]) + " account lockout(s)")
    if profile["ip"] in suspicious_ips:
        score += 20
        reasons.append("listed in suspicious_ips.txt")

    if score >= HIGH_SCORE:
        level = "HIGH"
    elif score >= MEDIUM_SCORE:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, reasons


def get_score(finding):
    "Used for sorting findings by score."
    return finding["score"]


def rank_findings(profiles, suspicious_ips):
    "Score every IP and return the ones with evidence, highest score first."
    findings = []
    for ip in profiles:
        score, level, reasons = calculate_risk(profiles[ip], suspicious_ips)
        if len(reasons) > 0:
            findings.append({"ip": ip, "score": score, "level": level, "reasons": reasons})
    findings.sort(key=get_score, reverse=True)
    return findings


def add_ranked_list(lines, title, items, label):
    "Add a numbered top list to the report lines."
    lines.append("  " + title)
    if len(items) == 0:
        lines.append("    (none)")
    position = 1
    for name, count in items:
        lines.append("    " + str(position) + ". " + str(name) + " - " + str(count) + " " + label)
        position += 1


def generate_report(firewall, auth, findings, firewall_bad, auth_bad):
    "Build the full text report and return it as one string."
    lines = []
    lines.append("=" * 70)
    lines.append("SECURITY LOG INVESTIGATION SUMMARY")
    lines.append("=" * 70)

    lines.append("")
    lines.append("DATA QUALITY")
    lines.append("  firewall.log: " + str(firewall["valid_events"]) + " valid, "
                 + str(len(firewall_bad)) + " skipped")
    lines.append("  authentication.log: " + str(auth["valid_events"]) + " valid, "
                 + str(len(auth_bad)) + " skipped")

    lines.append("")
    lines.append("FIREWALL")
    lines.append("  ALLOWED: " + str(firewall["allowed"]) + "   BLOCKED: " + str(firewall["blocked"])
                 + "   Unique source IPs: " + str(firewall["unique_sources"]))
    add_ranked_list(lines, "Top blocked source IPs:", firewall["top_blocked_sources"], "blocked")
    add_ranked_list(lines, "Most targeted ports:", firewall["top_ports"], "events")
    add_ranked_list(lines, "Most blocked ports:", firewall["top_blocked_ports"], "blocked")

    lines.append("")
    lines.append("AUTHENTICATION")
    lines.append("  LOGIN_SUCCESS: " + str(auth["login_success"])
                 + "   LOGIN_FAILED: " + str(auth["login_failed"])
                 + "   ACCOUNT_LOCKED: " + str(auth["account_locked"]))
    lines.append("  Locked accounts: " + ", ".join(auth["locked_users"]))
    add_ranked_list(lines, "Top failed-login source IPs:", auth["top_failed_sources"], "failures")
    add_ranked_list(lines, "Most targeted usernames:", auth["top_targeted_users"], "failures")

    lines.append("")
    lines.append("RANKED FINDINGS (highest risk first)")
    if len(findings) == 0:
        lines.append("  No source IP met any threshold.")
    position = 1
    for finding in findings:
        lines.append("  #" + str(position) + " [" + finding["level"] + "] " + finding["ip"]
                     + "  (score " + str(finding["score"]) + ")")
        for reason in finding["reasons"]:
            lines.append("       - " + reason)
        position += 1

    lines.append("")
    lines.append("Note: scores help decide what to review first. They are not proof of an attack.")
    lines.append("=" * 70)
    return "\n".join(lines)


def save_reports(report_text, firewall, auth, findings, bad_lines):
    "Save the results as TXT, JSON and CSV in the output folder."
    try:
        os.makedirs("output", exist_ok=True)

        with open("output/investigation_summary.txt", "w", encoding="utf-8") as handle:
            handle.write(report_text + "\n")

        results = {"firewall": firewall, "authentication": auth,
                   "findings": findings, "skipped_lines": bad_lines}
        with open("output/investigation_summary.json", "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2)

        with open("output/ranked_findings.csv", "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["ip", "level", "score", "reasons"])
            for finding in findings:
                writer.writerow([finding["ip"], finding["level"], finding["score"],
                                 "; ".join(finding["reasons"])])

        print("Reports saved in the output folder.")
    except OSError as error:
        print("ERROR: could not save reports:", error)


def main():
    firewall_lines = load_lines("data/firewall.log")
    auth_lines = load_lines("data/authentication.log")
    suspicious_ips = load_suspicious_ips("data/suspicious_ips.txt")

    firewall_events, firewall_bad = parse_log(
        firewall_lines, ["src", "dst", "port"], ["ALLOWED", "BLOCKED"])
    auth_events, auth_bad = parse_log(
        auth_lines, ["user", "src"], ["LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED", "LOGOUT"])

    firewall_results = analyse_firewall(firewall_events)
    auth_results = analyse_auth(auth_events)
    profiles = build_ip_profiles(firewall_events, auth_events)
    findings = rank_findings(profiles, suspicious_ips)

    report_text = generate_report(firewall_results, auth_results, findings, firewall_bad, auth_bad)
    print(report_text)
    save_reports(report_text, firewall_results, auth_results, findings, firewall_bad + auth_bad)


if __name__ == "__main__":
    main()