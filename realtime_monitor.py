import time
from datetime import datetime

import collector
import correlation_engine


# =========================================================
# SETTINGS
# =========================================================

SCAN_INTERVAL = 30


# =========================================================
# COLLECT WINDOWS SECURITY EVENTS
# =========================================================

def update_security_events():
    try:
        events = collector.run_powershell()

        if not events:
            return 0

        new_events, updated_events = collector.save_events(events)

        return new_events

    except Exception as error:
        print(f"[SECURITY COLLECTOR ERROR] {error}")
        return 0


# =========================================================
# FIND AND SAVE NEW INCIDENTS
# =========================================================

def update_correlations():

    try:
        events = correlation_engine.build_events()

        if not events:
            return 0

        triggers = correlation_engine.build_triggers(events)

        incidents = []
        fingerprints = set()

        for trigger in triggers:

            related_events = correlation_engine.build_incident(
                trigger,
                events
            )

            result = correlation_engine.analyze_incident(
                related_events
            )

            if result is None:
                continue

            fingerprint = correlation_engine.make_fingerprint(
                result
            )

            if fingerprint in fingerprints:
                continue

            fingerprints.add(fingerprint)
            incidents.append(result)

        saved = 0

        for incident in incidents:

            if correlation_engine.save_alert(incident):

                saved += 1

                print()
                print("==========================================")
                print("      CYBER ECHO INCIDENT DETECTED")
                print("==========================================")
                print(f"Level : {incident['level']}")
                print(f"Score : {incident['score']}/100")
                print(f"Title : {incident['title']}")
                print(f"Why   : {incident['explanation']}")
                print()

        return saved

    except Exception as error:

        print(
            f"[CORRELATION ERROR] {error}"
        )

        return 0


# =========================================================
# MAIN SERVICE
# =========================================================

def main():

    print()
    print("==========================================")
    print("       CYBER ECHO REAL-TIME ENGINE")
    print("==========================================")
    print()
    print("Real Windows security collection: ACTIVE")
    print("Real process monitoring: ACTIVE")
    print("Real file monitoring: ACTIVE")
    print("Real-time correlation: ACTIVE")
    print()
    print(f"Scan interval: {SCAN_INTERVAL} seconds")
    print("Press CTRL+C to stop.")
    print()

    collector.init_db()
    correlation_engine.init_db()

    try:

        while True:

            now = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print(
                f"[{now}] Checking real security activity..."
            )

            new_security_events = update_security_events()

            new_incidents = update_correlations()

            if new_security_events:

                print(
                    f"New Windows security events: "
                    f"{new_security_events}"
                )

            if new_incidents:

                print(
                    f"New correlated incidents: "
                    f"{new_incidents}"
                )

            if (
                new_security_events == 0
                and new_incidents == 0
            ):

                print(
                    "No new high-value changes detected."
                )

            print()

            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:

        print()
        print(
            "CYBER ECHO real-time engine stopped."
        )
        print()


# =========================================================
# START
# =========================================================

if __name__ == "__main__":
    main()