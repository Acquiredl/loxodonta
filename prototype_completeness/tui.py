"""PROTOTYPE - THROWAWAY (issue #15). Run: python prototype_completeness/tui.py

Thin TUI shell over machine.py. Drive the completeness alarm state machine by
hand; the clock only moves when you move it, so every time-based edge is
reachable on purpose. Presets replay the field scenarios through the same
reducer the manual keys use.
"""
import sys
import machine as m

B, D, R = "\x1b[1m", "\x1b[2m", "\x1b[0m"
COLORS = {"OK": "\x1b[32m", "QUIET": "\x1b[36m", "LAGGING": "\x1b[33m",
          "ALARM-SILENT": "\x1b[31m", "ALARM-DEFICIT": "\x1b[31m",
          "SURPLUS?": "\x1b[35m", "ENDED-CLEAN": "\x1b[2m",
          "ENDED-DEFICIT": "\x1b[31m", "IDLE-CLEAN": "\x1b[2m", "IDLE-DEFICIT": "\x1b[31m"}

# int = advance clock that many seconds; letters = events on the preset's session
PRESETS = {
    "F": ("silent fork: 8 tools, 6 receipts, receipts keep arriving; wait out the grace",
          ["t", 1, "r", 1, "t", 1, "r", 1, "t", 1, "t", 1, "r", 1, "t", 1,
           "r", 1, "t", 1, "r", 1, "t", 1, "r", 1, "t", 35]),
    "W": ("wedged lock: receipts stop mid-session, tools continue",
          ["t", 1, "r", 1, "t", 1, "r", 1, "t", 15, "t", 20, "t"]),
    "D": ("hook disabled from the start: tools, zero receipts",
          ["t", 10, "t", 25, "t"]),
    "S": ("sibling continuation: tear, recording resumes in -002",
          ["t", 1, "r", 1, "t", 1, "r", 2, "t", 1, "g", 1, "t", 1, "g"]),
}


def getch():
    if sys.platform == "win32":
        import msvcrt
        return msvcrt.getwch()
    import termios, tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def render(world, active, last_msg):
    print("\x1b[2J\x1b[H", end="")
    print(f"{B}completeness alarm - prototype{R}  {D}(issue #15; grace={m.GRACE_SECONDS}s idle-end={m.IDLE_END_SECONDS}s){R}")
    print(f"{B}clock{R} t={world['now']}s\n")
    for sid in world["order"]:
        s = world["sessions"][sid]
        state, detail = m.classify(s, world["now"])
        c = COLORS.get(state, "")
        mark = ">" if sid == active else " "
        print(f"{mark} {B}session {sid}{R}  {c}{B}{state}{R}  {D}{detail}{R}")
        print(f"    tools={s['tools']}  receipts={s['receipts']}  chains={s['chains']}"
              f"  deficit={max(0, s['tools'] - s['receipts'])}"
              f"  {D}last_tool={s['last_tool']} last_receipt={s['last_receipt']}"
              f" deficit_since={s['deficit_since']} ended={s['ended']}{R}")
    if last_msg:
        print(f"\n{D}{last_msg}{R}")
    print(f"\n{B}[t]{R}{D} tool witnessed {R}{B}[r]{R}{D} receipt {R}{B}[g]{R}{D} receipt in new sibling {R}"
          f"{B}[e]{R}{D} session end{R}")
    print(f"{B}[5]{R}{D} +5s {R}{B}[3]{R}{D} +30s {R}{B}[m]{R}{D} +30min {R}"
          f"{B}[n]{R}{D} new session {R}{B}[1-9]{R}{D} switch{R}")
    print(f"{B}[F]{R}{D} fork {R}{B}[W]{R}{D} wedged lock {R}{B}[D]{R}{D} hook disabled {R}"
          f"{B}[S]{R}{D} sibling {R}{D}(presets run on a fresh session){R}  {B}[q]{R}{D} quit{R}")


def main():
    world = m.new_session(m.new_world(), "1")
    active, last_msg = "1", ""
    while True:
        render(world, active, last_msg)
        k = getch()
        last_msg = ""
        if k == "q":
            break
        elif k == "t":
            world = m.apply_event(world, active, "tool")
        elif k == "r":
            world = m.apply_event(world, active, "receipt")
        elif k == "g":
            world = m.apply_event(world, active, "sibling_receipt")
        elif k == "e":
            world = m.apply_event(world, active, "end")
        elif k == "5":
            world = m.apply_event(world, active, ("tick", 5))
        elif k == "3":
            world = m.apply_event(world, active, ("tick", 30))
        elif k == "m":
            world = m.apply_event(world, active, ("tick", 1800))
        elif k == "n":
            sid = str(len(world["order"]) + 1)
            world = m.new_session(world, sid)
            active = sid
        elif k.isdigit() and k in world["order"]:
            active = k
        elif k in PRESETS:
            desc, events = PRESETS[k]
            sid = str(len(world["order"]) + 1)
            world = m.new_session(world, sid)
            active = sid
            for ev in events:
                if isinstance(ev, int):
                    world = m.apply_event(world, sid, ("tick", ev))
                else:
                    world = m.apply_event(world, sid, {"t": "tool", "r": "receipt", "g": "sibling_receipt"}[ev])
            last_msg = f"preset [{k}] on fresh session {sid}: {desc}"


if __name__ == "__main__":
    main()
