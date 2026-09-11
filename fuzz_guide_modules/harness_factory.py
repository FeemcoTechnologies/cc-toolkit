"""AFL++ campaign setup + harness generation for a target."""

import os
import re
import shlex
import shutil
import subprocess

from . import r2util


WORKDIR = os.environ.get("FUZZ_GUIDE_WORKDIR", "/tmp/fuzz_guide_workdir")


def setup_campaign(
    binary: str,
    input_type: str = "stdin",
    seeds: str = "",
    n_seeds: int = 8,
    timeout_ms: int = 1000,
    target: str = "",
    args: str = "",
) -> dict:
    """Prepare an AFL++ campaign directory for a target binary.

    Creates ``<workdir>/<name>/`` with ``in/``, ``out/`` and a run script.

    input_type: stdin | file | net_basic | dlopen
    """
    if not os.path.isfile(binary):
        return {"error": f"Binary not found: {binary}"}

    binary = os.path.abspath(binary)
    name = os.path.basename(binary)
    work = os.path.join(WORKDIR, name)
    in_dir = os.path.join(work, "in")
    os.makedirs(in_dir, exist_ok=True)
    os.makedirs(os.path.join(work, "out"), exist_ok=True)

    # ---- seed generation ----
    if seeds and os.path.isdir(seeds):
        copied = 0
        for f in sorted(os.listdir(seeds))[:n_seeds]:
            sp = os.path.join(seeds, f)
            if os.path.isfile(sp):
                shutil.copy(sp, os.path.join(in_dir, f))
                copied += 1
        seed_note = f"copied {copied} seed files"
    else:
        seed_note = _gen_default_seeds(in_dir, n_seeds)

    # ---- build command ----
    if input_type == "file":
        if not args or "@@" not in args:
            args = "@@"  # AFL replaces @@ with the file path
        cmd = f"{binary} {args}" if args.startswith("@") else f"{binary} {args}"
    elif input_type == "net_basic":
        harness = generate_net_harness(target or "127.0.0.1:5555", work)
        if harness.get("error"):
            return {"error": harness["error"]}
        host, port = harness["host"], harness["port"]
        cmd = f"{harness['harness_bin']} {host} {port} @@"
    elif input_type == "dlopen":
        harness = generate_dlopen_harness(binary, work)
        if harness.get("error"):
            return {"error": harness["error"]}
        if not harness.get("built"):
            return {"error": f"dlopen harness failed to build: {harness.get('build_error')}"}
        cmd = f"{harness['harness_bin']} @@"
    else:  # stdin
        cmd = binary

    # ---- input mode for AFL ----
    if input_type in ("net_basic", "dlopen"):
        # harness is our own native driver; AFL runs it in dumb mode (-n).
        # The TARGET only needs to be running / loadable, not instrumented.
        afl_mode = "-n"
        qemu_flag, inst_mode = "", "dumb (harness driver; target un-instrumented)"
    else:
        afl_mode = "-m none"
        qemu_flag, inst_mode = _detect_afl_mode(binary)

    fuzzer = shutil.which("afl-fuzz") or "afl-fuzz"

    run_script = f"""#!/bin/sh
# AFL++ campaign for {binary}
# input_type: {input_type}  |  timeout: {timeout_ms} ms
# instrumentation: {inst_mode}
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 {fuzzer} {qemu_flag} {afl_mode} \\
  -i {in_dir} -o {os.path.join(work, "out")} -t {timeout_ms} {("-- " + cmd) if cmd else "# -- cmd omitted"}
"""
    script_path = os.path.join(work, "run.sh")
    with open(script_path, "w") as f:
        f.write(run_script)
    os.chmod(script_path, 0o755)

    # Build list-form command (safe for subprocess without shell=True)
    run_command_list = None
    if cmd:
        _rl = [fuzzer]
        if qemu_flag:
            _rl.extend(qemu_flag.split())
        _rl.extend(afl_mode.split())
        _rl += ["-i", in_dir, "-o", os.path.join(work, "out"),
                "-t", str(timeout_ms), "--"] + shlex.split(cmd)
        run_command_list = _rl

    return {
        "binary": binary,
        "campaign_dir": work,
        "input_dir": in_dir,
        "out_dir": os.path.join(work, "out"),
        "run_script": script_path,
        "input_type": input_type,
        "inst_mode": inst_mode,
        "seed_info": seed_note,
        "command": cmd,
        "run_command": f"AFL_SKIP_CPUFREQ=1 {fuzzer} {qemu_flag} {afl_mode} -i {in_dir} -o {os.path.join(work,'out')} -t {timeout_ms} -- {cmd}" if cmd else None,
        "run_command_list": run_command_list,
        "timeout_ms": timeout_ms,
    }


def generate_dlopen_harness(so_path: str, workdir: str = "") -> dict:
    """Generate + build a dlopen harness for a shared library.

    Exports-first: the exported API is the fuzz surface, so targets are taken
    from the dynamic symbol table (readelf -Ws GLOBAL/FUNC) — no r2 required,
    which makes this safe on large .so files too.
    """
    if not os.path.isfile(so_path):
        return {"error": f"Shared library not found: {so_path}"}

    workdir = workdir or os.path.join(WORKDIR, os.path.basename(so_path) + "_harness")
    os.makedirs(workdir, exist_ok=True)

    # readelf exports (GLOBAL FUNC, defined only)
    exports = []
    try:
        out = subprocess.check_output(
            ["readelf", "-Ws", so_path], text=True,
            timeout=12, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[3] == "FUNC" and parts[4] == "GLOBAL" and parts[6] != "UND":
                exports.append(parts[-1])
    except Exception:
        pass

    if not exports:
        return {"error": "No exported FUNC symbols found (readelf -Ws). "
                         "Stripped/no-dynsym library: exports-first surface not available."}

    # prefer names that look like a parse/entry API, then dedupe
    preferred = [n for n in exports if any(k in n.lower() for k in ("parse", "decode", "new", "init", "load", "run", "proc"))]
    targets = list(dict.fromkeys(preferred + exports))[:10]

    calls = "\n".join(
        f"    {{ void_fn g{i} = (void_fn)dlsym(h, \"{name}\"); "
        f"if (g{i}) ((int_pfn)g{i})(input, input_len); }}  // fuzz {name}"
        for i, name in enumerate(targets)
    )

    harness = f"""/* Auto-generated exports-first dlopen harness for {so_path} */
/* Dumb mode: AFL runs THIS program; each exec the exported API is called */
/* with the fuzz payload (input buffer) as the global fuzz data.           */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>

typedef void (*void_fn)(void);
typedef int  (*int_pfn)(const void*, unsigned long);
typedef void (*void_pfn)(const void*, unsigned long);

static unsigned char input[65536];
static unsigned long input_len = 0;

int main(int argc, char **argv) {{
    void *h = dlopen("{so_path}", RTLD_NOW | RTLD_GLOBAL);
    if (!h) {{ fprintf(stderr, "dlopen failed: %s\\n", dlerror()); return 1; }}
    if (argc > 1) {{
        FILE *fp = fopen(argv[1], "rb");
        if (!fp) return 1;
        input_len = fread(input, 1, sizeof(input), fp);
        fclose(fp);
    }} else {{
        input_len = fread(input, 1, sizeof(input), stdin);
    }}
    volatile void_fn f_void = (void_fn)0;
    {calls}
    (void)input_len; (void)f_void;
    dlclose(h);
    return 0;
}}
"""
    src = os.path.join(workdir, "harness.c")
    with open(src, "w") as f:
        f.write(harness)

    out_bin = os.path.join(workdir, "harness")
    cc = shutil.which("gcc") or "gcc"
    built, build_err = True, ""
    try:
        subprocess.check_output(
            [cc, "-O2", "-o", out_bin, src, "-ldl"],
            text=True, timeout=30, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        built, build_err = False, (e.output or "")[:500]

    result = {
        "so_path": so_path,
        "harness_src": src,
        "harness_bin": out_bin,
        "built": built,
        "num_exported": len(exports),
        "num_targets": len(targets),
        "targets": targets,
    }
    if not built:
        result["build_error"] = build_err
    return result


def generate_net_harness(target: str = "127.0.0.1:5555", workdir: str = "") -> dict:
    """Generate + build a TCP *client* fuzz driver (net_basic).

    The harness connects OUT to the target service (already listening on
    `host:port`) with a fuzz-derived payload, reads the reply, exits.  This is
    the blackbox way to fuzz a remote-only consumer: the target process stays
    uninstrumented, AFL purely mutates wire bytes from an external perspective.
    """
    try:
        host, port = target.rsplit(":", 1)
        port = int(port)
    except Exception:
        return {"error": f"Bad target '{target}' — expected host:port"}

    workdir = workdir or os.path.join(WORKDIR, "net_driver")
    os.makedirs(workdir, exist_ok=True)

    src = os.path.join(workdir, "net_driver.c")
    with open(src, "w") as f:
        f.write(f"""/* TCP fuzz driver: connect to {host}:{port}, send fuzz bytes, read reply. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

int main(int argc, char **argv) {{
    const char *host = "{host}", *port_s = "{port}";
    char *file = NULL;
    if (argc >= 4) {{ host = argv[1]; port_s = argv[2]; file = argv[3]; }}
    else if (argc == 2) file = argv[1];

    unsigned char buf[131072];
    long n = 0;
    if (file) {{
        FILE *fp = fopen(file, "rb");
        if (!fp) {{ perror("open"); return 1; }}
        n = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
    }} else {{
        n = read(0, buf, sizeof(buf));
    }}
    if (n < 0) n = 0;

    struct addrinfo hints, *ai, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_s, &hints, &ai) != 0) {{ perror("getaddrinfo"); return 1; }}
    int fd = -1;
    for (p = ai; p; p = p->ai_next) {{
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }}
    freeaddrinfo(ai);
    if (fd < 0) {{ perror("connect"); return 1; }}

    send(fd, buf, (size_t)n, 0);

    /* drain reply (bounded) so the target actually processes the payload */
    struct pollfd pfd = {{ fd, POLLIN, 0 }};
    char tmp[4096];
    int overall = 0;
    while (overall < 2000) {{
        int pr = poll(&pfd, 1, 150);
        if (pr <= 0) break;
        ssize_t r = recv(fd, tmp, sizeof(tmp), 0);
        if (r <= 0) break;
        overall += (int)r;
    }}
    close(fd);
    return 0;
}}
""")

    out_bin = os.path.join(workdir, "net_driver")
    cc = shutil.which("gcc") or "gcc"
    built, build_err = True, ""
    try:
        subprocess.check_output(
            [cc, "-O2", "-o", out_bin, src], text=True,
            timeout=30, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        built, build_err = False, (e.output or "")[:500]

    result = {
        "harness_src": src,
        "harness_bin": out_bin,
        "host": host,
        "port": port,
        "built": built,
    }
    if not built:
        result["build_error"] = build_err
    return result


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _gen_default_seeds(in_dir: str, n: int) -> str:
    """Write simple default seeds for stdin fuzzing."""
    plain = [
        b"0", b"1", b"A", b"\x00", b"\xff", b"1234567890",
        b"hello world", b"AAAAAAAAAAAAAAAAAAAAAAAA", b"-----BEGIN CERT-----",
        b"\x00\x01\x02\x03\x04\x05\x06\x07", b"GET / HTTP/1.1\r\n",
    ]
    for i, data in enumerate(plain[:n]):
        with open(os.path.join(in_dir, f"seed_{i}"), "wb") as f:
            f.write(data)
    return f"wrote {min(n, len(plain))} default seeds (hex/ascii/edge cases)"


def read_fuzzer_stats(out_dir: str) -> dict:
    """Read fuzzer_stats from an AFL output dir (handles single/master layouts)."""
    for cand in (
        os.path.join(out_dir, "default", "fuzzer_stats"),
        os.path.join(out_dir, "fuzzer_stats"),
    ):
        if os.path.isfile(cand):
            stats = {}
            with open(cand) as f:
                for line in f:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        stats[k.strip()] = v.strip()
            return stats

    # fallback: parse plot_data (some builds only write this)
    plot = os.path.join(out_dir, "plot_data")
    if os.path.isfile(plot):
        with open(plot) as f:
            lines = [l for l in f.read().splitlines() if l and not l.startswith("#")]
        if lines:
            data = lines[-1].split(",")
            # col: rel_time,cycles_done,cur_item,corpus_count,pending_total,
            #      pending_favs,map_size,saved_crashes,saved_hangs,max_depth,
            #      execs_per_sec,total_execs,edges_found,total_crashes,servers
            def _col(i):
                try:
                    return data[i].strip()
                except Exception:
                    return None
            return {
                "execs_done": _col(11),
                "execs_per_sec": _col(10),
                "corpus_count": _col(3),
                "cycles_done": _col(1),
                "saved_crashes": _col(7),
                "edges_found": _col(12),
                "relative_time": _col(0),
                "last_update": None,
            }

    return {}


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _detect_afl_mode(binary_path: str) -> tuple[str, str]:
    """Return (afl_flag, mode_name) for best available binary-only instrumentation.

    Checks for afl-qemu-trace → QEMU, frida-trace.so → FRIDA, else dumb mode.
    """
    # QEMU mode
    qemu = shutil.which("afl-qemu-trace")
    if qemu:
        return "-Q", "qemu"

    # FRIDA mode — look for the .so in the standard AFL libs directory
    for lib_dir in ("/usr/local/lib/afl", "/usr/lib/afl", "/usr/lib/x86_64-linux-gnu/afl"):
        frida = os.path.join(lib_dir, "afl-frida-trace.so")
        if os.path.isfile(frida):
            return "-O", "frida"

    # Unicorn mode
    for lib_dir in ("/usr/local/lib/afl", "/usr/lib/afl", "/usr/lib/x86_64-linux-gnu/afl"):
        unicorn = os.path.join(lib_dir, "afl-unicorn-trace.so")
        if os.path.isfile(unicorn):
            return "-U", "unicorn"

    # Dumb mode (no instrumentation, still mutates + detects crashes)
    return "-n", "dumb (no instrumentation — no coverage feedback)"