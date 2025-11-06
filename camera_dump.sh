#!/usr/bin/env bash
# capture_cam_regs.sh
# One-touch setup to enable Qualcomm camera register/log tracing on Android,
# install kprobes to capture MMIO addresses/values, auto-launch the Camera,
# wait 5 seconds, then close it and collect everything.
#
# Requirements:
# - Rooted device with Qualcomm CamX/Spectra drivers (best results), but kprobes also
#   work on generic MMIO helpers readl/writel.
# - adb in PATH; USB debugging enabled
#
# Usage:
#   chmod +x capture_cam_regs.sh
#   ./capture_cam_regs.sh
#
# Outputs will be in ./cam_capture_<timestamp>/ on your host.
set -Eeuo pipefail

# --------------------------- Config (tweak if needed) ---------------------------
# Bitmask for kernel camera debug groups (CAM_*). 0xFFFFFFFF = everything.
: "${CAM_DEBUG_MDL:=0xFFFFFFFF}"
# CSID debug: 0x3 = SOF/EOF; 0xF to include SOT/EOT, etc.
: "${CSID_DEBUG:=0x3}"
# Enable per-request register dumps from IFE block (1 = on)
: "${PER_REQ_REG_DUMP:=1}"
# UMD (userspace) register dump toggles for CamX
: "${ENABLE_IFE_REG_DUMP:=TRUE}"
: "${IFE_REG_DUMP_MASK:=0xFFFFF}"

# Intent to launch the camera (image capture). Change if vendor camera needs custom intent.
: "${CAMERA_INTENT_ACTION:=android.media.action.IMAGE_CAPTURE}"
# How long to keep the camera open (seconds)
: "${CAMERA_OPEN_SECS:=5}"

# Potential override file locations for CamX settings
OVERRIDE_FILES=(
  "/data/vendor/camera/camxoverridesettings.txt"
  "/vendor/etc/camera/camxoverridesettings.txt"
  "/sdcard/camxoverridesettings.txt"
)

# --------------------------- Helpers ---------------------------
ADB_BIN="${ADB_BIN:-adb}"

ts() { date +"%Y%m%d-%H%M%S"; }
say() { echo -e "[*] $*"; }
die() { echo -e "[!] $*" >&2; exit 1; }

adb_ok() { command -v "$ADB_BIN" >/dev/null 2>&1 || die "adb not found in PATH"; }

adb_wait_device() {
  "$ADB_BIN" wait-for-device
  # Verify we can talk to a single device
  local count
  count=$("$ADB_BIN" devices | awk 'NR>1 && $2=="device"{c++} END{print c+0}')
  [[ "$count" -eq 1 ]] || die "Expected 1 connected device in \"device\" state, found $count"
}

adb_sh() { "$ADB_BIN" shell "$@"; }

host_outdir="cam_capture_$(ts)"
mkdir -p "$host_outdir"

cleanup() {
  set +e
  say "Stopping tracing and background capture..."
  # Turn off kernel tracing
  adb_sh "echo 0 > /sys/kernel/tracing/tracing_on" >/dev/null 2>&1
  
  # Kill host background readers with SIGTERM first, then SIGKILL if needed
  if [[ -n "${PID_KMSG:-}" ]]; then
    kill "$PID_KMSG" >/dev/null 2>&1
    sleep 1
    kill -9 "$PID_KMSG" >/dev/null 2>&1
  fi
  
  if [[ -n "${PID_TRACE:-}" ]]; then
    kill "$PID_TRACE" >/dev/null 2>&1
    sleep 1
    kill -9 "$PID_TRACE" >/dev/null 2>&1
  fi
  
  if [[ -n "${PID_LOGCAT:-}" ]]; then
    kill "$PID_LOGCAT" >/dev/null 2>&1
    sleep 1
    kill -9 "$PID_LOGCAT" >/dev/null 2>&1
  fi
  
  # Wait briefly for processes to terminate, but don't hang indefinitely
  timeout 3 wait >/dev/null 2>&1 || true
  say "Done."
}
trap cleanup EXIT

# --------------------------- Start ---------------------------
adb_ok
adb_wait_device

say "Gaining root & remounting (if supported)..."
$ADB_BIN root    >/dev/null 2>&1 || true
$ADB_BIN remount >/dev/null 2>&1 || true

say "Mounting debugfs (if not already)..."
adb_sh "mount -t debugfs debugfs /sys/kernel/debug" >/dev/null 2>&1 || true

# Unredact kernel pointers in logs/tracing (best-effort, requires root)
say "Setting kptr_restrict=0 (unredact kernel pointers in logs)"
adb_sh "echo 0 > /proc/sys/kernel/kptr_restrict" || true

# Configure kernel camera debug (Qualcomm)
if adb_sh "[ -e /sys/module/cam_debug_util/parameters/debug_mdl ]"; then
  say "Setting cam_debug_util debug_mdl=${CAM_DEBUG_MDL}"
  adb_sh "echo ${CAM_DEBUG_MDL} > /sys/module/cam_debug_util/parameters/debug_mdl" || die "Failed to set debug_mdl"
else
  say "cam_debug_util not found; continuing (some logs may be missing)"
fi

# CSID / CSIPHY debug knobs (best-effort)
if adb_sh "[ -e /sys/kernel/debug/camera_ife/ife_csid_debug ]"; then
  say "Enabling CSID debug=${CSID_DEBUG} (SOF/EOF/etc.)"
  adb_sh "echo ${CSID_DEBUG} > /sys/kernel/debug/camera_ife/ife_csid_debug" || true
fi

if adb_sh "[ -e /sys/module/cam_csiphy_core/parameters/csiphy_dump ]"; then
  say "Enabling CSIPHY dump"
  adb_sh "echo 1 > /sys/module/cam_csiphy_core/parameters/csiphy_dump" || true
fi

# Enable ftrace camera events
say "Enabling camera trace events + trace buffer streaming..."
adb_sh "echo 1 > /sys/kernel/tracing/tracing_on" || true
adb_sh "for e in /sys/kernel/tracing/events/camera/*/enable; do echo 1 > \"\$e\" 2>/dev/null || true; done" || true

# Per-request IFE register dump (kernel side)
if adb_sh "[ -e /sys/kernel/debug/camera_ife/per_req_reg_dump ]"; then
  say "Setting per_req_reg_dump=${PER_REQ_REG_DUMP}"
  adb_sh "echo ${PER_REQ_REG_DUMP} > /sys/kernel/debug/camera_ife/per_req_reg_dump" || true
fi

# Userspace CamX overrides (optional, best-effort)
say "Ensuring CamX override settings for IFE reg dump (userspace)..."
for f in "${OVERRIDE_FILES[@]}"; do
  adb_sh "mkdir -p \"$(dirname "$f")\"" >/dev/null 2>&1 || true
  adb_sh "touch \"$f\"" >/dev/null 2>&1 || true
  adb_sh "grep -q '^enableIFERegDump=' \"$f\" 2>/dev/null || echo enableIFERegDump=${ENABLE_IFE_REG_DUMP} >> \"$f\"" || true
  adb_sh "grep -q '^IFERegDumpMask='  \"$f\" 2>/dev/null || echo IFERegDumpMask=${IFE_REG_DUMP_MASK} >> \"$f\"" || true
done

# Prepare device-side outdir for ad-hoc dumps
dev_tmp="/sdcard/cam_capture_$(ts)"
adb_sh "mkdir -p ${dev_tmp}" || true

# --------------------------- Install kprobes (addresses + values) ---------------------------
say "Installing kprobes for cam_io_* and readl/writel (best-effort)…"
adb_sh 'bash -lc "
  cd /sys/kernel/tracing || exit 0
  # Clear any previous custom kprobes
  : > kprobe_events 2>/dev/null || true

  # Try cam_io_w_mb and cam_io_r_mb if present (Qualcomm)
  echo \"p:camw cam_io_w_mb addr=%x0 val=%x1\" >> kprobe_events 2>/dev/null || true
  echo \"r:camr cam_io_r_mb ret=%x\$retval addr=%x0\" >> kprobe_events 2>/dev/null || true

  # Also hook generic writel/readl so we catch everything even if helpers differ
  echo \"p:w writel val=%x0 addr=%x1\" >> kprobe_events 2>/dev/null || true
  echo \"r:r readl ret=%x\$retval addr=%x0\" >> kprobe_events 2>/dev/null || true

  # Enable all kprobe events
  for e in events/kprobes/*/enable; do echo 1 > \"$e\" 2>/dev/null || true; done

  # Make sure tracing is on
  echo 1 > tracing_on 2>/dev/null || true
"' || true

# --------------------------- Start background capture ---------------------------
say "Starting background capture (kmsg, trace_pipe, logcat)..."

# kmsg -> host file
$ADB_BIN shell "cat /proc/kmsg" | tee "${host_outdir}/kmsg.txt" &
PID_KMSG=$!

# trace_pipe -> host file (includes kprobes + camera tracepoints)
$ADB_BIN shell "cat /sys/kernel/tracing/trace_pipe" | tee "${host_outdir}/trace_pipe.txt" &
PID_TRACE=$!

# logcat (userspace CamX & camera service logs) -> host file
$ADB_BIN logcat -v threadtime | tee "${host_outdir}/logcat.txt" &
PID_LOGCAT=$!

# --------------------------- Launch camera, wait, close ---------------------------
say "Launching Camera via intent: ${CAMERA_INTENT_ACTION}"
adb_sh "am start -a ${CAMERA_INTENT_ACTION}" >/dev/null 2>&1 || say "Intent start failed (try unlocking device or custom vendor intent)"

say "Waiting ${CAMERA_OPEN_SECS}s with camera in foreground…"
sleep "${CAMERA_OPEN_SECS}"

say "Closing the Camera (best-effort: BACK, BACK, HOME)…"
adb_sh "input keyevent 4" >/dev/null 2>&1 || true  # BACK
adb_sh "input keyevent 4" >/dev/null 2>&1 || true  # BACK again
adb_sh "input keyevent 3" >/dev/null 2>&1 || true  # HOME

# (Optional) Try to force-stop stock AOSP camera if running (best-effort)
for pkg in com.android.camera com.google.android.GoogleCamera org.codeaurora.snapcam; do
  adb_sh "cmd activity force-stop $pkg" >/dev/null 2>&1 || true
done

# --------------------------- Stop capture & collect ---------------------------
say "Stopping trace and collecting device-side dumps..."

# Stop tracing to stabilize outputs
adb_sh "echo 0 > /sys/kernel/tracing/tracing_on" || true

# Dump current trace buffer to a file on device, then pull
adb_sh "cat /sys/kernel/tracing/trace > ${dev_tmp}/trace_dump.txt" || true

# If the camera stack wrote dumps under /data/vendor/camera, copy to sdcard for pull
if adb_sh "[ -d /data/vendor/camera ]"; then
  say "Copying /data/vendor/camera/* to ${dev_tmp} (best-effort)…"
  adb_sh "ls -1 /data/vendor/camera 2>/dev/null | xargs -I{} cp -fp \"/data/vendor/camera/{}\" \"${dev_tmp}/\" 2>/dev/null" || true
fi

# Best-effort copies of common debug txts that some drivers emit
for f in "/sdcard/kmd_camera_logs.txt" "/sdcard/csid_csiphy.txt" "/sdcard/fw_trace.txt"; do
  if adb_sh "[ -f \"$f\" ]"; then
    adb_sh "cp -fp \"$f\" \"${dev_tmp}/\"" || true
  fi
done

# Pull everything
say "Pulling logs to host: ${host_outdir}"
$ADB_BIN pull "${dev_tmp}/." "${host_outdir}/device_dumps" >/dev/null 2>&1 || true

# --------------------------- Parse and summarize results ---------------------------
parse_camera_data() {
    local logdir="$1"
    
    echo ""
    echo "================================================================================"
    echo "CAMERA REGISTER ACCESS SUMMARY"
    echo "================================================================================"
    
    # Parse trace_pipe.txt for kprobe events
    local trace_file="${logdir}/trace_pipe.txt"
    local logcat_file="${logdir}/logcat.txt"
    
    if [[ -f "$trace_file" ]]; then
        echo "Analyzing trace data from: $trace_file"
        
        # Count kprobe events
        local write_events=$(grep -c "camw:" "$trace_file" 2>/dev/null || echo "0")
        local read_events=$(grep -c "camr:" "$trace_file" 2>/dev/null || echo "0")
        local generic_writes=$(grep -c " w:" "$trace_file" 2>/dev/null || echo "0")
        local generic_reads=$(grep -c " r:" "$trace_file" 2>/dev/null || echo "0")
        
        echo "Kprobe Events Found:"
        echo "  Camera-specific writes (camw): $write_events"
        echo "  Camera-specific reads (camr):  $read_events"
        echo "  Generic writes (w):            $generic_writes"
        echo "  Generic reads (r):             $generic_reads"
        echo ""
        
        # Extract and display recent camera register accesses
        if [[ "$write_events" -gt 0 || "$read_events" -gt 0 ]]; then
            echo "RECENT CAMERA REGISTER WRITES:"
            echo "----------------------------------------------------------------"
            echo "Time                 Address            Value"
            echo "----------------------------------------------------------------"
            grep "camw:" "$trace_file" | tail -20 | while read -r line; do
                # Extract timestamp, address, and value from kprobe line
                if [[ $line =~ ([0-9]+\.[0-9]+):.*addr=([0-9a-fA-Fx]+).*val=([0-9a-fA-Fx]+) ]]; then
                    printf "%-20s %-18s %s\n" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
                fi
            done
            echo ""
            
            echo "RECENT CAMERA REGISTER READS:"
            echo "----------------------------------------------------------------"
            echo "Time                 Address            Return Value"
            echo "----------------------------------------------------------------"
            grep "camr:" "$trace_file" | tail -20 | while read -r line; do
                # Extract timestamp, address, and return value from kprobe line
                if [[ $line =~ ([0-9]+\.[0-9]+):.*ret=([0-9a-fA-Fx]+).*addr=([0-9a-fA-Fx]+) ]]; then
                    printf "%-20s %-18s %s\n" "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[2]}"
                fi
            done
            echo ""
        fi
        
        # Extract unique addresses accessed
        echo "ADDRESS ANALYSIS:"
        echo "----------------------------------------------------------------"
        local unique_addrs=$(grep -oE "addr=[0-9a-fA-Fx]+" "$trace_file" | sort -u | wc -l)
        echo "Unique addresses accessed: $unique_addrs"
        
        if [[ $unique_addrs -gt 0 ]]; then
            echo ""
            echo "Top 10 most frequently accessed addresses:"
            grep -oE "addr=[0-9a-fA-Fx]+" "$trace_file" | sort | uniq -c | sort -nr | head -10 | while read -r count addr; do
                printf "  %s: %d accesses\n" "${addr#addr=}" "$count"
            done
        fi
        echo ""
    fi
    
    # Parse logcat for CAM-UTIL messages
    if [[ -f "$logcat_file" ]]; then
        echo "LOGCAT CAM-UTIL MESSAGES:"
        echo "----------------------------------------------------------------"
        local cam_util_lines=$(grep -c "CAM-UTIL" "$logcat_file" 2>/dev/null || echo "0")
        echo "CAM-UTIL log lines found: $cam_util_lines"
        
        if [[ $cam_util_lines -gt 0 ]]; then
            echo ""
            echo "Recent CAM-UTIL register accesses:"
            grep "CAM-UTIL.*cam_io_[wr]" "$logcat_file" | tail -10 | while read -r line; do
                echo "  $line"
            done
        fi
        echo ""
    fi
    
    echo "================================================================================"
}

# --------------------------- Wrap up ---------------------------
say ""
say "Capture complete."
say "Host logs:"
say "  - ${host_outdir}/kmsg.txt"
say "  - ${host_outdir}/trace_pipe.txt   (includes kprobes: camw/camr/w/r)"
say "  - ${host_outdir}/logcat.txt"
say "Device dumps (if any):"
say "  - ${host_outdir}/device_dumps/"

# Parse and display camera register summary
parse_camera_data "$host_outdir"

say ""
say "Tuneables:"
say "  - CAMERA_OPEN_SECS (default 5)"
say "  - CAMERA_INTENT_ACTION (default android.media.action.IMAGE_CAPTURE)"
say "  - CAM_DEBUG_MDL/CSID_DEBUG for kernel verbosity"
