#!/bin/sh

# The aurargb_val parameter format is: "R,G,B,Mode,Speed,Direction"
#
# Available Modes (from UI auraEffectArray):
#  0: Event
#  1: Static
#  2: Breathing
#  3: Flash
#  4: Color Cycle
#  5: Rainbow
#  6: Strobing
#  8: Comet
# 11: Wave
# 12: Yoyo
# 13: Starry Night
#
# Speed: -2 to 2 (0 is default)
# Direction: 0 to 2
# Note: nvram set does not degrade flash memory since we are not calling 'nvram commit'

# Initial state unknown
CURRENT_STATE="unknown"

# The target to ping
TARGET="1.1.1.1"

while true; do
    ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1

    if [ $? -eq 0 ]; then
        # Ping succeeded
        if [ "$CURRENT_STATE" != "up" ]; then
            CURRENT_STATE="up"
            nvram set aurargb_enable=1
            nvram set aurargb_val="0,0,255,1,0,0" # Static blue
            service start_aurargb
        fi
    else
        # Ping failed
        if [ "$CURRENT_STATE" != "down" ]; then
            CURRENT_STATE="down"
            nvram set aurargb_enable=1
            nvram set aurargb_val="255,0,0,2,0,0" # Breathing red
            service start_aurargb
        fi
    fi

    # Wait before checking again
    sleep 5
done
