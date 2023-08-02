# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# q1.py - Q1 specific code, not needed on earlier devices.
#
# NOTE: Lots of hardware overlap with Mk4, so see mk4.py too!
#
import os, sys, pyb, ckcc, version, glob, uctypes

def init0():
    # called very early
    from mk4 import init0 as mk4_init0

    # replace drawing code.
    import lcd_display as display
    sys.modules['display'] = display

    mk4_init0()

    # XXX do not ship like this XXX
    ckcc.vcp_enabled(True); print("REPL enabled")

    # Setup various hardware features of the Q1
    # - try to continue in case of errors/hardware faults
    try:
        from scanner import QRScanner
        glob.SCAN = QRScanner()
    except: pass

    try:
        setup_adc()
        #print('Batt volt: %s' % get_batt_level())
    except BaseException as exc:
        sys.print_exception(exc)

def setup_adc():
    # configure VREF source as internal 2.5v 
    VREF_LAYOUT = {
        "CSR": 0 | uctypes.UINT32,
        "CCR": 4 | uctypes.UINT32,
    }
    VREFBUF_CSR = 0x40010030

    vref = uctypes.struct(VREFBUF_CSR, VREF_LAYOUT)
    vref.CSR = 0x01     # VRS=0, HIZ=0, ENVR=1

    # could delay here until reads back as 0x9 (VRR==1)
    # but no need 

def get_batt_level():
    # return voltage from batteries, as a float
    # - will only work on battery power, else return None
    try:
        from machine import ADC, Pin
    except ImportError:
        # simulator
        return 2.99

    if Pin('NOT_BATTERY')() == 1:
        # not getting power from batteries, so don't know level
        return None

    adc = ADC(Pin('VIN_SENSE'))
    avg = sum(adc.read_u16() for i in range(10)) / 10.0

    return round((avg / 65535.0) * 2.5 * 2, 2)
    
def get_batt_threshold():
    # return 0=empty, 1=low, 2=75% 3=full or None if no bat
    volts = get_batt_level()
    if volts is None:
        return None
    if volts <= 2.0:
        return 0
    if volts > 4.5:
        return 3
    return 2 if volts > 3 else 1

# EOF
