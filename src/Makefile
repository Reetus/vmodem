#
# Makefile for VMODEM - Virtual Serial Port TSR over TCP/IP
# Open Watcom wmake
#
# Build:        wmake
# Debug build:  wmake debug=1
# Clean:        wmake clean
#
# Prerequisites:
#   WATCOM environment variable must point to the Open Watcom install dir.
#   PATH must include $(WATCOM)\binl64 (Linux) or $(WATCOM)\binnt (Windows).
#   Example setup:
#     export WATCOM=/opt/watcom
#     export PATH=$WATCOM/binl64:$PATH
#     export INCLUDE=$WATCOM/h
#

# -------------------------------------------------------------------------
# Paths
# -------------------------------------------------------------------------

MTCP_ROOT = ../../mtcp/mTCP-src_2025-01-10
TCPLIB    = $(MTCP_ROOT)/TCPLIB
TCPINC    = $(MTCP_ROOT)/TCPINC
INC       = $(MTCP_ROOT)/INCLUDE

# -------------------------------------------------------------------------
# Compiler / Assembler flags
# -------------------------------------------------------------------------

memory_model = -ms

# Note: use \"...\" so that CFG_H expands to "vmodem.cfg" (with quotes).
# -fo=.obj: on Linux the OW compiler defaults to .o; force DOS OMF .obj output.
!ifdef debug
compile_opts = -0 $(memory_model) &
    -DCFG_H=\"vmodem.cfg\" &
    -fo=.obj &
    -i=$(TCPINC) -i=$(INC) -i=. &
    -zp2 -zpw -ei -s -d2
!else
compile_opts = -0 $(memory_model) &
    -DCFG_H=\"vmodem.cfg\" &
    -fo=.obj &
    -oh -os -oa &
    -i=$(TCPINC) -i=$(INC) -i=. &
    -zp2 -zpw -ei -s -we
!endif

asm_opts = -0 $(memory_model)

# -------------------------------------------------------------------------
# Object file lists
# -------------------------------------------------------------------------

# mTCP library objects (compiled from TCPLIB sources)
TCP_OBJS = packet.obj arp.obj eth.obj ip.obj ipasm.obj &
           tcp.obj tcpsockm.obj udp.obj utils.obj &
           dns.obj timer.obj trace.obj

# VMODEM application objects
VMODEM_OBJS = vmodem.obj int14.obj int8.obj poll.obj telnet.obj ringbuf.obj atcmd.obj

# -------------------------------------------------------------------------
# Default target
# -------------------------------------------------------------------------

all : vmodem.exe vmodctl.exe comdiag.exe fosschk.exe comtest.exe .symbolic
    @echo Build complete.

# -------------------------------------------------------------------------
# Implicit rules
# -------------------------------------------------------------------------

# Compile .c files as C++ (needed to link with mTCP C++ objects)
.c.obj :
    wpp $* $(compile_opts)

# -------------------------------------------------------------------------
# mTCP library objects
# (Each rule explicitly names the source file in TCPLIB)
# -------------------------------------------------------------------------

packet.obj : $(TCPLIB)/PACKET.CPP
    wpp $(TCPLIB)/packet $(compile_opts)

arp.obj : $(TCPLIB)/ARP.CPP
    wpp $(TCPLIB)/arp $(compile_opts)

eth.obj : $(TCPLIB)/ETH.CPP
    wpp $(TCPLIB)/eth $(compile_opts)

ip.obj : $(TCPLIB)/IP.CPP
    wpp $(TCPLIB)/ip $(compile_opts)

tcp.obj : $(TCPLIB)/TCP.CPP
    wpp $(TCPLIB)/tcp $(compile_opts)

tcpsockm.obj : $(TCPLIB)/TCPSOCKM.CPP
    wpp $(TCPLIB)/tcpsockm $(compile_opts)

udp.obj : $(TCPLIB)/UDP.CPP
    wpp $(TCPLIB)/udp $(compile_opts)

utils.obj : $(TCPLIB)/UTILS.CPP
    wpp $(TCPLIB)/utils $(compile_opts)

dns.obj : $(TCPLIB)/DNS.CPP
    wpp $(TCPLIB)/dns $(compile_opts)

timer.obj : $(TCPLIB)/TIMER.CPP
    wpp $(TCPLIB)/timer $(compile_opts)

trace.obj : $(TCPLIB)/TRACE.CPP
    wpp $(TCPLIB)/trace $(compile_opts)

ipasm.obj : $(TCPLIB)/IPASM.ASM
    wasm $(asm_opts) -fo=ipasm.obj $(TCPLIB)/ipasm

# -------------------------------------------------------------------------
# VMODEM application objects
# -------------------------------------------------------------------------

vmodem.obj  : vmodem.c  vmodem.h vmodem.cfg
ringbuf.obj : ringbuf.c vmodem.h vmodem.cfg
telnet.obj  : telnet.c  vmodem.h vmodem.cfg
int14.obj   : int14.c   vmodem.h vmodem.cfg
fossil.obj  : fossil.asm
    wasm $(asm_opts) -fo=fossil.obj fossil

atcmd.obj   : atcmd.c   vmodem.h vmodem.cfg
int8.obj    : int8.c    vmodem.h vmodem.cfg

# vmodctl does NOT need mTCP headers; compile with minimal options
vmodctl.obj : vmodctl.c
    wpp vmodctl -0 $(memory_model) -fo=.obj -zp2 -zpw -ei -s -we

# comdiag: standalone COM port diagnostic utility (no mTCP)
comdiag.obj : comdiag.c
    wpp comdiag -0 $(memory_model) -fo=.obj -zp2 -zpw -ei -s -we

# fosschk: FOSSIL driver detection checker (no mTCP)
fosschk.obj : fosschk.c
    wpp fosschk -0 $(memory_model) -fo=.obj -zp2 -zpw -ei -s -we

# comtest: DOS test helper for automated testing (no mTCP)
comtest.obj : ../tests/comtest.c
    wpp ../tests/comtest -0 $(memory_model) -fo=.obj -zp2 -zpw -ei -s -we

# -------------------------------------------------------------------------
# Link VMODEM.EXE
# -------------------------------------------------------------------------

vmodem.exe : $(VMODEM_OBJS) $(TCP_OBJS)
    wlink &
        system dos &
        option map &
        option eliminate &
        option stack=2048 &
        name $@ &
        file vmodem.obj,int14.obj,int8.obj,poll.obj,telnet.obj,ringbuf.obj,atcmd.obj &
        file packet.obj,arp.obj,eth.obj,ip.obj,ipasm.obj &
        file tcp.obj,tcpsockm.obj,udp.obj,utils.obj &
        file dns.obj,timer.obj,trace.obj

# -------------------------------------------------------------------------
# Link VMODEMCTL.EXE
# -------------------------------------------------------------------------

vmodctl.exe : vmodctl.obj
    wlink &
        system dos &
        option map &
        option eliminate &
        name $@ &
        file vmodctl.obj

comdiag.exe : comdiag.obj
    wlink &
        system dos &
        option map &
        option eliminate &
        name $@ &
        file comdiag.obj

fosschk.exe : fosschk.obj
    wlink &
        system dos &
        option map &
        option eliminate &
        name $@ &
        file fosschk.obj

comtest.exe : comtest.obj
    wlink &
        system dos &
        option map &
        option eliminate &
        name $@ &
        file comtest.obj

# -------------------------------------------------------------------------
# Clean
# -------------------------------------------------------------------------

install : vmodem.exe vmodctl.exe comdiag.exe fosschk.exe comtest.exe .symbolic
    @cp vmodem.exe ../../dosenv/vmodem/VMODEM.EXE
    @cp vmodctl.exe ../../dosenv/vmodem/VMODCTL.EXE
    @cp comdiag.exe ../../dosenv/vmodem/COMDIAG.EXE
    @cp fosschk.exe ../../dosenv/vmodem/FOSSCHK.EXE
    @cp comtest.exe ../../dosenv/vmodem/COMTEST.EXE
    @echo Installed to ../../dosenv/vmodem/

clean : .symbolic
    @rm -f *.obj *.o *.map *.err vmodem.exe vmodctl.exe comdiag.exe fosschk.exe comtest.exe
    @echo Clean done.
