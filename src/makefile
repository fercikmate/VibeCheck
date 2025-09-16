CC=gcc
CFLAGS=-Wall -g

ODIR=obj
LDIR =../lib

LIB= 
LIBS= -lmosquitto -lpthread -lcjson

SRCS=application.c kontroler.c LED.c mems.c sirena.c tilt.c server.c

OBJ = $(patsubst %.c,$(ODIR)/%.o,$(SRCS))

all: application kontroler LED mems sirena tilt server
$(ODIR)/%.o: %.c 
	@mkdir -p $(ODIR)
	$(CC) $(CFLAGS) -c $< -o $@ 

application: $(ODIR)/application.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
kontroler: $(ODIR)/kontroler.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
LED: $(ODIR)/LED.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
mems: $(ODIR)/mems.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
sirena: $(ODIR)/sirena.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
tilt: $(ODIR)/tilt.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
server: $(ODIR)/server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

run_all:
	wt.exe -w 0 nt -p "Ubuntu" --title "LED_actuator" -- bash -c "./LED" &
	wt.exe -w 0 nt -p "Ubuntu" --title "sirena_actuator" -- bash -c "./sirena" &
	wt.exe -w 0 nt -p "Ubuntu" --title "mems_sensor" -- bash -c "./mems" &
	wt.exe -w 0 nt -p "Ubuntu" --title "tilt_sensor" -- bash -c "./tilt" &
	wt.exe -w 0 nt -p "Ubuntu" --title "server" -- bash -c "./server" &
	wt.exe -w 0 nt -p "Ubuntu" --title "application" -- bash -c "./application" &
	wt.exe -w 0 nt -p "Ubuntu" --title "kontroler" -- bash -c "./kontroler" &
.PHONY: clean run_all


clean:
	rm -f $(ODIR)/*.o application kontroler LED mems sirena tilt server
