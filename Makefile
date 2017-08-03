CC = gcc
CFLAGS+=-g -O0 -fPIC -Wall -DXP_UNIX
LDFLAGS+=
INCDIRS+=-I. -Isrc
PKCS11_INCDIRS+=-I/usr/include/nss3 -I/usr/include/nspr4
#NSPR_LIBS=-lssl3 -lsmime3 -lnss3 -lnssutil3 -lplds4 -lplc4 -lnspr4 -lpthread -ldl  
NSPR_LIBS=-lplds4 -lplc4 -lnspr4 -ldl  

# change this for other OS's like Windows
OS_UTIL=linux_util

SOURCES=src/amvp.c src/amvp_transport.c src/amvp_util.c src/parson.c src/midbg.c src/$(OS_UTIL).c
#SOURCES=src/midbg.c src/$(OS_UTIL).c
OBJECTS=$(SOURCES:.c=.o)
HEADERS=src/amvp.h src/midbg.h

#all: libamvp.a nss_app
all: local_app pk11mode pk11debug simple_test

.PHONY: test testcpp

libamvp.a: $(OBJECTS) $(HEADERS) 
	ar rcs libamvp.a $(OBJECTS)


.c.o: $(HEADERS)
	$(CC) $(INCDIRS) $(CFLAGS) $(PKCS11_INCDIRS) -c $< -o $@

libamvp.so: $(OBJECTS) 
	$(CC) $(INCDIRS) $(CFLAGS) -shared -Wl,-soname,libamvp.so.1.0.0 -o libamvp.so.1.0.0 $(OBJECTS)
	ln -fs libamvp.so.1.0.0 libamvp.so


local_app: app/app_local.o app/nss_amvp.o libamvp.a
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ app/app_local.o app/nss_amvp.o  -L. $(LDFLAGS) -lamvp -lcurl -ldl

amvp_app: app/amvp_app.o app/nss_amvp.o libamvp.a
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ app/app_local.o app/nss_amvp.o -L. $(LDFLAGS) -lamvp -lcurl -ldl

pk11mode: tests/pk11mode.o tests/pk11table.o
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ $^ -L. $(LDFLAGS) $(NSPR_LIBS)

pk11debug: tests/pk11debug.o  tests/pk11table.o
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ $^ -L. $(LDFLAGS) $(NSPR_LIBS) -lamvp  -ldl

simple_test: tests/simple_test.o  tests/pk11table.o
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ $^ -L. $(LDFLAGS) $(NSPR_LIBS) -ldl

clean:
	rm -f *.[ao]
	rm -f src/*.[ao]
	rm -f app/*.[ao]
	rm -f tests/*.[ao]
	rm -f libacvp.so.1.0.0
	rm -f local_app
	rm -f pk11mode pk11debug simple_test
	rm -f *.db
