CC = gcc
CFLAGS+=-g -O0 -fPIC -Wall
LDFLAGS+=
INCDIRS+=-I. -Isrc
PKCS11_INCDIRS+=-I/usr/include/nss3 -I/usr/include/nspr4

SOURCES=src/amvp.c src/amvp_transport.c src/amvp_util.c src/parson.c
OBJECTS=$(SOURCES:.c=.o)

#all: libamvp.a nss_app
all: local_app

.PHONY: test testcpp

libamvp.a: $(OBJECTS)
	ar rcs libamvp.a $(OBJECTS)


.c.o:
	$(CC) $(INCDIRS) $(CFLAGS) -c $< -o $@

libamvp.so: $(OBJECTS)
	$(CC) $(INCDIRS) $(CFLAGS) -shared -Wl,-soname,libamvp.so.1.0.0 -o libamvp.so.1.0.0 $(OBJECTS)
	ln -fs libamvp.so.1.0.0 libamvp.so


local_app: app/app_local.o app/nss_amvp.o
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ app/app_local.o app/nss_amvp.o -L. $(LDFLAGS) 

amvp_app: app/amvp_app.o app/nss_amvp.o libamvp.a
	$(CC) $(INCDIRS) $(PKCS11_INCDIRS) -pie $(CFLAGS) -o $@ app/app_local.o app/nss_amvp.o -L. $(LDFLAGS) -lamvp -lcurl -ldl


clean:
	rm -f *.[ao]
	rm -f src/*.[ao]
	rm -f app/*.[ao]
	rm -f libacvp.so.1.0.0
	rm -f acvp_app
	rm -f testgcm
