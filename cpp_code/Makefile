
CC        = $(CROSS_COMPILE)g++
STRIP     = $(CROSS_COMPILE)strip

CFLAGS    = -Wall
LDFLAGS   =  

TARGET    = hashtest_cpp

OBJS	  = hashtest_cpp.o crypto_hash.o sha1.o md5.o

all: $(TARGET)

clean: 
	rm -f *.o $(TARGET) *~ *.scc *.vcproj *.vspscc out/$(TARGET) keys/apikeys.h


$(TARGET): $(OBJS)
		$(CC) $(CFLAGS) $(DEBUGS) -o $@ $(OBJS) $(LDFLAGS)


.cpp.o:
		$(CC) -c $(CFLAGS) $(DEBUGS) $<

hashtest.o: hashtest.cpp hmac.hpp
crypto_hash.o: crypto_hash.cpp crypto_hash.hpp
sha1.o: sha1.cpp sha1.hpp crypto_hash.hpp byteorder.hpp
md5.o: md5.cpp md5.hpp crypto_hash.hpp byteorder.hpp
