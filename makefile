include ../makefile.game.2.0.noconfig

CFLAGS += -g -Wall -fPIC -shared -m32
INC += -I. -I../../include -I./curl/include -I./rapidjson -I/usr/local/ssl/include
LIB += -L./curl/lib -lcurl

TARGET = dirtyfilter.so
CPP_FILE = $(wildcard ./*.cpp)
OBJ = $(patsubst ./%.cpp, ./%.o, $(CPP_FILE))

all:$(TARGET)
$(TARGET): $(OBJ)
	g++ $(CFLAGS) -o $@ $(OBJ) $(INC) $(LIB) 	

%.o: %.cpp
	g++ $(CFLAGS) -c -o $@ $< $(INC)

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $< $(INC)

clean:
	@rm -f $(OBJ) $(TARGET)
