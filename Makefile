CC = gcc
CFLAGS = -Wall -O2
TARGET = scrapper

all: $(TARGET)

$(TARGET): scrapper.c
	$(CC) $(CFLAGS) -o $(TARGET) scrapper.c

clean:
	rm -f $(TARGET)
