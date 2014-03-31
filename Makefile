TARGET = chan_test.so
OBJECTS = chan_test.o
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Winit-self -Wmissing-format-attribute -Wformat=2 \
	-g -fPIC -D'_GNU_SOURCE' -D'AST_MODULE="chan_test"'
LDFLAGS = -Wall -shared

.PHONY: install clean

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

install: $(TARGET)
	mkdir -p $(DESTDIR)/usr/lib/asterisk/modules
	install -m 644 $(TARGET) $(DESTDIR)/usr/lib/asterisk/modules/

clean:
	rm -f $(OBJECTS)
	rm -f $(TARGET)
