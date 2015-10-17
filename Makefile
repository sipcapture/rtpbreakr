# rtpbreakr Makefile.

INSTALL_DIR       = "$(HOME)/bin/" 

#####################################################################


all: build

build:
	@cd src ; $(MAKE)
	mv src/rtpbreakr ./
	@echo ""
	@echo "rtpbreakr has been compiled!"
	@echo ""


install:
	cp src/rtpbreak $(INSTALL_DIR)
	@echo ""
	@echo "rtpbreakr has been installed!"
	@echo ""

clean:
	cd src ; $(MAKE) clean
	rm -rf ./rtpbreakr
#eof
