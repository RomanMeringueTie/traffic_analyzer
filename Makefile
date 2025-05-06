all: main

main: main.go
	go build main.go

.PHONY: run

run: main
	sudo ./main "" res.txt

.PHONY: clean

clean:
	$(RM) main *.txt

.PHONY: check

check: *.txt
	sudo cat *.txt