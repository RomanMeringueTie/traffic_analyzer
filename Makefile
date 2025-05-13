all: a.out

a.out: main.cpp
	g++ -Wall -Wextra main.cpp -lpcap

.PHONY: run

run: a.out
	sudo ./a.out "" res.txt

.PHONY: clean

clean:
	$(RM) *.txt *.out

.PHONY: check

check: *.txt
	sudo cat *.txt