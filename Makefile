all:  clean  server kdc
	@echo "client.cpp complied and run"



clean:
	rm client
	echo "Removing the executables present"

kdc:
	g++ -o kdc kdc.cpp -lssl -lcrypto
	@echo "kdc.cpp compiled successfully\n"
	@echo "./kdc -p 8080 -o log.txt -f pwd.txt \n"


server: client.cpp
	g++ -o client client.cpp -lssl -lcrypto
	@echo "client.cpp compiled successfully\n"
	@echo "Sending  Message @Sender Node ..."
	@echo "-------------------------------------\n"
	@./client -n myname -m S -o othername -i plain.txt -a 127.0.0.1 -p 8080
	@echo "-------------------------------------\n"
	@echo "Receiving Message @Receiver Node ..."
	@echo "-------------------------------------\n"
	@echo "-------------------------------------\n"

c2:
	@./client -n othername -m R -s cipher.txt -o out.txt -a 127.0.0.1 -p 8080
	