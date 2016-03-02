all: run-server-background run-client
	
	
run-server:
	python SRP_Server.py

run-client:
	sleep 0.2
	python SRP_Client.py

run-server-background:
	python SRP_Server.py &

add-user:
	@echo 'Name of user ?'
	@read username; python generateUsers.py $$username