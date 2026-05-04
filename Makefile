run:
	docker compose --profile kali run --rm -it kali

build:
	docker compose build

run-dvwa:
	docker compose --profile dvwa up