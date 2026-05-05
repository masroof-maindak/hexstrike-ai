run:
	docker compose --profile kali run --rm -it kali

build:
	docker compose --profile kali build

run-dvwa:
	docker compose --profile dvwa up