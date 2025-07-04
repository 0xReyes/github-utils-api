docker-build: docker-clean
	docker build -t github-utils-api .

docker-clean:
	@if [ $$(docker ps -q -f name=github-api) ]; then docker stop github-api; fi
	@if [ $$(docker ps -a -q -f name=github-api) ]; then docker rm github-api; fi

docker-run: docker-build
	docker run -d -p 8080:8080 --name github-api \
	  -e GITHUB_TOKEN=${CR_PAT} \
	  -e PORT="8080" \
	  github-utils-api