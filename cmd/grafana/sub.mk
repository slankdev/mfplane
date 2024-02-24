grafana_img := slankdev/mfplane-grafana:develop
grafana-docker-build:
	docker build -t ${grafana_img} -f cmd/grafana/Dockerfile .
grafana-docker-push: grafana-docker-build
	docker push ${grafana_img}
