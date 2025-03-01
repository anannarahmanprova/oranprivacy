# Makefile for building and installing the TEE-enabled application

# Variables (customize these as needed)
REGISTRY=registry:5001
IMAGE_NAME=myapp
TAG=latest
DEPLOYMENT_FILE=deployment.yaml
NAMESPACE=riab

.PHONY: build-tee install-tee

build-tee:
	@echo "Building Docker image..."
	docker build -t $(IMAGE_NAME):$(TAG) .
	@echo "Tagging image for registry..."
	docker tag $(IMAGE_NAME):$(TAG) $(REGISTRY)/$(IMAGE_NAME):$(TAG)
	@echo "Pushing image to $(REGISTRY)..."
	docker push $(REGISTRY)/$(IMAGE_NAME):$(TAG)

install-tee:
	@echo "Deploying application to Kubernetes namespace $(NAMESPACE)..."
	kubectl apply -f $(DEPLOYMENT_FILE)
