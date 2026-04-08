#!/usr/bin/env bash
set -x
set -eo pipefail

if [[ $PWD != *"raiko" ]]; then
	echo "move to root directory"
	# Find path to root directory (named 'raiko') from current directory
	# Find Cargo project root using cargo, regardless of directory name
	cargo_root=$(cargo locate-project --workspace --message-format plain 2>/dev/null | xargs dirname)
	if [[ -n "$cargo_root" && -d "$cargo_root" ]]; then
		cd "$cargo_root"
		echo "cd to Cargo project root: $cargo_root"
	else
		echo "Error: Could not locate Cargo project root from $PWD"
		exit 1
	fi
fi

if [[ -n $1 ]]; then
	tag=$1
else
	read -p "Do you have specific tag to build? default[latest]: " tag
	case "$tag" in
	"")
		tag=latest
		;;
	*) ;;
	esac
fi
echo "build tag is $tag"

# docker build
read -p "Do you want to build tee(0) or zk(1): " proof_type
case "$proof_type" in
0 | tee)
	image_name=raiko
	target_dockerfile=Dockerfile
	;;
1 | zk)
	image_name=raiko-zk
	target_dockerfile=Dockerfile.zk
	;;
*)
	echo "unknown proof type to build"
	exit 1
	;;
esac

echo "Build and push $image_name:$tag..."
docker buildx build . \
	-f $target_dockerfile \
	--load \
	--platform linux/amd64 \
	-t $image_name:latest \
	--build-arg TARGETPLATFORM=linux/amd64 \
	--progress=plain \
	2>&1 | tee log.build.$image_name.$tag

# check docker build status
if [ $? -ne 0 ]; then
	echo "❌ Docker build failed!"
	exit 1
fi

# Update local .env file with Docker-generated image IDs for zk builds
if [ "$proof_type" = "1" ] || [ "$proof_type" = "zk" ]; then
	echo "Updating local .env file with Docker-generated image IDs..."

	# Extract RISC0 image IDs from the Docker build log
	if grep -q "risc0 elf image id:" log.build.$image_name.$tag; then
		echo "Updating RISC0 image IDs from Docker build log..."
		./script/update_imageid.sh risc0 log.build.$image_name.$tag
	else
		echo "No RISC0 image IDs found in Docker build log"
	fi

	# Extract SP1 VK hashes from the Docker build log
	if grep -q "sp1 elf vk hash_bytes is:" log.build.$image_name.$tag; then
		echo "Updating SP1 VK hashes from Docker build log..."
		./script/update_imageid.sh sp1 log.build.$image_name.$tag
	else
		echo "No SP1 VK hashes found in Docker build log"
	fi

	echo "Local .env file updated with Docker-generated image IDs"
fi

# update latest tag at same time for local docker compose running
DOCKER_REPOSITORY=us-docker.pkg.dev/evmchain/images
docker tag $image_name:latest $DOCKER_REPOSITORY/$image_name:latest
docker tag $image_name:latest $DOCKER_REPOSITORY/$image_name:$tag

read -p "Do you want to push $image_name:$tag to registry? (y/N) " confirm
case "$confirm" in
[yY][eE][sS] | [yY])
	docker push $DOCKER_REPOSITORY/$image_name:$tag
	;;
*)
	echo "⏭️ Skipped: docker push $DOCKER_REPOSITORY/$image_name:$tag."
	echo "you can do it manually"
	;;
esac

echo "Done"
