# `image` is a marker file recording when build.sh last ran; it does not prove the
# image still exists. A `docker system prune` removes the image and leaves the
# marker, and make would then report "up to date" while nothing is built -- after
# which Docker would fall back to pulling interuss/monitoring from Docker Hub,
# i.e. the unpinned UPSTREAM image. Drop the marker whenever the image is missing.
ifeq ($(shell docker image inspect interuss/monitoring >/dev/null 2>&1 && echo present),)
$(shell rm -f image)
endif

image: ../uv.lock ../pyproject.toml $(shell find . -type f ! -path "*/output/*" ! -path "*/.*" ! -path "*/__pycache__/*" ! -name image ! -name "*.pyc") $(shell find ../interfaces -type f)
	./build.sh
