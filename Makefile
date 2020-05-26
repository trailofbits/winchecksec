CLANG_FORMAT := clang-format
ALL_SRCS := $(shell \
	find . -type f \
		\( -path './build/*' -o -path './include/vendor/*' \) \
		-prune -o \
		\( -name '*.cpp' -o -name '*.h' \) \
		-print \
)

ALL_LISTFILES := $(shell \
	find . -type f \
	-path './build/*' \
	-prune -o \
	\( -name 'CMakeLists.txt' -o -name '*.cmake' \) \
	-print \
)

VERSION := $(shell cat VERSION)

.PHONY: all
all:
	echo "This is not a build system! Run my targets individually!"

.PHONY: format
format: clang-format cmake-format

.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i -style=file $(ALL_SRCS)
	git diff --exit-code

.PHONY: cmake-format
cmake-format:
	cmake-format -i $(ALL_LISTFILES)
	git diff --exit-code

.PHONY: doc
doc:
	# Docs only: append the short hash to the version.
	VERSION=$(VERSION)-$(shell git rev-parse --short HEAD) \
		doxygen Doxyfile
