CLANG_FORMAT := clang-format
ALL_SRCS := $(wildcard *.cc) $(wildcard *.h)

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
	cmake-format -i CMakeLists.txt
	git diff --exit-code
