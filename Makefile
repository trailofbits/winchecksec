ALL_SRCS := $(wildcard *.cc) $(wildcard *.h)

.PHONY: all
all:
	echo "This is not a build system! Run my targets individually!"

.PHONY: lint
lint:
	clang-format -i -style=file $(ALL_SRCS)
	git diff --exit-code
