TARGET := lb

BPF_OBJ_EL := $(TARGET)_bpfel.o
BPF_OBJ_EB := $(TARGET)_bpfeb.o
GO_GEN_EL  := $(TARGET)_bpfel.go
GO_GEN_EB  := $(TARGET)_bpfeb.go

GO_GEN_T := $(BPF_OBJ_EL) $(BPF_OBJ_EB) $(GO_GEN_EL) $(GO_GEN_EB)

.PHONY: all generate build clean

all: build

generate: gen.go $(TARGET).c $(TARGET).h go.mod go.sum
	go generate

$(GO_GEN_T): generate

build: $(GO_GEN_T)
	go build -o $(TARGET)

clean:
	rm -f $(GO_GEN_T) $(TARGET)
