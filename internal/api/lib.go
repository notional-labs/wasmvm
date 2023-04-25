package api

// notes:
// The original version seems to identify contracts by their checksum, if we want this we will need to build it.
// wazero uses context to track which contract is which.  Pin is implemented in rust, probably in https://github.com/CosmWasm/cosmwasm
// this file was much more useful than the rest of the docs: https://github.com/tetratelabs/wazero/blob/main/cache_example_test.go

import (
	"context"
	"fmt"
	"runtime"
	"syscall"

	"github.com/CosmWasm/wasmvm/types"
	"github.com/tetratelabs/wazero"
)

type Querier = types.Querier

func InitCache(dataDir string, supportedCapabilities string, cacheSize uint32, instanceMemoryLimit uint32) (wazero.CompilationCache, error) {

	cache, err := wazero.NewCompilationCacheWithDir(dataDir)
	defer cache.Close(context.Background())
	return cache, err
}

func ReleaseCache(ctx context.Context, cache wazero.CompilationCache) {
	cache.Close(ctx)
}

func StoreCode(ctx context.Context, cache wazero.CompilationCache, wasm []byte) (wazero.CompiledModule, error) {
	config := wazero.NewRuntimeConfig().WithCompilationCache(cache)
	r := wazero.NewRuntimeWithConfig(ctx, config)

	defer r.Close(ctx) // This closes everything this Runtime created except the file system cache.
	module, err := r.CompileModule(ctx, wasm)

	return module, err
}

func RemoveCode(ctx context.Context, cache wazero.CompilationCache, checksum []byte) error {
	err := cache.Close(ctx)

	return err
}

func GetCode(cache wazero.CompilationCache, checksum []byte) ([]byte, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	errmsg := uninitializedUnmanagedVector()
	wasm, err := C.load_wasm(cache.ptr, cs, &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(wasm), nil
}

func Pin(cache wazero.CompilationCache, checksum []byte) error {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	errmsg := uninitializedUnmanagedVector()
	_, err := C.pin(cache.ptr, cs, &errmsg)
	if err != nil {
		return errorWithMessage(err, errmsg)
	}
	return nil
}

func Unpin(cache wazero.CompilationCache, checksum []byte) error {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	errmsg := uninitializedUnmanagedVector()
	_, err := C.unpin(cache.ptr, cs, &errmsg)
	if err != nil {
		return errorWithMessage(err, errmsg)
	}
	return nil
}

func AnalyzeCode(cache wazero.CompilationCache, checksum []byte) (*types.AnalysisReport, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	errmsg := uninitializedUnmanagedVector()
	report, err := C.analyze_code(cache.ptr, cs, &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}
	requiredCapabilities := string(copyAndDestroyUnmanagedVector(report.required_capabilities))
	res := types.AnalysisReport{
		HasIBCEntryPoints:    bool(report.has_ibc_entry_points),
		RequiredFeatures:     requiredCapabilities,
		RequiredCapabilities: requiredCapabilities,
	}
	return &res, nil
}

func GetMetrics(cache wazero.CompilationCache) (*types.Metrics, error) {
	errmsg := uninitializedUnmanagedVector()
	metrics, err := C.get_metrics(cache.ptr, &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return &types.Metrics{
		HitsPinnedMemoryCache:     uint32(metrics.hits_pinned_memory_cache),
		HitsMemoryCache:           uint32(metrics.hits_memory_cache),
		HitsFsCache:               uint32(metrics.hits_fs_cache),
		Misses:                    uint32(metrics.misses),
		ElementsPinnedMemoryCache: uint64(metrics.elements_pinned_memory_cache),
		ElementsMemoryCache:       uint64(metrics.elements_memory_cache),
		SizePinnedMemoryCache:     uint64(metrics.size_pinned_memory_cache),
		SizeMemoryCache:           uint64(metrics.size_memory_cache),
	}, nil
}

func Instantiate(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	info []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	i := makeView(info)
	defer runtime.KeepAlive(info)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.instantiate(cache.ptr, cs, e, i, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func Execute(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	info []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	i := makeView(info)
	defer runtime.KeepAlive(info)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.execute(cache.ptr, cs, e, i, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func Migrate(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.migrate(cache.ptr, cs, e, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func Sudo(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.sudo(cache.ptr, cs, e, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func Reply(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	reply []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	r := makeView(reply)
	defer runtime.KeepAlive(reply)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.reply(cache.ptr, cs, e, r, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func Query(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.query(cache.ptr, cs, e, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func IBCChannelOpen(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.ibc_channel_open(cache.ptr, cs, e, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func IBCChannelConnect(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.ibc_channel_connect(cache.ptr, cs, e, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func IBCChannelClose(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	m := makeView(msg)
	defer runtime.KeepAlive(msg)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.ibc_channel_close(cache.ptr, cs, e, m, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func IBCPacketReceive(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	packet []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	pa := makeView(packet)
	defer runtime.KeepAlive(packet)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.ibc_packet_receive(cache.ptr, cs, e, pa, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func IBCPacketAck(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	ack []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	ac := makeView(ack)
	defer runtime.KeepAlive(ack)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.ibc_packet_ack(cache.ptr, cs, e, ac, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

func IBCPacketTimeout(
	cache wazero.CompilationCache,
	checksum []byte,
	env []byte,
	packet []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, uint64, error) {
	cs := makeView(checksum)
	defer runtime.KeepAlive(checksum)
	e := makeView(env)
	defer runtime.KeepAlive(env)
	pa := makeView(packet)
	defer runtime.KeepAlive(packet)

	callID := startCall()
	defer endCall(callID)

	dbState := buildDBState(store, callID)
	db := buildDB(&dbState, gasMeter)
	a := buildAPI(api)
	q := buildQuerier(querier)
	var gasUsed cu64
	errmsg := uninitializedUnmanagedVector()

	res, err := C.ibc_packet_timeout(cache.ptr, cs, e, pa, db, a, q, cu64(gasLimit), cbool(printDebug), &gasUsed, &errmsg)
	if err != nil && err.(syscall.Errno) != C.ErrnoValue_Success {
		// Depending on the nature of the error, `gasUsed` will either have a meaningful value, or just 0.
		return nil, uint64(gasUsed), errorWithMessage(err, errmsg)
	}
	return copyAndDestroyUnmanagedVector(res), uint64(gasUsed), nil
}

/**** To error module ***/

func errorWithMessage(err error, b C.UnmanagedVector) error {
	// this checks for out of gas as a special case
	if errno, ok := err.(syscall.Errno); ok && int(errno) == 2 {
		return types.OutOfGasError{}
	}
	msg := copyAndDestroyUnmanagedVector(b)
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}
