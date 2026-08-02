use wasmtime::*;
use wasmtime_wasi::sync::WasiCtxBuilder;
use wasmtime_wasi::WasiCtx;

struct HostState {
    wasi: WasiCtx,
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("wasm path arg required");

    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;
    let module = Module::from_file(&engine, &path)?;

    let mut linker: Linker<HostState> = Linker::new(&engine);
    wasmtime_wasi::sync::add_to_linker(&mut linker, |s: &mut HostState| &mut s.wasi)?;

    let wasi = WasiCtxBuilder::new().inherit_stdout().inherit_stderr().build();
    let mut store = Store::new(&engine, HostState { wasi });
    store.set_fuel(u64::MAX)?;

    let instance = linker.instantiate(&mut store, &module)?;

    // WASI reactor/command entry point conventions: try _start first, else __wasm_call_ctors then nothing else.
    if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
        let fuel_before = store.get_fuel()?;
        let result = start.call(&mut store, ());
        let fuel_after = store.get_fuel().unwrap_or(0);
        let consumed = fuel_before.saturating_sub(fuel_after);
        match result {
            Ok(()) => println!("OK fuel_consumed={}", consumed),
            Err(e) => println!("TRAP fuel_consumed={} err={}", consumed, e),
        }
    } else {
        println!("no _start export found");
    }
    Ok(())
}
