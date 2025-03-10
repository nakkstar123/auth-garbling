use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use utils::filter_drain::FilterDrain;

use mpz_common::{
    scoped_futures::{ScopedBoxFuture, ScopedFutureExt},
    Context, Flush,
};
use mpz_core::{bitvec::BitVec, Block};
use mpz_garble_core::GeneratorOutput;
use mpz_memory_core::{binary::Binary, correlated::Delta, DecodeFuture, Memory, Slice, View};
use mpz_ot::cot::COTSender;
use mpz_vm_core::{Call, Callable, Execute, Result, VmError};

use crate::store::GeneratorStore;

/// Semi-honest generator.
#[derive(Debug)]
pub struct Generator<COT> {
    store: Arc<Mutex<GeneratorStore<COT>>>,
    call_stack: Vec<(Call, Slice)>,
    preprocessed: Vec<(Vec<Slice>, Slice)>,
}

impl<COT> Generator<COT> {
    /// Creates a new generator.
    pub fn new(cot: COT, seed: [u8; 16], delta: Delta) -> Self {
        Self {
            store: Arc::new(Mutex::new(GeneratorStore::new(seed, delta, cot))),
            call_stack: Vec::new(),
            preprocessed: Vec::new(),
        }
    }

    fn take_preprocess_calls(&mut self) -> Vec<(Call, Slice)> {
        let store = self.store.try_lock().unwrap();
        self.call_stack
            .filter_drain(|(call, _)| call.inputs().iter().all(|slice| store.is_set_keys(*slice)))
            .collect()
    }

    fn take_execute_calls(&mut self) -> Vec<(Call, Slice)> {
        let store = self.store.try_lock().unwrap();
        self.call_stack
            .filter_drain(|(call, _)| call.inputs().iter().all(|slice| store.is_committed(*slice)))
            .collect()
    }

    // Marks the outputs of preprocessed calls as executed.
    fn mark_executed(&mut self) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
        loop {
            let outputs = self
                .preprocessed
                .filter_drain(|(inputs, _)| inputs.iter().all(|input| store.is_committed(*input)))
                .map(|(_, output)| output)
                .collect::<Vec<_>>();

            if outputs.is_empty() {
                break;
            }

            for output in outputs {
                store
                    .mark_output_complete(output)
                    .map_err(VmError::memory)?;
            }
        }

        Ok(())
    }
}

impl<COT> Memory<Binary> for Generator<COT> {
    type Error = VmError;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store
            .try_lock()
            .unwrap()
            .alloc_raw(size)
            .map_err(VmError::memory)
    }

    fn assign_raw(&mut self, slice: Slice, value: BitVec) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .assign_raw(slice, value)
            .map_err(VmError::memory)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .commit_raw(slice)
            .map_err(VmError::memory)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .get_raw(slice)
            .map_err(VmError::memory)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .decode_raw(slice)
            .map_err(VmError::memory)
    }
}

impl<COT> View<Binary> for Generator<COT>
where
    COT: COTSender<Block>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_public_raw(slice)
            .map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_private_raw(slice)
            .map_err(VmError::view)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_blind_raw(slice)
            .map_err(VmError::view)
    }
}

impl<COT> Callable<Binary> for Generator<COT> {
    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let slice = self
            .store
            .try_lock()
            .unwrap()
            .alloc_output(call.circ().output_len());
        self.call_stack.push((call, slice));
        Ok(slice)
    }
}

#[async_trait]
impl<COT> Execute for Generator<COT>
where
    COT: COTSender<Block> + Flush + Send + 'static,
{
    fn wants_flush(&self) -> bool {
        self.store.try_lock().unwrap().wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
        if store.wants_flush() {
            store.flush(ctx).await.map_err(VmError::memory)?;
        }

        Ok(())
    }

    fn wants_preprocess(&self) -> bool {
        let store = self.store.try_lock().unwrap();
        self.call_stack
            .iter()
            .any(|(call, _)| call.inputs().iter().all(|slice| store.is_set_keys(*slice)))
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<()> {
        let delta = *self.store.try_lock().unwrap().delta();
        let store = self.store.clone();
        let f = scope_closure(move |ctx: &mut Context, (call, output): (Call, Slice)| {
            generate(ctx, store.clone(), delta, call, output, Mode::Preprocess).scope_boxed()
        });

        while !self.call_stack.is_empty() {
            let calls = self.take_preprocess_calls();

            if calls.is_empty() {
                break;
            } else {
                for (call, output) in &calls {
                    let inputs = call.inputs().to_vec();
                    self.preprocessed.push((inputs, *output));
                }
            }

            let outputs = ctx
                .map(calls, f.clone(), |(call, _)| call.circ().and_count())
                .await
                .map_err(VmError::execute)?;

            outputs.into_iter().collect::<Result<()>>()?;
        }

        Ok(())
    }

    fn wants_execute(&self) -> bool {
        let store = self.store.try_lock().unwrap();
        self.preprocessed
            .iter()
            .any(|(inputs, _)| inputs.iter().all(|input| store.is_committed(*input)))
            || self
                .call_stack
                .iter()
                .any(|(call, _)| call.inputs().iter().all(|slice| store.is_committed(*slice)))
    }

    async fn execute(&mut self, ctx: &mut Context) -> Result<()> {
        let delta = *self.store.try_lock().unwrap().delta();
        let store = self.store.clone();
        let f = scope_closure(move |ctx: &mut Context, (call, output): (Call, Slice)| {
            generate(ctx, store.clone(), delta, call, output, Mode::Execute).scope_boxed()
        });

        while !self.call_stack.is_empty() {
            let calls = self.take_execute_calls();

            if calls.is_empty() {
                break;
            }

            let outputs = ctx
                .map(calls, f.clone(), |(call, _)| call.circ().and_count())
                .await
                .map_err(VmError::execute)?;

            outputs.into_iter().collect::<Result<()>>()?;
        }

        self.mark_executed()?;

        Ok(())
    }
}

// This is required to help the compiler infer the correct lifetimes :(
fn scope_closure<Ctx, F, R>(f: F) -> F
where
    F: for<'a> Fn(&'a mut Ctx, (Call, Slice)) -> ScopedBoxFuture<'static, 'a, R>
        + Clone
        + Send
        + 'static,
{
    f
}

enum Mode {
    Preprocess,
    Execute,
}

async fn generate<COT>(
    ctx: &mut Context,
    store: Arc<Mutex<GeneratorStore<COT>>>,
    delta: Delta,
    call: Call,
    output: Slice,
    mode: Mode,
) -> Result<()> {
    let (circ, inputs) = call.into_parts();

    let mut input_keys = Vec::with_capacity(circ.input_len());
    {
        let lock = store.lock().await;
        for input in inputs {
            input_keys.extend_from_slice(lock.try_get_keys(input).map_err(VmError::memory)?);
        }
    }

    let GeneratorOutput {
        outputs: output_keys,
    } = crate::generator::generate(ctx, circ, delta, input_keys)
        .await
        .map_err(VmError::execute)?;

    let mut lock = store.lock().await;
    lock.set_output(output, &output_keys)
        .map_err(VmError::memory)?;

    if let Mode::Execute = mode {
        lock.mark_output_complete(output).map_err(VmError::memory)?;
    }

    Ok(())
}
