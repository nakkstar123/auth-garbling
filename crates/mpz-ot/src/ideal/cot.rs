//! Ideal functionality for correlated OT.

use async_trait::async_trait;
use mpz_common::Flush;
use mpz_core::Block;
use mpz_ot_core::{
    cot::{COTReceiver, COTSender},
    ideal::cot::{IdealCOT as Core, IdealCOTError as CoreError},
};

/// Returns a new ideal COT sender and receiver.
pub fn ideal_cot(delta: Block) -> (IdealCOTSender, IdealCOTReceiver) {
    let core = Core::new(delta);
    (
        IdealCOTSender { core: core.clone() },
        IdealCOTReceiver { core },
    )
}

/// Ideal COT sender.
pub struct IdealCOTSender {
    core: Core,
}

impl COTSender<Block> for IdealCOTSender {
    type Error = IdealCOTError;
    type Future = <Core as COTSender<Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        COTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        COTSender::available(&self.core)
    }

    fn delta(&self) -> Block {
        COTSender::delta(&self.core)
    }

    fn queue_send_cot(&mut self, msgs: &[Block]) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_cot(msgs).map_err(From::from)
    }
}

#[async_trait]
impl<Ctx> Flush<Ctx> for IdealCOTSender {
    type Error = IdealCOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealCOTError::from)?;
        }

        Ok(())
    }
}

/// Ideal COT receiver.
pub struct IdealCOTReceiver {
    core: Core,
}

impl COTReceiver<bool, Block> for IdealCOTReceiver {
    type Error = IdealCOTError;
    type Future = <Core as COTReceiver<bool, Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        COTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        COTReceiver::available(&self.core)
    }

    fn queue_recv_cot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_cot(choices).map_err(From::from)
    }
}

#[async_trait]
impl<Ctx> Flush<Ctx> for IdealCOTReceiver {
    type Error = IdealCOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealCOTError::from)?;
        }

        Ok(())
    }
}

/// Ideal COT error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IdealCOTError(#[from] CoreError);

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::test::test_cot;

    #[tokio::test]
    async fn test_ideal_cot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (sender, receiver) = ideal_cot(rng.gen());
        test_cot(sender, receiver, 8).await;
    }
}
