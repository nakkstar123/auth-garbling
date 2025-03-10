//! Ideal functionality for random correlated OT.

use async_trait::async_trait;

use mpz_common::{
    ideal::{call_sync, CallSync},
    Context, Flush,
};
use mpz_core::Block;
use mpz_ot_core::{
    ideal::rcot::{IdealRCOT as Core, IdealRCOTError as CoreError},
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};

/// Returns a new ideal RCOT sender and receiver.
pub fn ideal_rcot(seed: Block, delta: Block) -> (IdealRCOTSender, IdealRCOTReceiver) {
    let core = Core::new(seed, delta);
    let (sync_0, sync_1) = call_sync();
    (
        IdealRCOTSender {
            core: core.clone(),
            sync: sync_0,
        },
        IdealRCOTReceiver { core, sync: sync_1 },
    )
}

/// Ideal RCOT sender.
pub struct IdealRCOTSender {
    core: Core,
    sync: CallSync,
}

impl RCOTSender<Block> for IdealRCOTSender {
    type Error = IdealRCOTError;
    type Future = <Core as RCOTSender<Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        RCOTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        RCOTSender::available(&self.core)
    }

    fn delta(&self) -> Block {
        RCOTSender::delta(&self.core)
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        self.core.try_send_rcot(count).map_err(From::from)
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_rcot(count).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealRCOTSender {
    type Error = IdealRCOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealRCOTError::from))
                .await
                .transpose()?;
        }

        Ok(())
    }
}

/// Ideal RCOT receiver.
pub struct IdealRCOTReceiver {
    core: Core,
    sync: CallSync,
}

impl RCOTReceiver<bool, Block> for IdealRCOTReceiver {
    type Error = IdealRCOTError;
    type Future = <Core as RCOTReceiver<bool, Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        RCOTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        RCOTReceiver::available(&self.core)
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        self.core.try_recv_rcot(count).map_err(From::from)
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_rcot(count).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealRCOTReceiver {
    type Error = IdealRCOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealRCOTError::from))
                .await
                .transpose()?;
        }

        Ok(())
    }
}

/// Ideal RCOT error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IdealRCOTError(#[from] CoreError);

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::test::test_rcot;

    #[tokio::test]
    async fn test_ideal_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (sender, receiver) = ideal_rcot(rng.gen(), rng.gen());
        test_rcot(sender, receiver, 8).await;
    }
}
