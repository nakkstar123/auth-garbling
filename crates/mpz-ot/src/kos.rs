//! [`KOS15`](https://eprint.iacr.org/2015/546.pdf) oblivious transfer extension protocol.

mod receiver;
mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

pub use mpz_ot_core::kos::{
    msgs, ReceiverConfig, ReceiverConfigBuilder, ReceiverConfigBuilderError, SenderConfig,
    SenderConfigBuilder, SenderConfigBuilderError,
};

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    use crate::{ideal::ot::ideal_ot, test::test_rcot};

    #[tokio::test]
    async fn test_kos_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (base_sender, base_receiver) = ideal_ot();
        let delta = Block::random(&mut rng);
        let sender = Sender::new(SenderConfig::default(), delta, base_receiver);
        let receiver = Receiver::new(ReceiverConfig::default(), base_sender);

        test_rcot(sender, receiver, 1).await;
    }
}
