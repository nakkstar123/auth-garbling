use async_trait::async_trait;
use rand::{thread_rng, Rng};
use serio::SinkExt as _;

use mpz_cointoss::{self as cointoss, cointoss_sender};
use mpz_common::{future::MaybeDone, Context, ContextError, Flush};
use mpz_core::Block;
use mpz_ot_core::{
    kos::{receiver_state as state, Receiver as Core, ReceiverConfig, ReceiverError as CoreError},
    ot::OTSender,
    rcot::{RCOTReceiver, RCOTReceiverOutput},
};

type Error = ReceiverError;

#[derive(Debug)]
enum State<BaseOT> {
    Initialized {
        base_ot: BaseOT,
        receiver: Core<state::Initialized>,
    },
    Extension(Core<state::Extension>),
    Error,
}

impl<BaseOT> State<BaseOT> {
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

/// KOS receiver.
#[derive(Debug)]
pub struct Receiver<BaseOT> {
    state: State<BaseOT>,
}

impl<BaseOT> Receiver<BaseOT> {
    /// Creates a new Receiver
    ///
    /// # Arguments
    ///
    /// * `config` - The Receiver's configuration.
    /// * `base_ot` - Base OT.
    pub fn new(config: ReceiverConfig, base_ot: BaseOT) -> Self {
        Self {
            state: State::Initialized {
                base_ot,
                receiver: Core::new(config),
            },
        }
    }
}

impl<BaseOT> RCOTReceiver<bool, Block> for Receiver<BaseOT> {
    type Error = Error;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        match &mut self.state {
            State::Initialized { receiver, .. } => receiver.alloc(count).map_err(Error::from),
            State::Extension(receiver) => receiver.alloc(count).map_err(Error::from),
            State::Error => Err(Error::state("can not allocate, receiver in error state")),
        }
    }

    fn available(&self) -> usize {
        match &self.state {
            State::Initialized { .. } | State::Error => 0,
            State::Extension(receiver) => receiver.available(),
        }
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        match &mut self.state {
            State::Initialized { receiver, .. } => {
                receiver.try_recv_rcot(count).map_err(Error::from)
            }
            State::Extension(receiver) => receiver.try_recv_rcot(count).map_err(Error::from),
            State::Error => Err(Error::state("can not send, receiver in error state")),
        }
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        match &mut self.state {
            State::Initialized { receiver, .. } => {
                receiver.queue_recv_rcot(count).map_err(Error::from)
            }
            State::Extension(receiver) => receiver.queue_recv_rcot(count).map_err(Error::from),
            State::Error => Err(Error::state("can not queue, receiver in error state")),
        }
    }
}

#[async_trait]
impl<Ctx, BaseOT> Flush<Ctx> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: OTSender<Block> + Flush<Ctx> + Send,
{
    type Error = Error;

    fn wants_flush(&self) -> bool {
        match &self.state {
            State::Initialized { .. } => true,
            State::Extension(receiver) => receiver.wants_extend(),
            State::Error => false,
        }
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        let mut receiver = match self.state.take() {
            State::Initialized {
                mut base_ot,
                receiver,
            } => {
                let (receiver, seeds) = {
                    let mut rng = thread_rng();
                    let seeds = std::array::from_fn(|_| rng.gen());
                    (receiver.setup(seeds), seeds)
                };

                _ = base_ot.queue_send_ot(&seeds).map_err(Error::base_ot)?;
                base_ot.flush(ctx).await.map_err(Error::base_ot)?;

                receiver
            }
            State::Extension(receiver) => receiver,
            State::Error => return Err(Error::state("can not flush, receiver in error state")),
        };

        if !receiver.wants_extend() {
            self.state = State::Extension(receiver);
            return Ok(());
        }

        while receiver.wants_extend() {
            let extend = receiver.extend()?;
            ctx.io_mut().send(extend).await?;
        }

        let seed = thread_rng().gen();

        // See issue #176.
        let chi_seed = cointoss_sender(ctx, vec![seed]).await?[0];

        let receiver_check = receiver.check(chi_seed)?;

        ctx.io_mut().send(receiver_check).await?;

        self.state = State::Extension(receiver);

        Ok(())
    }
}

/// Error for [`Receiver`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverError(#[from] ErrorRepr);

impl ReceiverError {
    fn base_ot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::BaseOT(err.into()))
    }

    fn state(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::State(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("base OT error: {0}")]
    BaseOT(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("cointoss error: {0}")]
    Cointoss(#[from] cointoss::CointossError),
    #[error("state error: {0}")]
    State(String),
    #[error("context error: {0}")]
    Context(#[from] ContextError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for ReceiverError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<cointoss::CointossError> for ReceiverError {
    fn from(err: cointoss::CointossError) -> Self {
        Self(ErrorRepr::Cointoss(err))
    }
}

impl From<ContextError> for ReceiverError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}

impl From<std::io::Error> for ReceiverError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}
