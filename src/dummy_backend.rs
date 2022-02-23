use std::sync::{Arc, RwLock};
use std::thread::spawn;
use log::{info, warn, error};
use std::{convert, io};

use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_net::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use vm_memory::{ GuestMemoryAtomic};
use vm_memory::bitmap::{Bitmap, AtomicBitmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};


use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use crate::i2c::{I2c, i2c_initialize};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

type Result<T> = std::result::Result<T, Error>;
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug, PartialEq, ThisError)]
/// Errors related to low level i2c helpers
pub enum Error {
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Invalid device list")]
    DeviceListInvalid,
    #[error("Duplicate adapter detected: {0}")]
    AdapterDuplicate(u32),
    #[error("Invalid client address: {0}")]
    ClientAddressInvalid(u16),
    #[error("Duplicate client address detected: {0}")]
    ClientAddressDuplicate(u16),
    #[error("Failed to join threads")]
    FailedJoiningThreads,
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
    #[error("Received unexpected write only descriptor at index {0}")]
    UnexpectedWriteOnlyDescriptor(usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Invalid descriptor count {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, u32),
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("Failed to create new EventFd")]
    EventFdFailed,
}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

pub fn start_backend() -> Result<()> {
    let socket = "/home/vireshk/junk/vi2c.sock-dummy";

    spawn(move || loop {
        // A separate thread is spawned for each socket and can connect to a separate guest.
        // These are run in an infinite loop to not require the daemon to be restarted once a
        // guest exits.
        //
        // There isn't much value in complicating code here to return an error from the
        // threads, and so the code uses unwrap() instead. The panic on a thread won't cause
        // trouble to other threads/guests or the main() function and should be safe for the
        // daemon.
        let backend = Arc::new(RwLock::new(VhostUserI2cBackend::new().unwrap()));
        let listener = Listener::new(socket.clone(), true).unwrap();

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-i2c-backend"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        daemon.start(listener).unwrap();

        match daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly.");
            }
            Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage,
                    )) => {
                info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        backend.read().unwrap().exit_event.write(1).unwrap();
    }).join().unwrap();

    Ok(())
}

/// Virtio I2C Feature bits
const VIRTIO_I2C_F_ZERO_LENGTH_REQUEST: u16 = 0;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

pub struct VhostUserI2cBackend<> {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    base: u32,
    event_idx: bool,
    pub exit_event: EventFd,
    i2c: Option<I2c>,
}

impl VhostUserI2cBackend {
    pub fn new() -> Result<Self> {
        Ok(VhostUserI2cBackend {
            mem: None,
            base: 0,
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            i2c: None,
        })
    }
}

/// VhostUserBackendMut trait methods
impl VhostUserBackendMut<VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>, AtomicBitmap>
 for VhostUserI2cBackend

{
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        // this matches the current libvhost defaults except VHOST_F_LOG_ALL
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_I2C_F_ZERO_LENGTH_REQUEST
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        dbg!(self.event_idx = enabled);
    }

    fn update_memory(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> VhostUserBackendResult<()> {
        self.mem = Some(mem.clone());
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            0 => {
                let vring = &vrings[0];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();

                        self.i2c.as_ref().unwrap().kick();
                        self.i2c.as_ref().unwrap().call();
                        vring.signal_used_queue().unwrap();

                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                        self.i2c.as_ref().unwrap().kick();
                        self.i2c.as_ref().unwrap().call();
                        vring.signal_used_queue().unwrap();
                }
            }
            _ => {
                warn!("unhandled device_event: {}", device_event);
                return Err(Error::HandleEventUnknown.into());
            }
        }
        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }

    fn set_vring_base(&mut self, index: u32, base: u32) {
        self.base = base
    }
    fn set_vring_addr(&mut self, index: u32, descriptor: u64, used: u64, available: u64) {
        self.i2c = Some(i2c_initialize(self.mem.as_ref().unwrap().clone(), index, self.base, descriptor, used, available));
    }
}
