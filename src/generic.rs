use log::{error};
use seccompiler::SeccompAction;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::vec::Vec;

use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vhost::vhost_user::{MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler};
use virtio_queue::Queue;
use vm_memory::GuestMemoryAtomic;
use vmm_sys_util::eventfd::EventFd;

use crate::{ActivateResult, VirtioCommon, VirtioDevice, VirtioDeviceType};
use crate::{VhostUserConfig, VhostUserHandle};
use crate::VhostUserCommon;
use crate::{Error, Result};
use crate::Thread;
use crate::spawn_virtio_thread;
use crate::VirtioInterrupt;
use crate::{GuestMemoryMmap, GuestRegionMmap};

const MIN_NUM_QUEUES: usize = 1;

pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub vu_num_queues: usize,
}

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Generic {
    common: VirtioCommon,
    vu_common: VhostUserCommon,
    id: String,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    epoll_thread: Option<thread::JoinHandle<()>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    device_features: u64,
    num_queues: u32,
    name: String,
}

impl Generic {
    /// Create a new vhost-user-blk device
    pub fn new(
        vu_cfg: VhostUserConfig,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
    ) -> Result<Generic> {
        let queue_sizes = vu_cfg.device_type.queue_sizes();
        let num_queues = queue_sizes.len();

        let vu =
            VhostUserHandle::connect_vhost_user(false, &vu_cfg.socket, num_queues as u64, false)?;
        let device_features = vu.device_features()?;

        Ok(Generic {
            common: VirtioCommon {
                device_type: vu_cfg.device_type,
                queue_sizes,
                avail_features: 0,
                acked_features: 0,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: MIN_NUM_QUEUES as u16,
                ..Default::default()
            },
            vu_common: VhostUserCommon {
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features: 0,
                socket_path: vu_cfg.socket,
                vu_num_queues: num_queues,
                ..Default::default()
            },
            id: "generic_device".to_string(),
            guest_memory: None,
            epoll_thread: None,
            seccomp_action,
            exit_evt,
            device_features,
            num_queues: 0,
            name: String::from(vu_cfg.device_type),
        })
    }

    pub fn device_features(&self) -> u64 {
        self.device_features
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn negotiate_features(
        &mut self,
        avail_features: u64,
    ) -> Result<(u64, u64)> {
        let mut vu = self.vu_common.vu.as_ref().unwrap().lock().unwrap();
        let avail_protocol_features = VhostUserProtocolFeatures::MQ;

        let (acked_features, acked_protocol_features) =
            vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

        let backend_num_queues =
            if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                vu.socket_handle()
                    .get_queue_num()
                    .map_err(Error::VhostUserGetQueueMaxNum)? as usize
            } else {
                MIN_NUM_QUEUES
            };

        if self.vu_common.vu_num_queues > backend_num_queues {
            error!("vhost-user-device requested too many queues ({}) since the backend only supports {}\n",
                self.vu_common.vu_num_queues, backend_num_queues);
            return Err(Error::BadQueueNum);
        }

        self.common.acked_features = acked_features;
        self.vu_common.acked_protocol_features = acked_protocol_features;
        self.num_queues = backend_num_queues as u32;

        Ok((acked_features, acked_protocol_features))
    }

    pub fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            acked_protocol_features: self.vu_common.acked_protocol_features,
            vu_num_queues: self.vu_common.vu_num_queues,
        }
    }

    pub fn set_state(&mut self, state: &State) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        self.vu_common.acked_protocol_features = state.acked_protocol_features;
        self.vu_common.vu_num_queues = state.vu_num_queues;

        if let Err(e) = self
            .vu_common
            .restore_backend_connection(self.common.acked_features)
        {
            error!(
                "Failed restoring connection with vhost-user backend: {:?}",
                e
            );
        }
    }
}

impl Drop for Generic {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to kill vhost-user-blk: {:?}", e);
            }
        }
    }
}

impl VirtioDevice for Generic {
    fn device_type(&self) -> VirtioDeviceType {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        self.guest_memory = Some(mem.clone());

        let slave_req_handler: Option<MasterReqHandler<SlaveReqHandler>> = None;

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let mut handler = self.vu_common.activate(
            mem,
            queues,
            queue_evts,
            interrupt_cb,
            self.common.acked_features,
            slave_req_handler,
            kill_evt,
            pause_evt,
        )?;

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        let mut epoll_threads = Vec::new();

        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostBlock,
            &mut epoll_threads,
            &self.exit_evt,
            move || {
                if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running worker: {:?}", e);
                }
            },
        )?;
        self.epoll_thread = Some(epoll_threads.remove(0));

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        if let Some(vu) = &self.vu_common.vu {
            if let Err(e) = vu
                .lock()
                .unwrap()
                .reset_vhost_user(self.common.queue_sizes.len())
            {
                error!("Failed to reset vhost-user daemon: {:?}", e);
                return None;
            }
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown()
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), Error> {
        self.vu_common.add_memory_region(&self.guest_memory, region)
    }
}
