pub mod vu_common_ctrl;

use libc::EFD_NONBLOCK;
use log::{warn, error, info};
use seccompiler::SeccompAction;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::io;
use std::io::Write;
use std::num::Wrapping;
use std::ops::Deref;
use std::{
    panic::AssertUnwindSafe,
    thread::{self, JoinHandle},
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Barrier, Mutex
};
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use vhost::Error as VhostError;
use vhost::vhost_user::{MasterReqHandler, VhostUserMasterReqHandler};
use vhost::vhost_user::message::{
    VhostUserInflight, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use virtio_queue::Error as QueueError;
use virtio_queue::Queue;
use vm_memory::{
    bitmap::AtomicBitmap, mmap::MmapRegionError, Error as MmapError, GuestAddress, GuestAddressSpace, GuestMemory,
    GuestMemoryAtomic, GuestUsize
};
use vmm_sys_util::eventfd::EventFd;

use crate::vhost_user::vu_common_ctrl::VhostUserHandle;

pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;
pub type MmapRegion = vm_memory::MmapRegion<AtomicBitmap>;
pub type MmapRegionBuilder = vm_memory::mmap::MmapRegionBuilder<AtomicBitmap>;

const VIRTIO_F_RING_INDIRECT_DESC: u32 = 28;
const VIRTIO_F_RING_EVENT_IDX: u32 = 29;
const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_IN_ORDER: u32 = 35;
const VIRTIO_F_ORDER_PLATFORM: u32 = 36;
#[allow(dead_code)]
const VIRTIO_F_SR_IOV: u32 = 37;
const VIRTIO_F_NOTIFICATION_DATA: u32 = 38;

pub const DEFAULT_VIRTIO_FEATURES: u64 = 1 << VIRTIO_F_RING_INDIRECT_DESC
    | 1 << VIRTIO_F_RING_EVENT_IDX
    | 1 << VIRTIO_F_VERSION_1
    | 1 << VIRTIO_F_IN_ORDER
    | 1 << VIRTIO_F_ORDER_PLATFORM
    | 1 << VIRTIO_F_NOTIFICATION_DATA
    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

#[derive(Debug)]
pub enum Error {
    /// Failed accepting connection.
    AcceptConnection(io::Error),
    /// Invalid available address.
    AvailAddress,
    /// Queue number  is not correct
    BadQueueNum,
    /// Failed binding vhost-user socket.
    BindSocket(io::Error),
    /// Creating kill eventfd failed.
    CreateKillEventFd(io::Error),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(io::Error),
    /// Invalid descriptor table address.
    DescriptorTableAddress,
    /// Signal used queue failed.
    FailedSignalingUsedQueue(io::Error),
    /// Failed to read vhost eventfd.
    MemoryRegions(MmapError),
    /// Failed removing socket path
    RemoveSocketPath(io::Error),
    /// Failed to create master.
    VhostUserCreateMaster(VhostError),
    /// Failed to open vhost device.
    VhostUserOpen(VhostError),
    /// Connection to socket failed.
    VhostUserConnect,
    /// Get features failed.
    VhostUserGetFeatures(VhostError),
    /// Get queue max number failed.
    VhostUserGetQueueMaxNum(VhostError),
    /// Get protocol features failed.
    VhostUserGetProtocolFeatures(VhostError),
    /// Get vring base failed.
    VhostUserGetVringBase(VhostError),
    /// Vhost-user Backend not support vhost-user protocol.
    VhostUserProtocolNotSupport,
    /// Set owner failed.
    VhostUserSetOwner(VhostError),
    /// Reset owner failed.
    VhostUserResetOwner(VhostError),
    /// Set features failed.
    VhostUserSetFeatures(VhostError),
    /// Set protocol features failed.
    VhostUserSetProtocolFeatures(VhostError),
    /// Set mem table failed.
    VhostUserSetMemTable(VhostError),
    /// Set vring num failed.
    VhostUserSetVringNum(VhostError),
    /// Set vring addr failed.
    VhostUserSetVringAddr(VhostError),
    /// Set vring base failed.
    VhostUserSetVringBase(VhostError),
    /// Set vring call failed.
    VhostUserSetVringCall(VhostError),
    /// Set vring kick failed.
    VhostUserSetVringKick(VhostError),
    /// Set vring enable failed.
    VhostUserSetVringEnable(VhostError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(io::Error),
    /// Failed to read vhost eventfd.
    VhostIrqRead(io::Error),
    /// Failed to read vhost eventfd.
    VhostUserMemoryRegion(MmapError),
    /// Failed to create the master request handler from slave.
    MasterReqHandlerCreation(vhost::vhost_user::Error),
    /// Set slave request fd failed.
    VhostUserSetSlaveRequestFd(vhost::Error),
    /// Add memory region failed.
    VhostUserAddMemReg(VhostError),
    /// Failed getting the configuration.
    VhostUserGetConfig(VhostError),
    /// Failed setting the configuration.
    VhostUserSetConfig(VhostError),
    /// Failed getting inflight shm log.
    VhostUserGetInflight(VhostError),
    /// Failed setting inflight shm log.
    VhostUserSetInflight(VhostError),
    /// Failed setting the log base.
    VhostUserSetLogBase(VhostError),
    /// Invalid used address.
    UsedAddress,
    /// Invalid features provided from vhost-user backend
    InvalidFeatures,
    /// Missing file descriptor for the region.
    MissingRegionFd,
    /// Missing IrqFd
    MissingIrqFd,
    /// Failed getting the available index.
    GetAvailableIndex(QueueError),
    /// Migration is not supported by this vhost-user device.
    MigrationNotSupported,
    /// Failed creating memfd.
    MemfdCreate(io::Error),
    /// Failed truncating the file size to the expected size.
    SetFileSize(io::Error),
    /// Failed to set the seals on the file.
    SetSeals(io::Error),
    /// Failed creating new mmap region
    NewMmapRegion(MmapRegionError),
    /// Could not find the shm log region
    MissingShmLogRegion,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum ActivateError {
    EpollCtl(std::io::Error),
    BadActivate,
    /// Queue number is not correct
    BadQueueNum,
    /// Failed to clone Kill event fd
    CloneKillEventFd,
    /// Failed to clone exit event fd
    CloneExitEventFd(std::io::Error),
    // Failed to spawn thread
    ThreadSpawn(std::io::Error),
    /// Failed to create Vhost-user interrupt eventfd
    VhostIrqCreate,
    /// Failed to setup vhost-user-fs daemon.
    VhostUserFsSetup(Error),
    /// Failed to setup vhost-user-net daemon.
    VhostUserNetSetup(Error),
    /// Failed to setup vhost-user-blk daemon.
    VhostUserBlkSetup(Error),
    /// Failed to reset vhost-user daemon.
    VhostUserReset(Error),
    /// Cannot create rate limiter
    CreateRateLimiter(std::io::Error),
}

// Types taken from linux/virtio_ids.h
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub enum VirtioDeviceType {
    Net = 1,
    Block = 2,
    Console = 3,
    Rng = 4,
    Balloon = 5,
    Fs9P = 9,
    Gpu = 16,
    Input = 18,
    Vsock = 19,
    Iommu = 23,
    Mem = 24,
    Fs = 26,
    Pmem = 27,
    I2c = 34,
    Watchdog = 35, // Temporary until official number allocated
    Gpio = 41,
    Unknown = 0xFF,
}

impl From<u32> for VirtioDeviceType {
    fn from(t: u32) -> Self {
        match t {
            1 => VirtioDeviceType::Net,
            2 => VirtioDeviceType::Block,
            3 => VirtioDeviceType::Console,
            4 => VirtioDeviceType::Rng,
            5 => VirtioDeviceType::Balloon,
            9 => VirtioDeviceType::Fs9P,
            16 => VirtioDeviceType::Gpu,
            18 => VirtioDeviceType::Input,
            19 => VirtioDeviceType::Vsock,
            23 => VirtioDeviceType::Iommu,
            24 => VirtioDeviceType::Mem,
            26 => VirtioDeviceType::Fs,
            27 => VirtioDeviceType::Pmem,
            34 => VirtioDeviceType::I2c,
            35 => VirtioDeviceType::Watchdog,
            41 => VirtioDeviceType::Gpio,
            _ => VirtioDeviceType::Unknown,
        }
    }
}

// In order to use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type VirtioDeviceType.
impl fmt::Display for VirtioDeviceType {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = match *self {
            VirtioDeviceType::Net => "net",
            VirtioDeviceType::Block => "block",
            VirtioDeviceType::Console => "console",
            VirtioDeviceType::Rng => "rng",
            VirtioDeviceType::Balloon => "balloon",
            VirtioDeviceType::Gpu => "gpu",
            VirtioDeviceType::Fs9P => "9p",
            VirtioDeviceType::Input => "input",
            VirtioDeviceType::Vsock => "vsock",
            VirtioDeviceType::Iommu => "iommu",
            VirtioDeviceType::Mem => "mem",
            VirtioDeviceType::Fs => "fs",
            VirtioDeviceType::Pmem => "pmem",
            VirtioDeviceType::I2c => "i2c",
            VirtioDeviceType::Watchdog => "watchdog",
            VirtioDeviceType::Gpio => "gpio",
            VirtioDeviceType::Unknown => "unknown",
        };
        write!(f, "{}", output)
    }
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

const HUP_CONNECTION_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const SLAVE_REQ_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

#[derive(Default)]
pub struct Inflight {
    pub info: VhostUserInflight,
    pub fd: Option<std::fs::File>,
}

pub struct EpollHelper {
    pause_evt: EventFd,
    epoll_file: File,
}

#[derive(Debug)]
pub enum EpollHelperError {
    CreateFd(std::io::Error),
    Ctl(std::io::Error),
    IoError(std::io::Error),
    Wait(std::io::Error),
    QueueRingIndex(virtio_queue::Error),
}

pub const EPOLL_HELPER_EVENT_PAUSE: u16 = 0;
pub const EPOLL_HELPER_EVENT_KILL: u16 = 1;
pub const EPOLL_HELPER_EVENT_LAST: u16 = 15;

pub trait EpollHelperHandler {
    // Return true if the loop execution should be stopped
    fn handle_event(&mut self, helper: &mut EpollHelper, event: &epoll::Event) -> bool;
}

impl EpollHelper {
    pub fn new(
        kill_evt: &EventFd,
        pause_evt: &EventFd,
    ) -> std::result::Result<Self, EpollHelperError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(EpollHelperError::CreateFd)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        let mut helper = Self {
            pause_evt: pause_evt.try_clone().unwrap(),
            epoll_file,
        };

        helper.add_event(kill_evt.as_raw_fd(), EPOLL_HELPER_EVENT_KILL)?;
        helper.add_event(pause_evt.as_raw_fd(), EPOLL_HELPER_EVENT_PAUSE)?;
        Ok(helper)
    }

    pub fn add_event(&mut self, fd: RawFd, id: u16) -> std::result::Result<(), EpollHelperError> {
        self.add_event_custom(fd, id, epoll::Events::EPOLLIN)
    }

    pub fn add_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> std::result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn del_event_custom(
        &mut self,
        fd: RawFd,
        id: u16,
        evts: epoll::Events,
    ) -> std::result::Result<(), EpollHelperError> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(evts, id.into()),
        )
        .map_err(EpollHelperError::Ctl)
    }

    pub fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
        handler: &mut dyn EpollHelperHandler,
    ) -> std::result::Result<(), EpollHelperError> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        // Before jumping into the epoll loop, check if the device is expected
        // to be in a paused state. This is helpful for the restore code path
        // as the device thread should not start processing anything before the
        // device has been resumed.
        while paused.load(Ordering::SeqCst) {
            thread::park();
        }

        loop {
            let num_events = match epoll::wait(self.epoll_file.as_raw_fd(), -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(EpollHelperError::Wait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    EPOLL_HELPER_EVENT_KILL => {
                        info!("KILL_EVENT received, stopping epoll loop");
                        return Ok(());
                    }
                    EPOLL_HELPER_EVENT_PAUSE => {
                        info!("PAUSE_EVENT received, pausing epoll loop");

                        // Acknowledge the pause is effective by using the
                        // paused_sync barrier.
                        paused_sync.wait();

                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }

                        // Drain pause event after the device has been resumed.
                        // This ensures the pause event has been seen by each
                        // thread related to this virtio device.
                        let _ = self.pause_evt.read();
                    }
                    _ => {
                        if handler.handle_event(self, event) {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

impl AsRawFd for EpollHelper {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }
}
pub struct VhostUserEpollHandler<S: VhostUserMasterReqHandler> {
    pub vu: Arc<Mutex<VhostUserHandle>>,
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
    pub queue_evts: Vec<EventFd>,
    pub virtio_interrupt: Arc<dyn VirtioInterrupt>,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub socket_path: String,
    pub server: bool,
    pub slave_req_handler: Option<MasterReqHandler<S>>,
    pub inflight: Option<Inflight>,
}

impl<S: VhostUserMasterReqHandler> VhostUserEpollHandler<S> {
    pub fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> std::result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event_custom(
            self.vu.lock().unwrap().socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        if let Some(slave_req_handler) = &self.slave_req_handler {
            helper.add_event(slave_req_handler.as_raw_fd(), SLAVE_REQ_EVENT)?;
        }

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn reconnect(&mut self, helper: &mut EpollHelper) -> std::result::Result<(), EpollHelperError> {
        helper.del_event_custom(
            self.vu.lock().unwrap().socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        let mut vhost_user = VhostUserHandle::connect_vhost_user(
            self.server,
            &self.socket_path,
            self.queues.len() as u64,
            true,
        )
        .map_err(|e| {
            EpollHelperError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed connecting vhost-user backend{:?}", e),
            ))
        })?;

        // Initialize the backend
        vhost_user
            .reinitialize_vhost_user(
                self.mem.memory().deref(),
                self.queues.clone(),
                self.queue_evts
                    .iter()
                    .map(|q| q.try_clone().unwrap())
                    .collect(),
                &self.virtio_interrupt,
                self.acked_features,
                self.acked_protocol_features,
                &self.slave_req_handler,
                self.inflight.as_mut(),
            )
            .map_err(|e| {
                EpollHelperError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed reconnecting vhost-user backend{:?}", e),
                ))
            })?;

        helper.add_event_custom(
            vhost_user.socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        // Update vhost-user reference
        let mut vu = self.vu.lock().unwrap();
        *vu = vhost_user;

        Ok(())
    }
}

impl<S: VhostUserMasterReqHandler> EpollHelperHandler for VhostUserEpollHandler<S> {
    fn handle_event(&mut self, helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            HUP_CONNECTION_EVENT => {
                if let Err(e) = self.reconnect(helper) {
                    error!("failed to reconnect vhost-user backend: {:?}", e);
                    return true;
                }
            }
            SLAVE_REQ_EVENT => {
                if let Some(slave_req_handler) = self.slave_req_handler.as_mut() {
                    if let Err(e) = slave_req_handler.handle_request() {
                        error!("Failed to handle request from vhost-user backend: {:?}", e);
                        return true;
                    }
                }
            }
            _ => {
                error!("Unknown event for vhost-user thread");
                return true;
            }
        }

        false
    }
}

/// Convert an absolute address into an address space (GuestMemory)
/// to a host pointer and verify that the provided size define a valid
/// range within a single memory region.
/// Return None if it is out of bounds or if addr+size overlaps a single region.
pub fn get_host_address_range<M: GuestMemory>(
    mem: &M,
    addr: GuestAddress,
    size: usize,
) -> Option<*mut u8> {
    if mem.check_range(addr, size) {
        Some(mem.get_host_address(addr).unwrap())
    } else {
        None
    }
}

pub enum VirtioInterruptType {
    Config,
    Queue(u16),
}

pub trait VirtioInterrupt: Send + Sync {
    fn trigger(&self, int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error>;
    fn notifier(&self, _int_type: VirtioInterruptType) -> Option<EventFd> {
        None
    }
}

pub struct NoopVirtioInterrupt {
    irq_fd: EventFd,
}

impl NoopVirtioInterrupt {
    pub fn new() -> NoopVirtioInterrupt {
        NoopVirtioInterrupt {
            irq_fd: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }

    pub fn new_with_eventfd(fd: EventFd) -> NoopVirtioInterrupt {
        NoopVirtioInterrupt {
            irq_fd: fd,
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            irq_fd: self.irq_fd.try_clone().unwrap()
        }
    }

    pub fn public_notifier(&self) -> EventFd {
        self.irq_fd.try_clone().unwrap()
    }
}

impl VirtioInterrupt for NoopVirtioInterrupt {
    fn trigger(
        &self,
        _int_type: VirtioInterruptType,
        ) -> std::result::Result<(), std::io::Error> {
        self.irq_fd.write(1)
    }

    fn notifier(&self, _int_type: VirtioInterruptType) -> Option<EventFd> {
        Some(
            self.irq_fd
                .try_clone()
                .expect("Failed cloning interrupt's EventFd"),
        )
    }
}

#[derive(Clone)]
pub struct UserspaceMapping {
    pub host_addr: u64,
    pub mem_slot: u32,
    pub addr: GuestAddress,
    pub len: GuestUsize,
    pub mergeable: bool,
}

#[derive(Clone)]
pub struct VirtioSharedMemory {
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone)]
pub struct VirtioSharedMemoryList {
    pub host_addr: u64,
    pub mem_slot: u32,
    pub addr: GuestAddress,
    pub len: GuestUsize,
    pub region_list: Vec<VirtioSharedMemory>,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The set of feature bits that this device supports.
    fn features(&self) -> u64 {
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, value: u64) {
        let _ = value;
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        warn!(
            "No readable configuration fields for {}",
            VirtioDeviceType::from(self.device_type())
        );
    }

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        warn!(
            "No writable configuration fields for {}",
            VirtioDeviceType::from(self.device_type())
        );
    }

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_evt: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        None
    }

    /// Returns the list of shared memory regions required by the device.
    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        None
    }

    /// Updates the list of shared memory regions required by the device.
    fn set_shm_regions(
        &mut self,
        _shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), Error> {
        std::unimplemented!()
    }

    /// Some devices may need to do some explicit shutdown work. This method
    /// may be implemented to do this. The VMM should call shutdown() on
    /// every device as part of shutting down the VM. Acting on the device
    /// after a shutdown() can lead to unpredictable results.
    fn shutdown(&mut self) {}

    fn add_memory_region(
        &mut self,
        _region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), Error> {
        Ok(())
    }

    /// Returns the list of userspace mappings associated with this device.
    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        Vec::new()
    }

    /// Return the counters that this device exposes
    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        None
    }

    /// Helper to allow common implementation of read_config
    fn read_config_from_slice(&self, config: &[u8], offset: u64, mut data: &mut [u8]) {
        let config_len = config.len() as u64;
        let data_len = data.len() as u64;
        if offset + data_len > config_len {
            error!(
                "Out-of-bound access to configuration: config_len = {} offset = {:x} length = {} for {}",
                config_len,
                offset,
                data_len,
                self.device_type()
            );
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config[offset as usize..std::cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    /// Helper to allow common implementation of write_config
    fn write_config_helper(&self, config: &mut [u8], offset: u64, data: &[u8]) {
        let config_len = config.len() as u64;
        let data_len = data.len() as u64;
        if offset + data_len > config_len {
            error!(
                    "Out-of-bound access to configuration: config_len = {} offset = {:x} length = {} for {}",
                    config_len,
                    offset,
                    data_len,
                    self.device_type()
                );
            return;
        }

        if let Some(end) = offset.checked_add(config.len() as u64) {
            let mut offset_config =
                &mut config[offset as usize..std::cmp::min(end, config_len) as usize];
            offset_config.write_all(data).unwrap();
        }
    }
}

/// Trait providing address translation the same way a physical DMA remapping
/// table would provide translation between an IOVA and a physical address.
/// The goal of this trait is to be used by virtio devices to perform the
/// address translation before they try to read from the guest physical address.
/// On the other side, the implementation itself should be provided by the code
/// emulating the IOMMU for the guest.
pub trait DmaRemapping: Send + Sync {
    fn translate(&self, id: u32, addr: u64) -> std::result::Result<u64, std::io::Error>;
}

/// Structure to handle device state common to all devices
#[derive(Default)]
pub struct VirtioCommon {
    pub avail_features: u64,
    pub acked_features: u64,
    pub kill_evt: Option<EventFd>,
    pub interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    pub queue_evts: Option<Vec<EventFd>>,
    pub pause_evt: Option<EventFd>,
    pub paused: Arc<AtomicBool>,
    pub paused_sync: Option<Arc<Barrier>>,
    pub epoll_threads: Option<Vec<JoinHandle<()>>>,
    pub queue_sizes: Vec<u16>,
    pub device_type: u32,
    pub min_queues: u16,
}

impl VirtioCommon {
    pub fn feature_acked(&self, feature: u64) -> bool {
        self.acked_features & 1 << feature == 1 << feature
    }

    pub fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    pub fn activate(
        &mut self,
        queues: &[Queue<GuestMemoryAtomic<GuestMemoryMmap>>],
        queue_evts: &[EventFd],
        interrupt_cb: &Arc<dyn VirtioInterrupt>,
    ) -> ActivateResult {
        if queues.len() != queue_evts.len() {
            error!(
                "Cannot activate: length mismatch: queue_evts={} queues={}",
                queue_evts.len(),
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if queues.len() < self.min_queues.into() {
            error!(
                "Number of enabled queues lower than min: {} vs {}",
                queues.len(),
                self.min_queues
            );
            return Err(ActivateError::BadActivate);
        }

        let kill_evt = EventFd::new(EFD_NONBLOCK).map_err(|e| {
            error!("failed creating kill EventFd: {}", e);
            ActivateError::BadActivate
        })?;
        self.kill_evt = Some(kill_evt);

        let pause_evt = EventFd::new(EFD_NONBLOCK).map_err(|e| {
            error!("failed creating pause EventFd: {}", e);
            ActivateError::BadActivate
        })?;
        self.pause_evt = Some(pause_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);
        Ok(())
    }

    pub fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
//        if self.pause_evt.take().is_some() {
//            self.resume().ok()?;
//        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(mut threads) = self.epoll_threads.take() {
            for t in threads.drain(..) {
                if let Err(e) = t.join() {
                    error!("Error joining thread: {:?}", e);
                }
            }
        }

        // Return the interrupt
        Some(self.interrupt_cb.take().unwrap())
    }

    pub fn dup_eventfds(&self) -> (EventFd, EventFd) {
        (
            self.kill_evt.as_ref().unwrap().try_clone().unwrap(),
            self.pause_evt.as_ref().unwrap().try_clone().unwrap(),
        )
    }
}

#[derive(Default)]
pub struct VhostUserCommon {
    pub vu: Option<Arc<Mutex<VhostUserHandle>>>,
    pub acked_protocol_features: u64,
    pub socket_path: String,
    pub vu_num_queues: usize,
    pub migration_started: bool,
    pub server: bool,
}

impl VhostUserCommon {
    #[allow(clippy::too_many_arguments)]
    pub fn activate<T: VhostUserMasterReqHandler>(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        queue_evts: Vec<EventFd>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        acked_features: u64,
        slave_req_handler: Option<MasterReqHandler<T>>,
        kill_evt: EventFd,
        pause_evt: EventFd,
    ) -> std::result::Result<VhostUserEpollHandler<T>, ActivateError> {
        let mut inflight: Option<Inflight> =
            if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() != 0
            {
                Some(Inflight::default())
            } else {
                None
            };

        if self.vu.is_none() {
            error!("Missing vhost-user handle");
            return Err(ActivateError::BadActivate);
        }
        let vu = self.vu.as_ref().unwrap();
        vu.lock()
            .unwrap()
            .setup_vhost_user(
                &mem.memory(),
                queues.clone(),
                queue_evts.iter().map(|q| q.try_clone().unwrap()).collect(),
                &interrupt_cb,
                acked_features,
                &slave_req_handler,
                inflight.as_mut(),
            )
            .map_err(ActivateError::VhostUserBlkSetup)?;

        Ok(VhostUserEpollHandler {
            vu: vu.clone(),
            mem,
            kill_evt,
            pause_evt,
            queues,
            queue_evts,
            virtio_interrupt: interrupt_cb,
            acked_features,
            acked_protocol_features: self.acked_protocol_features,
            socket_path: self.socket_path.clone(),
            server: self.server,
            slave_req_handler,
            inflight,
        })
    }

    pub fn restore_backend_connection(&mut self, acked_features: u64) -> Result<()> {
        let mut vu = VhostUserHandle::connect_vhost_user(
            self.server,
            &self.socket_path,
            self.vu_num_queues as u64,
            false,
        )?;

        vu.set_protocol_features_vhost_user(acked_features, self.acked_protocol_features)?;

        self.vu = Some(Arc::new(Mutex::new(vu)));

        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(vu) = &self.vu {
            let _ = unsafe { libc::close(vu.lock().unwrap().socket_handle().as_raw_fd()) };
        }

        // Remove socket path if needed
        if self.server {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    pub fn add_memory_region(
        &mut self,
        guest_memory: &Option<GuestMemoryAtomic<GuestMemoryMmap>>,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), Error> {
        if let Some(vu) = &self.vu {
            if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                != 0
            {
                return vu
                    .lock()
                    .unwrap()
                    .add_memory_region(region);
            } else if let Some(guest_memory) = guest_memory {
                return vu
                    .lock()
                    .unwrap()
                    .update_mem_table(guest_memory.memory().deref());
            }
        }
        Ok(())
    }
}

pub enum Thread {
    VirtioBalloon,
    VirtioBlock,
    VirtioConsole,
    VirtioIommu,
    VirtioMem,
    VirtioNet,
    VirtioNetCtl,
    VirtioPmem,
    VirtioRng,
    VirtioVhostBlock,
    VirtioVhostFs,
    VirtioVhostNet,
    VirtioVhostNetCtl,
    VirtioVsock,
    VirtioWatchdog,
}

pub(crate) fn spawn_virtio_thread<F>(
    name: &str,
    _seccomp_action: &SeccompAction,
    _thread_type: Thread,
    epoll_threads: &mut Vec<thread::JoinHandle<()>>,
    exit_evt: &EventFd,
    f: F,
) -> std::result::Result<(), ActivateError>
where
    F: FnOnce(),
    F: Send + 'static,
{
    let thread_exit_evt = exit_evt
        .try_clone()
        .map_err(ActivateError::CloneExitEventFd)?;
    let thread_name = name.to_string();

    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            std::panic::catch_unwind(AssertUnwindSafe(f))
                .or_else(|_| {
                    error!("{} thread panicked", thread_name);
                    thread_exit_evt.write(1)
                })
                .ok();
        })
        .map(|thread| epoll_threads.push(thread))
        .map_err(|e| {
            error!("Failed to spawn thread for {}: {}", name, e);
            ActivateError::ThreadSpawn(e)
        })
}
