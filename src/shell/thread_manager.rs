use std::{
    sync::mpsc::{Receiver, RecvError, SendError, Sender},
    thread::{self, JoinHandle, ThreadId},
};

pub struct ThreadManager<S, R> {
    handle: Option<JoinHandle<()>>,
    sender: Sender<S>,
    receiver: Receiver<R>,
}

impl<S, R> ThreadManager<S, R> {
    pub fn new<F>(f: impl FnOnce() -> (Sender<S>, Receiver<R>, F)) -> ThreadManager<S, R>
    where
        F: FnOnce() -> (),
        F: Send + 'static,
    {
        let (s, r, func) = f();
        let handle = thread::spawn(func);

        Self {
            handle: Some(handle),
            sender: s,
            receiver: r,
        }
    }

    pub fn send(&self, item: S) -> Result<(), SendError<S>> {
        self.sender.send(item)
    }

    pub fn receiver(&self) -> Result<R, RecvError> {
        self.receiver.recv()
    }

    pub fn id(&self) -> Option<ThreadId> {
        Some(self.handle.as_ref()?.thread().id())
    }

    pub fn name(&self) -> Option<&str> {
        self.handle.as_ref()?.thread().name()
    }

    pub fn join(&mut self) -> Result<(), ()> {
        if self.handle.is_none() {
            return Ok(());
        }
        self.handle.take().unwrap().join().map_err(|_| ())
    }

    pub fn is_finished(&mut self) -> bool {
        if let Some(ref handle) = self.handle {
            handle.is_finished()
        } else {
            true
        }
    }
}
