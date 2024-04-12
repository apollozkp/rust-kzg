use std::io::Read;

use alloc::sync::Arc;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

type Handler<T, const N: usize> = Arc<dyn Fn(&[u8; N]) -> T + Send + Sync>;

pub fn sync_reader<const N: usize, T>(
    reader: &mut dyn Read,
    n: usize,
    handler: Handler<T, N>,
) -> Result<Vec<T>, String>
where
    T: Clone + 'static,
{
    (0..n).try_fold(Vec::with_capacity(n), |mut acc, _| {
        let mut bytes = [0u8; N];
        reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
        acc.push(handler(&bytes));
        Ok(acc)
    })
}

#[cfg(feature = "parallel")]
pub fn par_io_batch_reader<const N: usize, T>(
    reader: &mut (dyn Read + Send),
    n: usize,
    handler: Handler<T, N>,
) -> Result<Vec<T>, String>
where
    T: Clone + Send + Sync + 'static,
{
    std::thread::scope(|s| {
        use crossbeam_channel::{bounded, unbounded};
        let (bytes_tx, bytes_rx) = unbounded();
        let (parsed_tx, parsed_rx) = unbounded();
        let (err_tx, err_rx) = bounded(1);

        let read_thread = {
            let bytes_tx = bytes_tx.clone();
            let err_tx = err_tx.clone();
            s.spawn(move || {
                for i in 0..n {
                    let mut bytes = [0u8; N];
                    if let Err(e) = reader.read_exact(&mut bytes) {
                        let _ = err_tx.send(e.to_string());
                        return;
                    };
                    bytes_tx.send((i, bytes)).unwrap();
                }
                let n_in_channel = bytes_tx.len();
                println!("Read thread finished, {} items in channel", n_in_channel);
            })
        };

        // Reserve 1 core for reading and 1 core for main process
        let n_workers = usize::min(num_cpus::get() - 2, n);
        for _ in 0..n_workers {
            let bytes_rx = bytes_rx.clone();
            let parsed_tx = parsed_tx.clone();
            let handler = handler.clone();
            s.spawn(move || {
                while let Ok((i, bytes)) = bytes_rx.recv() {
                    let parsed = handler(&bytes);
                    parsed_tx.send((i, parsed)).unwrap();
                }
            });
        }

        let mut output = unsafe { vec![std::mem::zeroed(); n] };
        for _ in 0..n {
            let (i, parsed) = parsed_rx.recv().unwrap();
            output[i] = parsed;
        }

        read_thread
            .join()
            .map_err(|e| format!("Error joining read thread: {:?}", e))?;

        if let Ok(e) = err_rx.try_recv() {
            return Err(e);
        }

        // Drop channels to ensure all threads exit
        drop(bytes_tx);
        drop(parsed_tx);
        drop(err_tx);

        Ok(output)
    })
}

#[cfg(feature = "parallel")]
pub fn sync_io_batch_reader<const N: usize, T>(
    reader: &mut (dyn Read + Send),
    n: usize,
    handler: Handler<T, N>,
) -> Result<Vec<T>, String>
where
    T: Clone + Send + Sync + 'static,
{
    {
        let mut bytes = Vec::with_capacity(n);
        for _ in 0..n {
            let mut bytes_arr = [0u8; N];
            reader
                .read_exact(&mut bytes_arr)
                .map_err(|e| e.to_string())?;
            bytes.push(bytes_arr);
        }
        let output = bytes
            .into_par_iter()
            .map(|bytes| handler(&bytes))
            .collect::<Vec<T>>();
        Ok(output)
    }
}

pub fn batch_reader<const N: usize, T>(
    reader: &mut (dyn Read + Send),
    n: usize,
    handler: Handler<T, N>,
    par_io: Option<bool>,
) -> Result<Vec<T>, String>
where
    T: Clone + Send + Sync + 'static,
{
    #[cfg(not(feature = "parallel"))]
    {
        sync_reader(reader, n, handler)
    }

    #[cfg(feature = "parallel")]
    {
        match par_io {
            Some(true) => par_io_batch_reader(reader, n, handler),
            _ => sync_io_batch_reader(reader, n, handler),
        }
    }
}
