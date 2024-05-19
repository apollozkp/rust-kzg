use core::marker::PhantomData;

use alloc::sync::Arc;

use crate::{Fr, G1Affine, G1Fp, G1GetFp, G1Mul, Scalar256, G1};

use super::pippenger_utils::{
    booth_decode, booth_encode, get_wval_limb, is_zero, p1_dadd, p1_to_jacobian,
    pippenger_window_size, type_is_zero, P1XYZZ,
};

#[derive(Debug, Clone)]
pub struct BgmwTable<TFr, TG1, TG1Fp, TG1Affine>
where
    TFr: Fr,
    TG1: G1 + G1Mul<TFr> + G1GetFp<TG1Fp>,
    TG1Fp: G1Fp,
    TG1Affine: G1Affine<TG1, TG1Fp>,
{
    window: BgmwWindow,
    points: Vec<TG1Affine>,
    numpoints: usize,
    h: usize,

    g1_marker: PhantomData<TG1>,
    g1_fp_marker: PhantomData<TG1Fp>,
    fr_marker: PhantomData<TFr>,
}

impl <TFr, TG1, TG1Fp, TG1Affine>PartialEq for BgmwTable<TFr, TG1, TG1Fp, TG1Affine>
where
    TFr: Fr,
    TG1: G1 + G1Mul<TFr> + G1GetFp<TG1Fp>,
    TG1Fp: G1Fp,
    TG1Affine: G1Affine<TG1, TG1Fp>,
{
    fn eq(&self, other: &Self) -> bool {
        self.window == other.window
            && self.points == other.points
            && self.numpoints == other.numpoints
            && self.h == other.h
    }
}

const NBITS: usize = 255;

#[cfg(feature = "parallel")]
#[derive(Debug, Clone, Copy)]
pub enum BgmwWindow {
    Sync(usize),
    Parallel((usize, usize, usize)),
}

#[cfg(not(feature = "parallel"))]
pub type BgmwWindow = usize;

impl PartialEq for BgmwWindow {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "parallel")]
        match (self, other) {
            (BgmwWindow::Sync(a), BgmwWindow::Sync(b)) => a == b,
            _ => false,
        }
        #[cfg(not(feature = "parallel"))]
        {
            self == other
        }
    }
}

#[inline]
const fn get_table_dimensions(window: BgmwWindow) -> (usize, usize) {
    let window_width;

    #[cfg(not(feature = "parallel"))]
    {
        window_width = window;
    }

    #[cfg(feature = "parallel")]
    {
        window_width = match window {
            BgmwWindow::Sync(wnd) => wnd,
            BgmwWindow::Parallel((_, ny, wnd)) => return (wnd, ny),
        }
    }

    let h =
        (NBITS + window_width - 1) / window_width + is_zero((NBITS % window_width) as u64) as usize;

    (window_width, h)
}

#[inline]
const fn get_sequential_window_size(window: BgmwWindow) -> usize {
    #[cfg(not(feature = "parallel"))]
    {
        window
    }

    #[cfg(feature = "parallel")]
    {
        match window {
            BgmwWindow::Sync(wnd) => wnd,
            BgmwWindow::Parallel(_) => {
                panic!("Cannot use parallel BGMW table in sequential version")
            }
        }
    }
}

impl<
        TFr: Fr,
        TG1Fp: G1Fp,
        TG1: G1 + G1Mul<TFr> + G1GetFp<TG1Fp>,
        TG1Affine: G1Affine<TG1, TG1Fp>,
    > BgmwTable<TFr, TG1, TG1Fp, TG1Affine>
{
    pub fn new(points: &[TG1]) -> Result<Option<Self>, String> {
        let window = Self::window(points.len());

        let (window_width, h) = get_table_dimensions(window);

        let mut table: Vec<TG1Affine> = Vec::new();
        let q = TFr::from_u64(1u64 << window_width);

        table
            .try_reserve_exact(points.len() * h)
            .map_err(|_| "BGMW precomputation table is too large".to_string())?;

        unsafe { table.set_len(points.len() * h) };

        for i in 0..points.len() {
            let mut tmp_point = points[i].clone();
            for j in 0..h {
                let idx = j * points.len() + i;
                table[idx] = TG1Affine::into_affine(&tmp_point);
                tmp_point = tmp_point.mul(&q);
            }
        }

        Ok(Some(Self {
            numpoints: points.len(),
            points: table,
            window,
            h,

            fr_marker: PhantomData,
            g1_fp_marker: PhantomData,
            g1_marker: PhantomData,
        }))
    }

    pub fn multiply_sequential(&self, scalars: &[Scalar256]) -> TG1 {
        let window = get_sequential_window_size(self.window);
        let mut buckets = vec![P1XYZZ::<TG1Fp>::default(); 1 << (window - 1)];

        let mut wbits: usize = 255 % window;
        let mut cbits: usize = wbits + 1;
        let mut bit0: usize = 255;

        let mut q_idx = self.h;

        loop {
            bit0 -= wbits;
            q_idx -= 1;
            if bit0 == 0 {
                break;
            }

            p1_tile_bgmw(
                &self.points[q_idx * self.numpoints..(q_idx + 1) * self.numpoints],
                scalars,
                &mut buckets,
                bit0,
                wbits,
                cbits,
            );

            cbits = window;
            wbits = window;
        }
        p1_tile_bgmw(
            &self.points[0..self.numpoints],
            scalars,
            &mut buckets,
            0,
            wbits,
            cbits,
        );

        let mut ret = TG1::default();
        integrate_buckets(&mut ret, &buckets, wbits - 1);

        ret
    }

    #[cfg(feature = "parallel")]
    pub fn multiply_parallel(&self, scalars: &[Scalar256]) -> TG1 {
        use super::{
            cell::Cell,
            thread_pool::{da_pool, ThreadPoolExt},
        };
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;

        let npoints = scalars.len();
        let pool = da_pool();
        let ncpus = pool.max_count();

        struct Tile {
            x: usize,
            dx: usize,
            y: usize,
            dy: usize,
        }

        let (nx, ny, window) = match self.window {
            BgmwWindow::Sync(_) => return self.multiply_sequential(scalars),
            BgmwWindow::Parallel(values) => values,
        };

        // |grid[]| holds "coordinates" and place for result
        let mut grid: Vec<(Tile, Cell<TG1>)> = Vec::with_capacity(nx * ny);
        #[allow(clippy::uninit_vec)]
        unsafe {
            grid.set_len(grid.capacity())
        };
        let dx = npoints / nx;
        let mut y = window * (ny - 1);
        let mut total = 0usize;

        while total < nx {
            grid[total].0.x = total * dx;
            grid[total].0.dx = dx;
            grid[total].0.y = y;
            grid[total].0.dy = 255 - y;
            total += 1;
        }
        grid[total - 1].0.dx = npoints - grid[total - 1].0.x;
        while y != 0 {
            y -= window;
            for i in 0..nx {
                grid[total].0.x = grid[i].0.x;
                grid[total].0.dx = grid[i].0.dx;
                grid[total].0.y = y;
                grid[total].0.dy = window;
                total += 1;
            }
        }
        let grid = &grid[..];

        let mut row_sync: Vec<AtomicUsize> = Vec::with_capacity(ny);
        row_sync.resize_with(ny, Default::default);
        let counter = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let n_workers = core::cmp::min(ncpus, total);

        let mut results: Vec<Cell<TG1>> = Vec::with_capacity(n_workers);
        #[allow(clippy::uninit_vec)]
        unsafe {
            results.set_len(results.capacity());
        };

        let results = &results[..];

        #[allow(clippy::needless_range_loop)]
        for worker_index in 0..n_workers {
            let tx = tx.clone();
            let counter = counter.clone();

            pool.joined_execute(move || {
                let mut buckets = vec![P1XYZZ::<TG1Fp>::default(); 1 << (window - 1)];
                loop {
                    let work = counter.fetch_add(1, Ordering::Relaxed);
                    if work >= total {
                        integrate_buckets(
                            unsafe { results[worker_index].as_ptr().as_mut() }.unwrap(),
                            &buckets,
                            window - 1,
                        );
                        tx.send(worker_index).expect("disaster");

                        break;
                    }

                    let x = grid[work].0.x;
                    let y = grid[work].0.y;
                    let dx = grid[work].0.dx;

                    let row_start = (y / window) * self.numpoints + x;
                    let points = &self.points[row_start..(row_start + dx)];

                    let (wbits, cbits) = if y + window > NBITS {
                        let wbits = NBITS - y;
                        (wbits, wbits + 1)
                    } else {
                        (window, window)
                    };

                    p1_tile_bgmw(points, &scalars[x..], &mut buckets, y, wbits, cbits);
                }
            });
        }

        let mut ret = <TG1>::default();
        for _ in 0..n_workers {
            let idx = rx.recv().unwrap();

            ret.add_or_dbl_assign(results[idx].as_mut());
        }
        ret
    }

    fn window(npoints: usize) -> BgmwWindow {
        #[cfg(feature = "parallel")]
        {
            let default_window = pippenger_window_size(npoints);

            use super::{parallel_pippenger_utils::breakdown, thread_pool::da_pool};

            let pool = da_pool();
            let ncpus = pool.max_count();
            if npoints > 32 && ncpus > 2 {
                BgmwWindow::Parallel(breakdown(default_window, ncpus))
            } else {
                BgmwWindow::Sync(default_window)
            }
        }

        #[cfg(not(feature = "parallel"))]
        {
            let n_exponent = npoints.trailing_zeros();

            // TODO: experiment with different q exponents, to find optimal
            match n_exponent {
                12 => 13, // this value is picked from https://github.com/LuoGuiwen/MSM_blst/blob/2e098f09f07969ac3191406976be6d1c197100f2/ches_config_files/config_file_n_exp_12.h#L17
                _ => pippenger_window_size(npoints), // default to pippenger window size. This is not optimal window size, but still better than simple pippenger
            }
        }
    }
}

impl<
        TFr: Fr,
        TG1Fp: G1Fp,
        TG1: G1 + G1Mul<TFr> + G1GetFp<TG1Fp>,
        TG1Affine: G1Affine<TG1, TG1Fp> + 'static,
    > BgmwTable<TFr, TG1, TG1Fp, TG1Affine>
{
    /////// File IO ///////

    pub fn read_from_file(path: &str, compressed: bool) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut reader = std::io::BufReader::new(file);
        Self::read_from_reader(&mut reader, compressed)
    }

    pub fn read_from_reader(reader: &mut std::io::BufReader<std::fs::File>, compressed: bool) -> Result<Self, String> {
        let window = Self::read_window(reader)?;
        let numpoints = Self::read_numpoints(reader)?;
        let h = Self::read_h(reader)?;
        let points = Self::read_points(reader, numpoints, h, compressed)?;
        Ok(Self {
            window,
            points,
            numpoints,
            h,
            g1_marker: PhantomData,
            g1_fp_marker: PhantomData,
            fr_marker: PhantomData,
        })
    }

    pub fn read_usize(reader: &mut std::io::BufReader<std::fs::File>) -> Result<usize, String> {
        use std::io::Read;
        let mut buffer = [0u8; 8];
        reader.read_exact(&mut buffer).map_err(|e| e.to_string())?;
        Ok(usize::from_le_bytes(buffer))
    }

    // window is just a usize
    pub fn read_window(
        reader: &mut std::io::BufReader<std::fs::File>,
    ) -> Result<BgmwWindow, String> {
        #[cfg(not(feature = "parallel"))]
        {
            match Self::read_usize(reader)? {
                1 => Ok(BgmwWindow::from(Self::read_usize(reader)?)),
                _ => Err("Invalid window type".to_string()),
            }
        }

        #[cfg(feature = "parallel")]
        {
            match Self::read_usize(reader)? {
                1 => Ok(BgmwWindow::Sync(Self::read_usize(reader)?)),
                3 => Ok(BgmwWindow::Parallel((
                    Self::read_usize(reader)?,
                    Self::read_usize(reader)?,
                    Self::read_usize(reader)?,
                ))),
                _ => Err("Invalid window type".to_string()),
            }
        }
    }

    pub fn read_numpoints(reader: &mut std::io::BufReader<std::fs::File>) -> Result<usize, String> {
        Self::read_usize(reader)
    }

    pub fn read_h(reader: &mut std::io::BufReader<std::fs::File>) -> Result<usize, String> {
        Self::read_usize(reader)
    }

    pub fn read_points(
        reader: &mut std::io::BufReader<std::fs::File>,
        numpoints: usize,
        h: usize,
        compressed: bool,
    ) -> Result<Vec<TG1Affine>, String> {
        let mut points = Vec::new();
        points
            .try_reserve_exact(numpoints * h)
            .map_err(|_| "BGMW precomputation table is too large".to_string())?;
        unsafe { points.set_len(numpoints * h) };

        let affines = if compressed {
            const BYTES: usize = 48;
            let handler = |bytes: &[u8; BYTES]| -> Result<TG1Affine, String> {
                Ok(TG1Affine::into_affine(&TG1::from_bytes(bytes)?))
            };

            
            crate::io_utils::batch_reader::<BYTES, Result<TG1Affine, String>>(
                &mut *reader,
                numpoints * h,
                Arc::new(handler),
                None,
            )?
        } else {
            const BYTES: usize = 96;
            let handler = |bytes: &[u8; BYTES]| -> Result<TG1Affine, String> {
                Ok(TG1Affine::into_affine(&TG1::deserialize(bytes)?))
            };

            
            crate::io_utils::batch_reader::<BYTES, Result<TG1Affine, String>>(
                &mut *reader,
                numpoints * h,
                Arc::new(handler),
                None,
            )?
        };

        for (i, affine) in affines.into_iter().enumerate() {
            points[i] = affine?;
        }

        Ok(points)
    }

    pub fn write_to_file(&self, path: &str, compressed: bool) -> Result<(), String> {
        let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        let mut writer = std::io::BufWriter::new(file);
        self.write_to_writer(&mut writer, compressed)?;
        Ok(())
    }

    pub fn write_to_writer(&self, writer: &mut std::io::BufWriter<std::fs::File>, compressed: bool) -> Result<(), String> {
        self.write_window(writer)?;
        self.write_numpoints(writer)?;
        self.write_h(writer)?;
        self.write_points(writer, compressed)
    }

    pub fn write_usize(
        writer: &mut std::io::BufWriter<std::fs::File>,
        value: usize,
    ) -> Result<(), String> {
        use std::io::Write;
        writer
            .write_all(&value.to_le_bytes())
            .map_err(|e| e.to_string())
    }

    pub fn write_window(
        &self,
        writer: &mut std::io::BufWriter<std::fs::File>,
    ) -> Result<(), String> {
        #[cfg(not(feature = "parallel"))]
        {
            Self::write_usize(writer, 1)?;
            Self::write_usize(writer, self.window)?;
        }

        #[cfg(feature = "parallel")]
        {
            match self.window {
                BgmwWindow::Sync(wnd) => {
                    Self::write_usize(writer, 1)?;
                    Self::write_usize(writer, wnd)?;
                }
                BgmwWindow::Parallel((nx, ny, wnd)) => {
                    Self::write_usize(writer, 3)?;
                    Self::write_usize(writer, nx)?;
                    Self::write_usize(writer, ny)?;
                    Self::write_usize(writer, wnd)?;
                }
            };
        }

        Ok(())
    }

    pub fn write_numpoints(
        &self,
        writer: &mut std::io::BufWriter<std::fs::File>,
    ) -> Result<(), String> {
        Self::write_usize(writer, self.numpoints)
    }

    pub fn write_h(&self, writer: &mut std::io::BufWriter<std::fs::File>) -> Result<(), String> {
        Self::write_usize(writer, self.h)
    }

    pub fn write_points(
        &self,
        writer: &mut std::io::BufWriter<std::fs::File>,
        compressed: bool,
    ) -> Result<(), String> {
        use std::io::Write;
        for affine in self.points.iter() {
            let point = affine.to_proj();
            if compressed {
                writer
                    .write_all(&point.to_bytes())
                    .map_err(|e| e.to_string())?;
            } else {
                writer
                    .write_all(&point.serialize())
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn p1_tile_bgmw<TG1: G1 + G1GetFp<TFp>, TFp: G1Fp, TG1Affine: G1Affine<TG1, TFp>>(
    points: &[TG1Affine],
    scalars: &[Scalar256],
    buckets: &mut [P1XYZZ<TFp>],
    bit0: usize,
    wbits: usize,
    cbits: usize,
) {
    // Get first scalar
    let scalar = &scalars[0];

    // Get first point
    let point = &points[0];

    // Create mask, that contains `wbits` ones at the end.
    let wmask = (1u64 << (wbits + 1)) - 1;

    /*
     * Check if `bit0` is zero. `z` is set to `1` when `bit0 = 0`, and `0` otherwise.
     *
     * The `z` flag is used to do a small trick -
     */
    let z = is_zero(bit0.try_into().unwrap());

    // Offset `bit0` by 1, if it is not equal to zero.
    let bit0 = bit0 - (z ^ 1) as usize;

    // Increase `wbits` by one, if `bit0` is not equal to zero.
    let wbits = wbits + (z ^ 1) as usize;

    // Calculate first window value (encoded bucket index)
    let wval = (get_wval_limb(scalar, bit0, wbits) << z) & wmask;
    let mut wval = booth_encode(wval, cbits);

    // Get second scalar
    let scalar = &scalars[1];

    // Calculate second window value (encoded bucket index)
    let wnxt = (get_wval_limb(scalar, bit0, wbits) << z) & wmask;
    let mut wnxt = booth_encode(wnxt, cbits);

    // Move first point to corresponding bucket
    booth_decode(buckets, wval, cbits, point);

    // Last point will be calculated separately, so decrementing point count
    let npoints = scalars.len() - 1;

    // Move points to buckets
    for i in 1..npoints {
        // Get current window value (encoded bucket index)
        wval = wnxt;

        // Get next scalar
        let scalar = &scalars[i + 1];
        // Get next window value (encoded bucket index)
        wnxt = (get_wval_limb(scalar, bit0, wbits) << z) & wmask;
        wnxt = booth_encode(wnxt, cbits);

        // TODO: add prefetching
        // POINTonE1_prefetch(buckets, wnxt, cbits);
        // p1_prefetch(buckets, wnxt, cbits);

        // Get current point
        let point = &points[i];

        // Move point to corresponding bucket (add or subtract from bucket)
        // `wval` contains encoded bucket index, as well as sign, which shows if point should be subtracted or added to bucket
        booth_decode(buckets, wval, cbits, point);
    }
    // Get last point
    let point = &points[npoints];
    // Move point to bucket
    booth_decode(buckets, wnxt, cbits, point);
}

/// Calculate bucket sum
///
/// This function multiplies the point in each bucket by it's index. Then, it will sum all multiplication results and write
/// resulting point to the `out`.
///
/// ## Arguments
///
/// * out     - output where bucket sum must be written
/// * buckets - pointer to the beginning of the array of buckets
/// * wbits   - window size, aka exponent of q (q^window)
///
fn integrate_buckets<TG1: G1 + G1GetFp<TFp>, TFp: G1Fp>(
    out: &mut TG1,
    buckets: &[P1XYZZ<TFp>],
    wbits: usize,
) {
    let mut n = (1usize << wbits) - 1;
    let mut ret = buckets[n];
    let mut acc = buckets[n];

    loop {
        if n == 0 {
            break;
        }
        n -= 1;

        if type_is_zero(&buckets[n]) == 0 {
            p1_dadd(&mut acc, &buckets[n]);
        }
        p1_dadd(&mut ret, &acc);
    }

    p1_to_jacobian(out, &ret);
}
