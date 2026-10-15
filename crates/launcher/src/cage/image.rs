// SPDX-License-Identifier: AGPL-3.0-or-later
//! Static ELF handoff through fresh mappings; no executable-system-call exception.

use std::{
    ffi::OsString,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
};

use super::{refusal, Result};

mod handoff;

const PAGE: usize = 4096;
const MAX_IMAGE: usize = 64 * 1024 * 1024;
const MAX_SPAN: usize = 256 * 1024 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_RANGES: usize = 4096;
const STACK_SIZE: usize = 8 * 1024 * 1024;
const CONTROL_SIZE: usize = 256 * 1024;
const RANGES_OFFSET: usize = 16384;
#[cfg(target_arch = "x86_64")]
const XSAVE_OFFSET: usize = 131072;

pub(super) fn validate(fd: &OwnedFd) -> Result<Vec<u8>> {
    let stat = rustix::fs::fstat(fd).map_err(|_| refusal("image-stat"))?;
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: this getter borrows the live image descriptor without transferring it.
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o111 == 0
        || seals < 0
        || seals & required != required
    {
        return Err(refusal("image-seals"));
    }
    let len = usize::try_from(stat.st_size).map_err(|_| refusal("image-size"))?;
    if !(64..=MAX_IMAGE).contains(&len) {
        return Err(refusal("image-size"));
    }
    let mut bytes = vec![0; len];
    let mut at = 0;
    while at < len {
        // SAFETY: the output is a live, exclusive slice, and the sealed file cannot shrink.
        let count = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                bytes[at..].as_mut_ptr().cast(),
                len - at,
                at as libc::off_t,
            )
        };
        if count < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if count <= 0 {
            return Err(refusal("image-read"));
        }
        at += count as usize;
    }
    Elf::parse(&bytes)?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct Segment {
    kind: u32,
    flags: u32,
    offset: usize,
    address: usize,
    files: usize,
    memory: usize,
}

struct Elf {
    kind: u16,
    entry: usize,
    headers_at: usize,
    headers: Vec<Segment>,
    low: usize,
    high: usize,
    alignment: usize,
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(refusal("image-elf"))?
            .try_into()
            .map_err(|_| refusal("image-elf"))?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(refusal("image-elf"))?
            .try_into()
            .map_err(|_| refusal("image-elf"))?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(refusal("image-elf"))?
            .try_into()
            .map_err(|_| refusal("image-elf"))?,
    ))
}
fn word_at(bytes: &[u8], at: usize) -> Result<usize> {
    usize::try_from(u64_at(bytes, at)?).map_err(|_| refusal("image-elf"))
}
fn page_up(value: usize) -> Result<usize> {
    value
        .checked_add(PAGE - 1)
        .map(|n| n & !(PAGE - 1))
        .ok_or(refusal("image-range"))
}

impl Elf {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let native_machine = if cfg!(target_arch = "x86_64") {
            62
        } else if cfg!(target_arch = "aarch64") {
            183
        } else {
            return Err(refusal("unsupported-architecture"));
        };
        if bytes.get(..9) != Some(&b"\x7fELF\x02\x01\x01\x00\x00"[..])
            && bytes.get(..9) != Some(&b"\x7fELF\x02\x01\x01\x03\x00"[..])
        {
            return Err(refusal("image-elf"));
        }
        let kind = u16_at(bytes, 16)?;
        if ![2, 3].contains(&kind)
            || u16_at(bytes, 18)? != native_machine
            || u32_at(bytes, 20)? != 1
            || u32_at(bytes, 48)? != 0
            || u16_at(bytes, 52)? != 64
            || u16_at(bytes, 54)? != 56
        {
            return Err(refusal("image-elf"));
        }
        let count = usize::from(u16_at(bytes, 56)?);
        let headers_at = word_at(bytes, 32)?;
        let headers_end = headers_at
            .checked_add(count * 56)
            .ok_or(refusal("image-range"))?;
        if count == 0 || count > MAX_HEADERS || headers_end > bytes.len() {
            return Err(refusal("image-headers"));
        }
        let mut headers = Vec::with_capacity(count);
        let mut low = usize::MAX;
        let mut high = 0;
        let mut dynamic = false;
        let mut maximum_alignment = PAGE;
        for index in 0..count {
            let at = headers_at + index * 56;
            let segment = Segment {
                kind: u32_at(bytes, at)?,
                flags: u32_at(bytes, at + 4)?,
                offset: word_at(bytes, at + 8)?,
                address: word_at(bytes, at + 16)?,
                files: word_at(bytes, at + 32)?,
                memory: word_at(bytes, at + 40)?,
            };
            let alignment = word_at(bytes, at + 48)?;
            if segment.kind == 3 || (segment.kind == 0x6474_e551 && segment.flags & 1 != 0) {
                return Err(refusal("image-dynamic"));
            }
            if segment.kind == 2 {
                if dynamic {
                    return Err(refusal("image-dynamic"));
                }
                dynamic = true;
            }
            if segment.kind == 1 {
                let end = segment
                    .address
                    .checked_add(segment.memory)
                    .ok_or(refusal("image-range"))?;
                let file_end = segment
                    .offset
                    .checked_add(segment.files)
                    .ok_or(refusal("image-range"))?;
                if segment.files > segment.memory
                    || file_end > bytes.len()
                    || (alignment > 1
                        && (!alignment.is_power_of_two() || alignment > 2 * 1024 * 1024))
                    || (alignment > 1 && segment.address % alignment != segment.offset % alignment)
                    || segment.address % PAGE != segment.offset % PAGE
                    || segment.flags & !7 != 0
                    || segment.flags & 6 == 2
                    || segment.flags & 3 == 3
                    || end > (1usize << 47)
                {
                    return Err(refusal("image-segment"));
                }
                if segment.memory != 0 {
                    maximum_alignment = maximum_alignment.max(alignment);
                    low = low.min(segment.address & !(PAGE - 1));
                    high = high.max(page_up(end)?);
                }
            }
            headers.push(segment);
        }
        if low == usize::MAX || high - low > MAX_SPAN || (kind == 2 && low < 65536) {
            return Err(refusal("image-range"));
        }
        let loads: Vec<_> = headers
            .iter()
            .filter(|s| s.kind == 1 && s.memory != 0)
            .collect();
        for (index, left) in loads.iter().enumerate() {
            for right in loads.iter().skip(index + 1) {
                if (left.address & !(PAGE - 1)) < page_up(right.address + right.memory)?
                    && (right.address & !(PAGE - 1)) < page_up(left.address + left.memory)?
                {
                    return Err(refusal("image-overlap"));
                }
            }
        }
        let entry = word_at(bytes, 24)?;
        if !loads
            .iter()
            .any(|s| s.flags & 1 != 0 && entry >= s.address && entry < s.address + s.memory)
            || !loads
                .iter()
                .any(|s| headers_at >= s.offset && headers_end <= s.offset + s.files)
        {
            return Err(refusal("image-entry"));
        }
        let elf = Self {
            kind,
            entry,
            headers_at,
            headers,
            low,
            high,
            alignment: maximum_alignment,
        };
        elf.relocations(bytes)?;
        Ok(elf)
    }

    fn file_slice<'a>(&self, bytes: &'a [u8], address: usize, len: usize) -> Result<&'a [u8]> {
        let end = address.checked_add(len).ok_or(refusal("image-range"))?;
        let segment = self
            .headers
            .iter()
            .find(|s| s.kind == 1 && address >= s.address && end <= s.address + s.files)
            .ok_or(refusal("image-relocation"))?;
        let offset = segment.offset + address - segment.address;
        bytes
            .get(offset..offset + len)
            .ok_or(refusal("image-relocation"))
    }

    fn relocations(&self, bytes: &[u8]) -> Result<Vec<(usize, i64)>> {
        let Some(dynamic) = self.headers.iter().find(|s| s.kind == 2) else {
            return Ok(Vec::new());
        };
        let end = dynamic
            .offset
            .checked_add(dynamic.files)
            .ok_or(refusal("image-dynamic"))?;
        let table = bytes
            .get(dynamic.offset..end)
            .ok_or(refusal("image-dynamic"))?;
        if table.len() % 16 != 0
            || table.len() > 65536
            || self.file_slice(bytes, dynamic.address, dynamic.files)? != table
        {
            return Err(refusal("image-dynamic"));
        }
        let (mut address, mut size, mut entry_size) = (None, None, None);
        let mut terminated = false;
        for entry in table.chunks_exact(16) {
            let tag = u64_at(entry, 0)?;
            let value = word_at(entry, 8)?;
            match tag {
                0 => {
                    terminated = true;
                    break;
                }
                7 => {
                    if address.replace(value).is_some() {
                        return Err(refusal("image-dynamic"));
                    }
                }
                8 => {
                    if size.replace(value).is_some() {
                        return Err(refusal("image-dynamic"));
                    }
                }
                9 => {
                    if entry_size.replace(value).is_some() {
                        return Err(refusal("image-dynamic"));
                    }
                }
                1 | 15 | 17 | 18 | 19 | 22 | 29 | 35 | 36 | 37 => {
                    return Err(refusal("image-dynamic"))
                }
                2 | 20 | 23 if value != 0 => return Err(refusal("image-dynamic")),
                30 if value & 4 != 0 => return Err(refusal("image-dynamic")),
                0x6fff_fffb if value & !0x0800_0001 != 0 => return Err(refusal("image-dynamic")),
                2..=6
                | 10..=14
                | 16
                | 20
                | 21
                | 23..=28
                | 30
                | 32
                | 33
                | 0x6fff_fef5
                | 0x6fff_fff9
                | 0x6fff_fffb => {}
                _ => return Err(refusal("image-dynamic")),
            }
        }
        if !terminated {
            return Err(refusal("image-dynamic"));
        }
        let size = size.unwrap_or(0);
        if size == 0 {
            return Ok(Vec::new());
        }
        if entry_size != Some(24) || size % 24 != 0 || size / 24 > 131072 {
            return Err(refusal("image-relocation"));
        }
        let table = self.file_slice(bytes, address.ok_or(refusal("image-relocation"))?, size)?;
        let relative = if cfg!(target_arch = "x86_64") {
            8
        } else {
            1027
        };
        let mut relocations = Vec::with_capacity(size / 24);
        for entry in table.chunks_exact(24) {
            let address = word_at(entry, 0)?;
            let info = u64_at(entry, 8)?;
            if info == 0 {
                continue;
            }
            if info != relative
                || address % 8 != 0
                || !self.headers.iter().any(|s| {
                    s.kind == 1
                        && s.flags & 2 != 0
                        && address >= s.address
                        && address
                            .checked_add(8)
                            .is_some_and(|end| end <= s.address + s.memory)
                })
            {
                return Err(refusal("image-relocation"));
            }
            relocations.push((
                address,
                i64::from_le_bytes(
                    entry[16..24]
                        .try_into()
                        .map_err(|_| refusal("image-relocation"))?,
                ),
            ));
        }
        Ok(relocations)
    }
}

struct Mapping {
    start: *mut u8,
    len: usize,
}

impl Mapping {
    fn aligned(len: usize, alignment: usize, low: usize) -> Result<Self> {
        let allocation = Self::allocate(0, len + alignment)?;
        let prefix = low.wrapping_sub(allocation.start as usize) & (alignment - 1);
        let suffix = allocation.len - prefix - len;
        // SAFETY: prefix and suffix are page-aligned subranges of this anonymous reservation.
        if prefix != 0 && unsafe { libc::munmap(allocation.start.cast(), prefix) } != 0 {
            return Err(refusal("image-alignment"));
        }
        // SAFETY: the suffix begins at the page-aligned end of the retained image mapping.
        if suffix != 0
            && unsafe { libc::munmap(allocation.start.add(prefix + len).cast(), suffix) } != 0
        {
            return Err(refusal("image-alignment"));
        }
        // SAFETY: the retained range remains mapped after releasing its disjoint prefix and suffix.
        let start = unsafe { allocation.start.add(prefix) };
        std::mem::forget(allocation);
        Ok(Self { start, len })
    }

    fn allocate(address: usize, len: usize) -> Result<Self> {
        let flags = libc::MAP_PRIVATE
            | libc::MAP_ANONYMOUS
            | if address != 0 {
                libc::MAP_FIXED_NOREPLACE
            } else {
                0
            };
        // SAFETY: the kernel chooses an unused anonymous range; FIXED_NOREPLACE cannot replace existing mappings.
        let start = unsafe {
            libc::mmap(
                address as *mut _,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if start == libc::MAP_FAILED {
            return Err(refusal("image-map"));
        }
        let mapping = Self {
            start: start.cast(),
            len,
        };
        if address != 0 && mapping.start as usize != address {
            return Err(refusal("image-address"));
        }
        Ok(mapping)
    }
    fn protect(&self, offset: usize, len: usize, protection: i32) -> Result<()> {
        if offset % PAGE != 0
            || len % PAGE != 0
            || offset.checked_add(len).is_none_or(|end| end > self.len)
        {
            return Err(refusal("image-protection"));
        }
        // SAFETY: the checked range belongs to this live mapping and both bounds are page aligned.
        if unsafe { libc::mprotect(self.start.add(offset).cast(), len, protection) } != 0 {
            return Err(refusal("image-protection"));
        }
        Ok(())
    }
    fn copy(&self, offset: usize, bytes: &[u8]) -> Result<()> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(refusal("image-range"));
        }
        // SAFETY: preparation owns a writable anonymous mapping and the source does not overlap it.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.start.add(offset), bytes.len());
        }
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: a successful allocation owns this exact range; handoff never returns to run this destructor.
        unsafe {
            libc::munmap(self.start.cast(), self.len);
        }
    }
}

pub(super) struct Prepared {
    image: Mapping,
    capsule: Mapping,
    code: usize,
    control: usize,
    proc_maps: Option<OwnedFd>,
    finalized: bool,
}

pub(super) fn prepare(bytes: &[u8], arguments: &[OsString]) -> Result<Prepared> {
    let elf = Elf::parse(bytes)?;
    // SAFETY: sysconf's page-size query takes no pointers or mutable process state.
    if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != PAGE as libc::c_long {
        return Err(refusal("image-page-size"));
    }
    let image = if elf.kind == 2 {
        Mapping::allocate(elf.low, elf.high - elf.low)?
    } else {
        Mapping::aligned(elf.high - elf.low, elf.alignment, elf.low)?
    };
    let bias = (image.start as usize)
        .checked_sub(elf.low)
        .ok_or(refusal("image-address"))?;
    for segment in elf.headers.iter().filter(|s| s.kind == 1 && s.files != 0) {
        image.copy(
            segment.address - elf.low,
            &bytes[segment.offset..segment.offset + segment.files],
        )?;
    }
    for (address, addend) in elf.relocations(bytes)? {
        let value = (bias as i128)
            .checked_add(i128::from(addend))
            .filter(|n| *n >= 0 && *n <= usize::MAX as i128)
            .ok_or(refusal("image-relocation"))? as usize;
        if value < image.start as usize || value > image.start as usize + image.len {
            return Err(refusal("image-relocation"));
        }
        image.copy(address - elf.low, &value.to_le_bytes())?;
    }
    for segment in elf
        .headers
        .iter()
        .filter(|s| s.kind == 1 && s.flags & 1 != 0 && s.memory != 0)
    {
        handoff::flush_instructions(bias + segment.address, segment.memory);
    }
    image.protect(0, image.len, libc::PROT_NONE)?;
    for segment in elf.headers.iter().filter(|s| s.kind == 1 && s.memory != 0) {
        let start = segment.address & !(PAGE - 1);
        let len = page_up(segment.address + segment.memory)? - start;
        let protection = if segment.flags & 4 != 0 {
            libc::PROT_READ
        } else {
            0
        } | if segment.flags & 2 != 0 {
            libc::PROT_WRITE
        } else {
            0
        } | if segment.flags & 1 != 0 {
            libc::PROT_EXEC
        } else {
            0
        };
        image.protect(start - elf.low, len, protection)?;
    }
    let capsule = Mapping::allocate(0, PAGE + STACK_SIZE + PAGE + CONTROL_SIZE)?;
    capsule.protect(0, PAGE, libc::PROT_NONE)?;
    let code = capsule.start as usize + PAGE + STACK_SIZE;
    let control = code + PAGE;
    let instructions = handoff::trampoline_code()?;
    if instructions.len() > PAGE {
        return Err(refusal("image-trampoline"));
    }
    capsule.copy(PAGE + STACK_SIZE, instructions)?;
    let entry_address = bias + elf.entry;
    {
        // SAFETY: control is aligned and belongs to the exclusively owned writable capsule mapping.
        let state =
            unsafe { std::slice::from_raw_parts_mut(control as *mut usize, CONTROL_SIZE / 8) };
        state[0] = entry_address;
        state[2] = control + RANGES_OFFSET;
        state[9] = libc::SS_DISABLE as usize;
        state[11] = 0x1f80;
        handoff::prepare_processor_state(state, control)?;
    }
    let headers_size = elf.headers.len() * 56;
    let phdr = elf
        .headers
        .iter()
        .find(|s| {
            s.kind == 1
                && elf.headers_at >= s.offset
                && elf.headers_at + headers_size <= s.offset + s.files
        })
        .ok_or(refusal("image-headers"))?;
    let phdr_address = bias + phdr.address + elf.headers_at - phdr.offset;
    let random_address = control + 8192;
    fill_random(random_address as *mut u8, 16)?;
    let stack = build_stack(
        &capsule,
        code,
        arguments,
        phdr_address,
        elf.headers.len(),
        entry_address,
        random_address,
    )?;
    // SAFETY: no mutable state slice remains; this writes one word in the live writable control mapping.
    unsafe {
        (control as *mut usize).add(1).write(stack);
    }
    handoff::flush_instructions(code, instructions.len());
    capsule.protect(PAGE + STACK_SIZE, PAGE, libc::PROT_READ | libc::PROT_EXEC)?;
    let proc_maps = rustix::fs::open(
        "/proc/self/maps",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| refusal("image-maps"))?;
    Ok(Prepared {
        image,
        capsule,
        code,
        control,
        proc_maps: Some(proc_maps),
        finalized: false,
    })
}

fn fill_random(pointer: *mut u8, len: usize) -> Result<()> {
    let mut at = 0;
    while at < len {
        // SAFETY: the caller supplied the fresh writable control range; GRND_NONBLOCK has no external input.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                pointer.add(at),
                len - at,
                libc::GRND_NONBLOCK,
            )
        };
        if count < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if count <= 0 {
            return Err(refusal("image-random"));
        }
        at += count as usize;
    }
    Ok(())
}

fn build_stack(
    capsule: &Mapping,
    top: usize,
    arguments: &[OsString],
    phdr: usize,
    count: usize,
    entry: usize,
    random: usize,
) -> Result<usize> {
    if arguments.is_empty() || arguments.len() > 256 {
        return Err(refusal("image-arguments"));
    }
    let mut cursor = top;
    let mut pointers = Vec::with_capacity(arguments.len());
    let mut total = 0;
    for argument in arguments.iter().rev() {
        let bytes = argument.as_os_str().as_bytes();
        total += bytes.len() + 1;
        if bytes.len() > 16384 || total > 131072 || bytes.contains(&0) {
            return Err(refusal("image-arguments"));
        }
        cursor -= bytes.len() + 1;
        capsule.copy(cursor - capsule.start as usize, bytes)?;
        pointers.push(cursor);
    }
    pointers.reverse();
    let mut words = Vec::with_capacity(arguments.len() + 48);
    words.push(arguments.len());
    words.extend_from_slice(&pointers);
    words.extend_from_slice(&[0, 0]);
    for (kind, value) in [
        (3, phdr),
        (4, 56),
        (5, count),
        (6, PAGE),
        (7, 0),
        (8, 0),
        (9, entry),
        (11, 0),
        (12, 0),
        (13, 0),
        (14, 0),
        (17, 100),
        (23, 1),
        (25, random),
        (31, pointers[0]),
        (0, 0),
    ] {
        words.extend_from_slice(&[kind, value]);
    }
    let stack = (cursor - words.len() * 8) & !15;
    for (index, value) in words.iter().enumerate() {
        capsule.copy(
            stack - capsule.start as usize + index * 8,
            &value.to_le_bytes(),
        )?;
    }
    Ok(stack)
}

impl Prepared {
    /// Finish after all allocations and before the descriptor/filter boundary.
    pub(super) fn finalize(&mut self) -> Result<()> {
        if self.finalized {
            return Err(refusal("image-finalized"));
        }
        let fd = self
            .proc_maps
            .as_ref()
            .ok_or(refusal("image-maps"))?
            .as_raw_fd();
        // SAFETY: maps is a live, private read-only descriptor opened during preparation.
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
            return Err(refusal("image-maps"));
        }
        let mut block = [0u8; 4096];
        let mut line = [0u8; 4096];
        let (mut used, mut ranges) = (0, 0);
        loop {
            // SAFETY: the output block is a live exclusive buffer.
            let length = unsafe { libc::read(fd, block.as_mut_ptr().cast(), block.len()) };
            if length < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if length < 0 {
                return Err(refusal("image-maps"));
            }
            if length == 0 {
                break;
            }
            for byte in &block[..length as usize] {
                if *byte == b'\n' {
                    self.record_mapping(&line[..used], &mut ranges)?;
                    used = 0;
                } else {
                    if used == line.len() {
                        return Err(refusal("image-maps-bound"));
                    }
                    line[used] = *byte;
                    used += 1;
                }
            }
        }
        if used != 0 || ranges == 0 {
            return Err(refusal("image-maps"));
        }
        // SAFETY: the control page remains writable until its final protection below.
        unsafe {
            (self.control as *mut usize).add(3).write(ranges);
        }
        self.proc_maps.take();
        self.capsule
            .protect(PAGE + STACK_SIZE + PAGE, CONTROL_SIZE, libc::PROT_READ)?;
        self.finalized = true;
        Ok(())
    }

    fn record_mapping(&self, line: &[u8], count: &mut usize) -> Result<()> {
        let end = line
            .iter()
            .position(|b| *b == b' ')
            .ok_or(refusal("image-maps"))?;
        let split = line[..end]
            .iter()
            .position(|b| *b == b'-')
            .ok_or(refusal("image-maps"))?;
        let start = hexadecimal(&line[..split])?;
        let finish = hexadecimal(&line[split + 1..end])?;
        if start >= finish || start % PAGE != 0 || finish % PAGE != 0 {
            return Err(refusal("image-maps"));
        }
        if start > isize::MAX as usize {
            if cfg!(target_arch = "x86_64")
                && start == 0xffff_ffff_ff60_0000
                && finish == 0xffff_ffff_ff60_1000
            {
                return Ok(());
            }
            return Err(refusal("image-maps"));
        }
        let mut kept = [
            (
                self.image.start as usize,
                self.image.start as usize + self.image.len,
            ),
            (
                self.capsule.start as usize,
                self.capsule.start as usize + self.capsule.len,
            ),
        ];
        kept.sort_unstable();
        let mut cursor = start;
        for (low, high) in kept {
            if high <= cursor || low >= finish {
                continue;
            }
            if cursor < low {
                self.record_range(cursor, low - cursor, count)?;
            }
            cursor = high.min(finish);
        }
        if cursor < finish {
            self.record_range(cursor, finish - cursor, count)?;
        }
        Ok(())
    }

    fn record_range(&self, start: usize, len: usize, count: &mut usize) -> Result<()> {
        if *count == MAX_RANGES {
            return Err(refusal("image-maps-bound"));
        }
        // SAFETY: each pair fits in the reserved control table and preparation owns it exclusively.
        unsafe {
            let entry = (self.control + RANGES_OFFSET) as *mut usize;
            entry.add(*count * 2).write(start);
            entry.add(*count * 2 + 1).write(len);
        }
        *count += 1;
        Ok(())
    }

    /// The caller has installed all restrictions and released the parent handshake.
    pub(super) unsafe fn enter(&self) -> ! {
        if !self.finalized {
            // SAFETY: no payload instruction is reachable on an unfinished handoff.
            unsafe {
                libc::_exit(127);
            }
        }
        // SAFETY: code is the copied architecture-specific trampoline in its dedicated RX page.
        let handoff: unsafe extern "C" fn(*const usize) -> ! =
            unsafe { std::mem::transmute(self.code) };
        // SAFETY: the finalized state/table and new stack remain mapped throughout the terminal handoff.
        unsafe { handoff(self.control as *const usize) }
    }
}

fn hexadecimal(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty() || bytes.len() > 16 {
        return Err(refusal("image-maps"));
    }
    bytes.iter().try_fold(0usize, |value, digit| {
        let digit = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => return Err(refusal("image-maps")),
        };
        value
            .checked_mul(16)
            .and_then(|n| n.checked_add(usize::from(digit)))
            .ok_or(refusal("image-maps"))
    })
}
