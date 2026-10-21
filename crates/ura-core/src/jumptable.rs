//! Narrow, guarded switch patterns. Recovered edges remain heuristic and an
//! indirect transfer is never declared exhaustive from a byte pattern alone.
use crate::analysis::{CodeImage, JumpTable};
use iced_x86::{ConditionCode, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

pub(crate) fn recover(
    code: &CodeImage<'_>,
    memory: &CodeImage<'_>,
    bits: u8,
    jump: &Instruction,
    previous: &[Instruction],
) -> Result<JumpTable, String> {
    let fail =
        || "indirect transfer unresolved: no supported guarded jump-table pattern".to_string();
    if jump.mnemonic() != Mnemonic::Jmp || jump.has_segment_prefix() {
        return Err(fail());
    }
    let (table, index, width, relative, guard_end) = if jump.op0_kind() == OpKind::Memory {
        let width = (bits / 8) as usize;
        if jump.memory_base() != Register::None
            || jump.memory_index() == Register::None
            || jump.memory_index_scale() != width as u32
            || jump.memory_size().size() != width
        {
            return Err(fail());
        }
        (
            jump.memory_displacement64(),
            jump.memory_index(),
            width,
            false,
            previous.len(),
        )
    } else if jump.op0_kind() == OpKind::Register && bits == 64 && previous.len() >= 3 {
        let n = previous.len();
        let lea = &previous[n - 3];
        let load = &previous[n - 2];
        let add = &previous[n - 1];
        let base = lea.op0_register();
        let target = jump.op0_register();
        let index = load.memory_index();
        if lea.mnemonic() != Mnemonic::Lea
            || lea.op0_kind() != OpKind::Register
            || base.size() != 8
            || !lea.is_ip_rel_memory_operand()
            || load.mnemonic() != Mnemonic::Movsxd
            || load.op0_register() != target
            || load.op1_kind() != OpKind::Memory
            || load.memory_base() != base
            || index == Register::None
            || load.memory_index_scale() != 4
            || load.memory_displacement64() != 0
            || load.has_segment_prefix()
            || add.mnemonic() != Mnemonic::Add
            || add.op0_register() != target
            || add.op1_kind() != OpKind::Register
            || add.op1_register() != base
            || target.size() != 8
            || target == base
            || index.full_register() == base.full_register()
        {
            return Err(fail());
        }
        (lea.ip_rel_memory_address(), index, 4, true, n - 3)
    } else {
        return Err(fail());
    };
    if index.size() != bits as usize / 8 {
        return Err("jump table rejected: address-size override is not supported".into());
    }
    // A 32-bit comparison alone does not bound a 64-bit index. Accept only an
    // explicit MOV to a 32-bit destination that zero-extends that index.
    let mut guard_end = guard_end;
    let mut compared = index;
    if bits == 64 && guard_end > 0 {
        let copy = &previous[guard_end - 1];
        if copy.mnemonic() == Mnemonic::Mov
            && copy.op0_kind() == OpKind::Register
            && copy.op1_kind() == OpKind::Register
            && copy.op0_register().size() == 4
            && copy.op1_register().size() == 4
            && copy.op0_register().full_register() == index
        {
            compared = copy.op1_register();
            guard_end -= 1;
        }
    }
    if guard_end < 2 {
        return Err(fail());
    }
    let compare = &previous[guard_end - 2];
    let guard = &previous[guard_end - 1];
    if compare.mnemonic() != Mnemonic::Cmp
        || compare.op0_kind() != OpKind::Register
        || compare.op0_register() != compared
        || !matches!(
            compare.op1_kind(),
            OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32
                | OpKind::Immediate32to64
        )
        || guard.condition_code() != ConditionCode::a
        || !guard.is_jcc_short_or_near()
    {
        return Err(fail());
    }
    let maximum = compare.immediate(1);
    if !(1..=255).contains(&maximum) {
        return Err("jump table rejected: unsigned bound must imply 2..256 entries".into());
    }
    let count = maximum as usize + 1;
    let raw = memory
        .read(table, count * width)
        .ok_or("jump table rejected: complete table is not in one read-only file-backed region")?;
    let mut targets = Vec::with_capacity(count);
    let mut boundaries = Vec::new();
    for entry in raw.chunks_exact(width) {
        let target = if relative {
            table
                .checked_add_signed(i32::from_le_bytes(entry.try_into().unwrap()) as i64)
                .ok_or("jump table rejected: relative target overflow")?
        } else if width == 8 {
            u64::from_le_bytes(entry.try_into().unwrap())
        } else {
            u32::from_le_bytes(entry.try_into().unwrap()) as u64
        };
        let bytes = code
            .bytes_at(target)
            .ok_or("jump table rejected: target is not executable and file-backed")?;
        let decoded = Decoder::with_ip(bits as u32, bytes, target, DecoderOptions::NONE).decode();
        if decoded.is_invalid() || decoded.len() == 0 {
            return Err("jump table rejected: invalid target instruction".into());
        }
        let end = target
            .checked_add(decoded.len() as u64)
            .ok_or("jump table rejected: instruction overflow")?;
        if target < table.saturating_add(raw.len() as u64) && end > table {
            return Err("jump table rejected: target overlaps table data".into());
        }
        targets.push(target);
        boundaries.push((target, end));
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    if boundaries.windows(2).any(|p| p[0].1 > p[1].0) {
        return Err("jump table rejected: overlapping target instructions".into());
    }
    Ok(JumpTable {
        source: jump.ip(),
        guard: guard.ip(),
        table,
        entry_width: width as u8,
        relative,
        targets,
    })
}
