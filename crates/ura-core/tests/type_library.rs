use ura_core::decomp::{StructField, Structure, TypeDatabase, TypeRef};

#[test]
fn curated_size_types_and_winapi_defaults_follow_target_width() {
    use ura_core::decomp::{api, CallingConvention};
    for bits in [32, 64] {
        let database = TypeDatabase::new(bits);
        let memcpy = api::instantiate(
            api::lookup("memcpy").unwrap(),
            CallingConvention::Unknown,
            bits,
        )
        .unwrap();
        assert_eq!(
            memcpy.parameters[2].ty.bits(&database),
            Some(u64::from(bits))
        );
        let strlen = api::instantiate(
            api::lookup("strlen").unwrap(),
            CallingConvention::Unknown,
            bits,
        )
        .unwrap();
        assert_eq!(
            strlen.return_value.ty.bits(&database),
            Some(u64::from(bits))
        );
        let alloc = api::instantiate(
            api::lookup("VirtualAlloc").unwrap(),
            CallingConvention::Unknown,
            bits,
        )
        .unwrap();
        assert_eq!(
            alloc.parameters[1].ty.bits(&database),
            Some(u64::from(bits))
        );
        assert_eq!(
            alloc.convention,
            if bits == 32 {
                CallingConvention::Stdcall
            } else {
                CallingConvention::Win64
            }
        );
    }
    let time =
        api::instantiate(api::lookup("time").unwrap(), CallingConvention::Unknown, 32).unwrap();
    assert_eq!(time.return_value.ty.bits(&TypeDatabase::new(32)), None);
    assert!(time.return_value.location.is_none());
}

#[test]
fn target_width_and_display_spellings_are_preserved() {
    assert_eq!(TypeRef::parse("usize", 32).unwrap(), TypeRef::uint(32));
    assert_eq!(
        TypeRef::parse("ssize_t", 32)
            .unwrap()
            .bits(&TypeDatabase::new(32)),
        Some(32)
    );
    for ty in [
        TypeRef::int(64),
        TypeRef::unknown(Some(32), "test"),
        TypeRef::Float { bits: 80 },
    ] {
        let parsed = TypeRef::parse(&ty.display(), 64).unwrap();
        assert_eq!(parsed.display(), ty.display());
        assert_eq!(
            parsed.bits(&TypeDatabase::new(64)),
            ty.bits(&TypeDatabase::new(64))
        );
    }
    assert!(TypeRef::parse("long", 64).is_err());
    assert!(TypeRef::parse("u8", 0).is_err());
}

#[test]
fn size_arithmetic_and_recursive_names_are_bounded() {
    let huge = TypeRef::Array {
        element: Box::new(TypeRef::uint(64)),
        count: Some(u64::MAX),
    };
    assert_eq!(huge.size(&TypeDatabase::new(64)), None);
    assert!(TypeRef::parse(&format!("u8{}", "*".repeat(80)), 64).is_err());
    let mut db = TypeDatabase::new(64);
    db.typedefs
        .insert("A".into(), TypeRef::Named { name: "B".into() });
    db.typedefs
        .insert("B".into(), TypeRef::Named { name: "A".into() });
    assert!(!db.validation_errors().is_empty());
    assert_eq!(TypeRef::Named { name: "A".into() }.size(&db), None);
}

#[test]
fn layouts_check_actual_widths_alignment_and_by_value_recursion() {
    let mut db = TypeDatabase::new(64);
    let structure = Structure {
        name: "Node".into(),
        size: Some(8),
        alignment: Some(8),
        union: false,
        source: "user".into(),
        fields: vec![StructField {
            name: "next".into(),
            offset: 0,
            ty: TypeRef::pointer_to(
                TypeRef::Struct {
                    name: "Node".into(),
                },
                64,
            ),
            size: None,
            source: "user".into(),
        }],
    };
    db.structures.insert("Node".into(), structure);
    assert!(db.validation_errors().is_empty());
    db.structures.get_mut("Node").unwrap().fields[0].ty = TypeRef::Struct {
        name: "Node".into(),
    };
    assert!(db.validation_errors().iter().any(|e| e.contains("cyclic")));
    db.structures.get_mut("Node").unwrap().fields[0].ty = TypeRef::uint(64);
    db.structures.get_mut("Node").unwrap().fields[0].offset = 4;
    assert!(db.validation_errors().iter().any(|e| e.contains("exceeds")));
    db.structures.get_mut("Node").unwrap().alignment = Some(3);
    assert!(db
        .validation_errors()
        .iter()
        .any(|e| e.contains("alignment")));
}
