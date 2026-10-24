/* Reconstructed C-like pseudocode; machine helpers preserve explicit widths/effects. */
ura_unknown64_t ura_flattened(uint64_t a0) {
    uint64_t v0;
    uint64_t v1;
    uint64_t v2;
    uint64_t v3;
    uint64_t v7;
    uint64_t in_rsp = ura_entry_rsp();
    uint64_t v122;
    uint64_t v150;

    L_1400011F0:
    v0 = ((uint64_t)(((uint32_t)((((uint64_t)a0)) >> 0))));
    v1 = v0;
    v7 = 1;
    goto L_1400011F7;
    L_1400011F7:
    if (((((uint32_t)((v7) >> 0))) == (1))) {
        goto L_140001207;
    } else {
        goto L_1400011FC;
    }
    L_1400011FC:
    if (((((uint32_t)((v7) >> 0))) == (2))) {
        goto L_140001211;
    } else {
        goto L_140001201;
    }
    L_140001201:
    if (((((uint32_t)((v7) >> 0))) == (3))) {
        v150 = ura_load_u64(in_rsp);
        return v1;
    } else {
        v122 = ura_load_u64(in_rsp);
        return v1;
    }
    L_140001207:
    v3 = ((uint64_t)(((uint32_t)((((uint32_t)((v1) >> 0))) + (7)))));
    v1 = v3;
    v7 = 2;
    goto L_1400011F7;
    L_140001211:
    v2 = ((uint64_t)(((uint32_t)((((uint32_t)((v1) >> 0))) ^ (0x55ULL)))));
    v1 = v2;
    v7 = 3;
    goto L_1400011F7;
}
