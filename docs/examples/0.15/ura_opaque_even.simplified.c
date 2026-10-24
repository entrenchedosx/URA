/* Reconstructed C-like pseudocode; machine helpers preserve explicit widths/effects. */
uint64_t ura_opaque_even(uint64_t a0) {
    uint64_t in_rsp = ura_entry_rsp();
    uint64_t v14;
    uint32_t v101;
    uint32_t v110;
    uint32_t v115;
    uint32_t v171;
    uint32_t v181;
    uint32_t v202;
    uint64_t v218;

    L_140001000:
    v14 = ((uint64_t)((in_rsp) - (0x10ULL)));
    ura_store_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (8))), ((uint32_t)((((uint64_t)a0)) >> 0))); /* stack: local_8 */
    v101 = ura_load_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (8))));
    ura_store_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (4))), ((uint32_t)((((uint64_t)(v101))) >> 0))); /* stack: local_c */
    v110 = ura_load_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (4))));
    v115 = ura_load_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (4))));
    v171 = ura_load_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (8))));
    v181 = ((uint32_t)((((uint32_t)((((uint64_t)(((uint32_t)((((uint32_t)((((uint64_t)(v171))) >> 0))) ^ (0x12345678ULL)))))) >> 0))) + (0x11ULL)));
    ura_store_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (0xcULL))), ((uint32_t)((((uint64_t)(v181))) >> 0))); /* stack: local_4 */
    v202 = ura_load_u32(((uint64_t)((((uint64_t)((v14) + (0)))) + (0xcULL))));
    v218 = ura_load_u64(((uint64_t)((v14) + (0x10ULL))));
    return ((uint64_t)(v202));
}
